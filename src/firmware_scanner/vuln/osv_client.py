"""OSV API client with local caching."""

import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from packaging.version import parse as parse_version, InvalidVersion

from .cache import (
    get_cache_dir,
    cache_key,
    read_cached,
    read_cached_stale,
    write_cache,
    update_cache_meta,
    get_cache_age_hours,
)
from .models import Vulnerability, VulnReference, Severity


def clean_version(v_str: str) -> str:
    """Normalize version string for packaging.version parsing, stripping distro/build tags."""
    if not v_str:
        return ""
    if ":" in v_str:
        v_str = v_str.split(":", 1)[1]
    v_clean = re.sub(r"^[a-zA-Z_\-]+", "", v_str)
    v_clean = re.split(r"[-+~]", v_clean)[0]
    match = re.match(r"^(\d+(\.\d+)*)", v_clean)
    if match:
        return match.group(1)
    return ""


def extract_canonical_id(vuln: dict) -> str:
    """Extract standard CVE identifier (CVE-YYYY-NNNNN) if present in ID, aliases, or references."""
    vid = vuln.get("id", "")
    match = re.search(r"CVE-\d{4}-\d+", vid)
    if match:
        return match.group(0)
    for a in vuln.get("aliases", []):
        match = re.search(r"CVE-\d{4}-\d+", a)
        if match:
            return match.group(0)
    for u in vuln.get("upstream", []):
        match = re.search(r"CVE-\d{4}-\d+", u)
        if match:
            return match.group(0)
    for r in vuln.get("related", []):
        match = re.search(r"CVE-\d{4}-\d+", r)
        if match:
            return match.group(0)
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        match = re.search(r"CVE-\d{4}-\d+", url)
        if match:
            return match.group(0)
    return vid


def is_version_affected(comp_ver_str: str, vuln: dict) -> bool:
    """Verify client-side whether comp_ver_str falls within any of the vulnerability's affected ranges."""
    target_clean = clean_version(comp_ver_str)
    if not target_clean:
        return True
    try:
        comp_v = parse_version(target_clean)
    except InvalidVersion:
        return True

    affected_entries = vuln.get("affected", [])
    if not affected_entries:
        return True

    # Collect all known fixed versions across all ranges to guard against open-ended introduced: 0 ranges
    all_fixed_versions = []
    for aff in affected_entries:
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    cf = clean_version(ev["fixed"])
                    if cf:
                        try:
                            all_fixed_versions.append(parse_version(cf))
                        except InvalidVersion:
                            pass

    # A vulnerability can affect multiple independent branches (e.g. 5.x, 6.1.x, 6.2.x, 7.x).
    # If the version matches ANY affected entry/range, it is affected.
    for aff in affected_entries:
        # 1. Exact version list match
        vers = [clean_version(v) for v in aff.get("versions", [])]
        if target_clean in vers:
            return True

        # 2. SemVer / Ecosystem range evaluation
        ranges = aff.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            current_intro = None
            for ev in events:
                if "introduced" in ev:
                    intro_str = clean_version(ev["introduced"])
                    try:
                        current_intro = parse_version(intro_str) if intro_str else parse_version("0")
                    except InvalidVersion:
                        current_intro = parse_version("0")

                if "fixed" in ev:
                    fixed_str = clean_version(ev["fixed"])
                    try:
                        fixed_v = parse_version(fixed_str) if fixed_str else None
                    except InvalidVersion:
                        fixed_v = None

                    intro_v = current_intro if current_intro is not None else parse_version("0")
                    if fixed_v is not None and comp_v >= intro_v and comp_v < fixed_v:
                        return True
                    current_intro = None

                if "last_affected" in ev:
                    la_str = clean_version(ev["last_affected"])
                    try:
                        la_v = parse_version(la_str) if la_str else None
                    except InvalidVersion:
                        la_v = None

                    intro_v = current_intro if current_intro is not None else parse_version("0")
                    if la_v is not None and comp_v >= intro_v and comp_v <= la_v:
                        return True
                    current_intro = None

            # Open-ended range (introduced without fixed or last_affected, e.g. Debian 12 open report)
            if current_intro is not None and comp_v >= current_intro:
                has_higher_fix = any(fv <= comp_v for fv in all_fixed_versions)
                if not has_higher_fix:
                    return True

    # If ranges or versions were specified and none matched, it's not affected
    has_criteria = any(aff.get("versions") or aff.get("ranges") for aff in affected_entries)
    if has_criteria:
        return False

    return True


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"
    TIMEOUT = 15
    BATCH_SIZE = 100

    def __init__(self, cache_dir: Path | None = None, base_url: str | None = None,
                 timeout: int | None = None, proxy: str | None = None):
        self._cache_dir = cache_dir or get_cache_dir()
        if base_url:
            self.BASE_URL = base_url.rstrip("/")
        if timeout:
            self.TIMEOUT = timeout
        self._opener = self._build_opener(proxy)

    def _build_opener(self, proxy: str | None) -> urllib.request.OpenerDirector:
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy,
                "https": proxy,
            })
            return urllib.request.build_opener(proxy_handler)
        return urllib.request.build_opener()

    def check_cache_freshness(self) -> tuple[bool, float | None]:
        """Returns (is_fresh, age_in_hours). is_fresh=True if <24h or no meta."""
        age = get_cache_age_hours(self._cache_dir)
        if age is None:
            return True, None
        return age < 24, age

    def query_batch(self, queries: list[dict]) -> list[list[dict]]:
        """Query OSV batch endpoint. Each query is {"purl": ...} or {"name": ..., "version": ..., "ecosystem": ...}.
        Returns a list of raw vuln lists, one per query (same order).
        """
        results: list[list[dict]] = []
        for i in range(0, len(queries), self.BATCH_SIZE):
            chunk = queries[i:i + self.BATCH_SIZE]
            batch_results = self._post_batch(chunk)
            results.extend(batch_results)
        update_cache_meta(self._cache_dir)
        return results

    def query_single(self, purl: str = "", name: str = "", version: str = "", ecosystem: str = "") -> list[dict]:
        """Query a single component. Returns raw vuln dicts."""
        key = cache_key(purl=purl, name=name, version=version)
        cached = read_cached(self._cache_dir, key)
        if cached is not None:
            return cached.get("vulns", [])

        payload = self._build_query(purl, name, version, ecosystem)
        try:
            raw_vulns = self._post_query(payload)
        except (urllib.error.URLError, OSError):
            stale = read_cached_stale(self._cache_dir, key)
            if stale:
                return stale.get("vulns", [])
            raise

        write_cache(self._cache_dir, key, raw_vulns, query={"purl": purl, "name": name, "version": version, "ecosystem": ecosystem})
        return raw_vulns

    def query_with_cache(self, queries: list[dict]) -> list[list[dict]]:
        """Query multiple components, using cache where available.
        Batches uncached queries together for efficiency.
        Returns results in same order as input queries.
        """
        results: list[list[dict] | None] = [None] * len(queries)
        uncached_indices: list[int] = []
        uncached_queries: list[dict] = []

        for idx, q in enumerate(queries):
            purl = q.get("purl", "")
            name = q.get("name", "")
            version = q.get("version", "")
            key = cache_key(purl=purl, name=name, version=version)
            cached = read_cached(self._cache_dir, key)
            if cached is not None:
                results[idx] = cached.get("vulns", [])
            else:
                uncached_indices.append(idx)
                uncached_queries.append(q)

        if uncached_queries:
            try:
                batch_results = self._fetch_batch_from_api(uncached_queries)
                for i, idx in enumerate(uncached_indices):
                    vulns = batch_results[i] if i < len(batch_results) else []
                    results[idx] = vulns
                    q = uncached_queries[i]
                    key = cache_key(
                        purl=q.get("purl", ""),
                        name=q.get("name", ""),
                        version=q.get("version", ""),
                    )
                    write_cache(self._cache_dir, key, vulns, query=q)
                update_cache_meta(self._cache_dir)
            except (urllib.error.URLError, OSError) as e:
                for i, idx in enumerate(uncached_indices):
                    q = uncached_queries[i]
                    key = cache_key(
                        purl=q.get("purl", ""),
                        name=q.get("name", ""),
                        version=q.get("version", ""),
                    )
                    stale = read_cached_stale(self._cache_dir, key)
                    if stale:
                        results[idx] = stale.get("vulns", [])
                    else:
                        results[idx] = []
                raise

        return [r if r is not None else [] for r in results]

    def parse_vulns(
        self,
        raw_vulns: list[dict],
        comp_version: str = "",
        comp_name: str = "",
    ) -> list[Vulnerability]:
        """Convert raw OSV JSON vulnerability objects to our model with semver verification and CVE deduplication."""
        # 1. Filter out vulnerabilities that do not affect comp_version
        filtered_vulns: list[dict] = []
        for v in raw_vulns:
            if comp_version and not is_version_affected(comp_version, v):
                continue
            filtered_vulns.append(v)

        # 2. Group by canonical CVE ID to eliminate duplicate distro notices
        cve_groups: dict[str, list[dict]] = {}
        for v in filtered_vulns:
            cid = extract_canonical_id(v)
            if cid not in cve_groups:
                cve_groups[cid] = []
            cve_groups[cid].append(v)

        parsed: list[Vulnerability] = []
        for cid, group in cve_groups.items():
            best_score = -1.0
            best_vector = ""
            best_severity = Severity.UNKNOWN
            best_summary = ""
            best_details = ""
            best_fixed = ""
            best_affected = ""
            all_aliases: set[str] = set()
            all_refs: list[VulnReference] = []
            seen_ref_urls: set[str] = set()
            pub_date = ""
            mod_date = ""

            for v in group:
                vid = v.get("id", "")
                if vid != cid:
                    all_aliases.add(vid)
                for a in v.get("aliases", []):
                    if a != cid:
                        all_aliases.add(a)

                for r in v.get("references", []):
                    url = r.get("url", "")
                    if url and url not in seen_ref_urls:
                        seen_ref_urls.add(url)
                        all_refs.append(VulnReference(url=url, type=r.get("type", "")))

                summary = v.get("summary", "")
                if len(summary) > len(best_summary):
                    best_summary = summary

                details = v.get("details", "")
                if len(details) > len(best_details):
                    best_details = details

                fixed = self._extract_fixed_version(v)
                if fixed and not best_fixed:
                    best_fixed = fixed

                aff_str = self._extract_affected_range(v)
                if aff_str and not best_affected:
                    best_affected = aff_str

                sev, score, vector = self._extract_severity(v)
                if score is not None and score > best_score:
                    best_score = score
                    best_vector = vector
                    best_severity = sev
                elif best_severity == Severity.UNKNOWN and sev != Severity.UNKNOWN:
                    best_severity = sev

                if v.get("published") and not pub_date:
                    pub_date = v.get("published", "")
                if v.get("modified") and not mod_date:
                    mod_date = v.get("modified", "")

            # If score was determined, calculate severity
            if best_score >= 9.0:
                best_severity = Severity.CRITICAL
            elif best_score >= 7.0:
                best_severity = Severity.HIGH
            elif best_score >= 4.0:
                best_severity = Severity.MEDIUM
            elif best_score > 0.0:
                best_severity = Severity.LOW

            parsed.append(Vulnerability(
                id=cid,
                summary=best_summary,
                details=best_details,
                aliases=sorted(list(all_aliases)),
                severity=best_severity,
                cvss_score=best_score if best_score >= 0 else None,
                cvss_vector=best_vector,
                affected_versions=best_affected,
                fixed_version=best_fixed,
                references=all_refs,
                published=pub_date,
                modified=mod_date,
            ))

        return parsed

    def _build_query(self, purl: str, name: str, version: str, ecosystem: str) -> dict:
        if purl:
            payload: dict = {"package": {"purl": purl}}
            if version and "@" not in purl:
                payload["version"] = version
            return payload
        pkg: dict = {"name": name}
        if ecosystem:
            pkg["ecosystem"] = ecosystem
        payload = {"package": pkg}
        if version:
            payload["version"] = version
        return payload

    def _post_query(self, payload: dict) -> list[dict]:
        url = f"{self.BASE_URL}/query"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with self._opener.open(req, timeout=self.TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("vulns", [])

    def _post_batch(self, queries: list[dict]) -> list[list[dict]]:
        """Post to /v1/querybatch. Returns list of vuln lists."""
        url = f"{self.BASE_URL}/querybatch"
        osv_queries = []
        for q in queries:
            osv_queries.append(self._build_query(
                purl=q.get("purl", ""),
                name=q.get("name", ""),
                version=q.get("version", ""),
                ecosystem=q.get("ecosystem", ""),
            ))
        payload = {"queries": osv_queries}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with self._opener.open(req, timeout=self.TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        results = body.get("results", [])
        return [r.get("vulns", []) for r in results]

    def _fetch_batch_from_api(self, queries: list[dict]) -> list[list[dict]]:
        """Fetch multiple queries using a fast two-phase strategy:
        1. Fast batch pre-filter via /v1/querybatch (chunks of 100) to find packages with candidate vulns.
        2. Parallel detail fetch via ThreadPoolExecutor against /v1/query ONLY for vulnerable candidates.
        """
        all_results: list[list[dict]] = [[] for _ in queries]
        if not queries:
            return all_results

        candidate_indices: list[int] = []
        chunk_size = 100

        try:
            for i in range(0, len(queries), chunk_size):
                chunk = queries[i : i + chunk_size]
                batch_res = self._post_batch(chunk)
                for local_idx, r in enumerate(batch_res):
                    global_idx = i + local_idx
                    if r:  # Has candidate vulnerabilities
                        candidate_indices.append(global_idx)
        except Exception:
            # Fallback: if querybatch fails, treat all as candidates
            candidate_indices = list(range(len(queries)))

        if not candidate_indices:
            return all_results

        def _fetch_one(idx: int) -> tuple[int, list[dict]]:
            q = queries[idx]
            payload = self._build_query(
                purl=q.get("purl", ""),
                name=q.get("name", ""),
                version=q.get("version", ""),
                ecosystem=q.get("ecosystem", ""),
            )
            try:
                vulns = self._post_query(payload)
                return idx, vulns
            except Exception:
                return idx, []

        max_workers = min(15, max(4, len(candidate_indices)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, vulns in executor.map(_fetch_one, candidate_indices):
                all_results[idx] = vulns

        return all_results

    def _extract_severity(self, vuln: dict) -> tuple[Severity, float | None, str]:
        severities = vuln.get("severity", [])
        for s in severities:
            score_str = s.get("score", "")
            stype = s.get("type", "")
            if stype.startswith("CVSS"):
                vector = score_str
                score = self._cvss_vector_to_score(vector)
                if score is not None:
                    if score >= 9.0:
                        return Severity.CRITICAL, score, vector
                    elif score >= 7.0:
                        return Severity.HIGH, score, vector
                    elif score >= 4.0:
                        return Severity.MEDIUM, score, vector
                    else:
                        return Severity.LOW, score, vector

        db_severity = vuln.get("database_specific", {}).get("severity", "")
        if db_severity:
            s_lower = db_severity.lower()
            if "critical" in s_lower:
                return Severity.CRITICAL, None, ""
            elif "high" in s_lower:
                return Severity.HIGH, None, ""
            elif "medium" in s_lower or "moderate" in s_lower:
                return Severity.MEDIUM, None, ""
            elif "low" in s_lower:
                return Severity.LOW, None, ""

        return Severity.UNKNOWN, None, ""

    def _cvss_vector_to_score(self, vector: str) -> float | None:
        """Extract base score from CVSS vector if embedded, or calculate from CVSS v3 metrics."""
        if not vector:
            return None
        # OSV sometimes puts score directly in the vector field as a number
        try:
            return float(vector)
        except ValueError:
            pass

        # Standard CVSS v3.x calculation
        if "CVSS:3" in vector:
            try:
                import math
                parts = dict(part.split(":") for part in vector.split("/") if ":" in part)
                av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
                ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
                pr_scope = parts.get("S", "U")
                if pr_scope == "C":
                    pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(parts.get("PR", "N"), 0.85)
                else:
                    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR", "N"), 0.85)
                ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
                c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("C", "N"), 0.0)
                i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("I", "N"), 0.0)
                a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("A", "N"), 0.0)

                iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
                if iss <= 0:
                    return 0.0
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if pr_scope == "C" else 6.42 * iss
                exploitability = 8.22 * av * ac * pr * ui
                if pr_scope == "C":
                    base_score = min(1.08 * (impact + exploitability), 10.0)
                else:
                    base_score = min(impact + exploitability, 10.0)
                return round(math.ceil(base_score * 10) / 10, 1)
            except Exception:
                pass

        return None

    def _extract_fixed_version(self, vuln: dict) -> str:
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return ""

    def _extract_affected_range(self, vuln: dict) -> str:
        ranges = []
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                introduced = ""
                fixed = ""
                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced or fixed:
                    if introduced and fixed:
                        ranges.append(f">={introduced}, <{fixed}")
                    elif introduced:
                        ranges.append(f">={introduced}")
                    elif fixed:
                        ranges.append(f"<{fixed}")
            versions = affected.get("versions", [])
            if versions and not ranges:
                if len(versions) <= 5:
                    ranges.append(", ".join(versions))
                else:
                    ranges.append(f"{versions[0]} ... {versions[-1]} ({len(versions)} versions)")
        return " | ".join(ranges) if ranges else ""
