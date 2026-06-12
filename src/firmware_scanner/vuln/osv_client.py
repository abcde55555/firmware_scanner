"""OSV API client with local caching."""

import json
import urllib.request
import urllib.error
from pathlib import Path

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


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"
    TIMEOUT = 120
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

    def parse_vulns(self, raw_vulns: list[dict]) -> list[Vulnerability]:
        """Convert raw OSV JSON vulnerability objects to our model."""
        parsed = []
        for v in raw_vulns:
            severity, score, vector = self._extract_severity(v)
            refs = [
                VulnReference(url=r.get("url", ""), type=r.get("type", ""))
                for r in v.get("references", [])
            ]
            aliases = v.get("aliases", [])
            vuln_id = v.get("id", "")

            fixed_ver = self._extract_fixed_version(v)
            affected_str = self._extract_affected_range(v)

            parsed.append(Vulnerability(
                id=vuln_id,
                summary=v.get("summary", ""),
                details=v.get("details", ""),
                aliases=aliases,
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                affected_versions=affected_str,
                fixed_version=fixed_ver,
                references=refs,
                published=v.get("published", ""),
                modified=v.get("modified", ""),
            ))
        return parsed

    def _build_query(self, purl: str, name: str, version: str, ecosystem: str) -> dict:
        if purl:
            payload: dict = {"package": {"purl": purl}}
            if version:
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
        """Fetch multiple queries via batch API, chunking by BATCH_SIZE."""
        all_results: list[list[dict]] = []
        for i in range(0, len(queries), self.BATCH_SIZE):
            chunk = queries[i:i + self.BATCH_SIZE]
            chunk_results = self._post_batch(chunk)
            all_results.extend(chunk_results)
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
        """Extract base score from CVSS vector if embedded, or estimate from metrics."""
        if not vector:
            return None
        # OSV sometimes puts score directly in the vector field as a number
        try:
            return float(vector)
        except ValueError:
            pass
        # For CVSS v3 vectors, try to extract from common patterns
        # The OSV API doesn't always provide numeric scores in severity,
        # but we can do a basic extraction from ecosystem_specific or database_specific
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
