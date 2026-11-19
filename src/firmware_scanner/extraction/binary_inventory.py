"""Attribute binary evidence to a file or an independently identified embedded library."""
import hashlib
import json
import re
from collections import defaultdict
from urllib.parse import quote

from .binary_reference import openssl_compatibility_only
from .elf_deep_extractor import ELFDeepExtractor
from .emba_rules import scan_binary_with_rules
from .models import Component, ExtractionMethod, VersionConfidence

_DEVELOPMENT = re.compile(
    r'dev|git|snapshot|alpha|beta|rc\d|-(?:\d+-)?g[0-9a-f]{7,40}(?:$|-dirty)',
    re.IGNORECASE,
)
_SOURCE_PATH = re.compile(
    rb"(?:external|packages|system|bionic|frameworks|hardware|vendor)/"
    rb"[A-Za-z0-9_.@+/-]{1,220}\.(?:rs|c|cc|cpp|cxx|h|hpp|S)"
)


def identity_key(name: str) -> str:
    name = name.rsplit('/', 1)[-1].lower().split('.so', 1)[0]
    name = name.removeprefix('lib')
    name = name.replace('-', '').replace('_', '').replace(' ', '')
    return {
        'z': 'zlib', 'png16': 'png', 'png12': 'png', 'libpng': 'png',
        'sqlite': 'sqlite3', 'harfbuzzng': 'harfbuzz', 'jpegturbo': 'jpeg',
        'libjpegturbo': 'jpeg', 'freetype2': 'freetype', 'ft2': 'freetype',
        'xml': 'xml2', 'libxml2': 'xml2', 'protobufcpplite': 'protobuf',
        'protobufcppfull': 'protobuf', 'protobuflite': 'protobuf',
        'ext2fs': 'e2fsprogs', 'ext2blkid': 'e2fsprogs', 'ext2comerr': 'e2fsprogs',
        'e2fsck': 'e2fsprogs', 'mke2fs': 'e2fsprogs', 'tune2fs': 'e2fsprogs',
        'resize2fs': 'e2fsprogs', 'sh': 'mksh', 'asound': 'alsalib',
        'lzma': 'xzutils', 'openwrtuclient': 'uclient',
        'icuuc': 'icu', 'icui18n': 'icu',
        'busyboxsmp': 'busybox', 'pppd': 'ppp',
        'speexwrapper': 'speex',
        'pcre28': 'pcre2', 'pcre216': 'pcre2', 'pcre232': 'pcre2',
        'yaml0': 'yaml',
    }.get(name, name)


class BinaryInventory:
    """Keep exact releases, identity evidence and build/interface facts distinct."""

    _MAX_CONTENT_CACHE_ENTRIES = 4096

    def __init__(self, database_enricher=None, source_manifest=None):
        from .binary_reference import BinaryReferenceMatcher
        from .binary_samples import BinarySampleMatcher
        from .semantic_version import SemanticVersionExtractor
        from .static_version import StaticVersionExtractor
        self._reference = BinaryReferenceMatcher()
        self._static = StaticVersionExtractor()
        self._semantic = SemanticVersionExtractor()
        self._samples = BinarySampleMatcher()
        from .rust_version_estimate import RustVersionEstimator
        self._rust_estimator = RustVersionEstimator()
        self._deep = ELFDeepExtractor()
        self._database_enricher = database_enricher
        self._source_project_paths = tuple(sorted(
            {
                str(project.get("path", "")).strip("/")
                for project in (source_manifest or {}).get("projects", [])
                if project.get("path")
            },
            key=len,
            reverse=True,
        ))
        self._content_cache: dict[tuple[str, str, str], list[Component]] = {}
        self._content_cache_hits = 0

    def extract(self, data: bytes, filename: str, location: str,
                component_type: str = 'library') -> list[Component]:
        if not data.startswith(b'\x7fELF'):
            return []
        digest = hashlib.sha256(data).hexdigest()
        cache_key = (digest, filename.casefold(), component_type)
        cached = self._content_cache.get(cache_key)
        if cached is not None:
            self._content_cache_hits += 1
            return self._rebase_components(cached, location)
        properties = [
            {'name': 'firmware:evidence:location', 'value': location},
            {'name': 'firmware:binary:sha256', 'value': digest},
        ]
        if self._source_project_paths:
            for evidence in self._source_project_evidence(data):
                properties.append({
                    'name': 'firmware:source:path-project',
                    'value': evidence['project'],
                })
                properties.append({
                    'name': 'firmware:source:path-evidence',
                    'value': json.dumps(evidence, sort_keys=True),
                })
        claims = []
        deep = self._deep.extract(filename, data)
        if deep:
            properties.extend(deep.facts)
            if deep.toolchain:
                properties.append({'name': 'firmware:elf:toolchain', 'value': deep.toolchain})
            if deep.version and deep.version_kind != 'release':
                properties.append({'name': f'firmware:{deep.version_kind}:version', 'value': deep.version})
                properties.append({'name': f'firmware:{deep.version_kind}:evidence', 'value': deep.evidence})
            elif deep.version:
                claims.append((deep.canonical_name, deep.version, deep.confidence, deep.method, deep.evidence, ''))
            elif deep.confidence >= .8 and deep.canonical_name != filename:
                claims.append((deep.canonical_name, '', deep.confidence, deep.method, deep.evidence, ''))
        for hit in self._reference.match(
            data,
            filename,
            defined_symbols=deep.defined_symbols if deep is not None else None,
        ):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.STATIC_RULE, hit.evidence, hit.source))
        for hit in self._static.extract(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        for hit in self._semantic.extract(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        from .protobuf_version import extract_protobuf_versions
        for hit in extract_protobuf_versions(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        from .tflite_version import extract_tflite_runtime
        for hit in extract_tflite_runtime(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        from .object_version import extract_object_versions
        for hit in extract_object_versions(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.SYMBOL_TABLE, hit.evidence, ''))
        from .structured_version import extract_structured_versions
        for hit in extract_structured_versions(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        if b'u_getVersion' in data and b'u_versionFromString' in data:
            from .icu_version import extract_icu
            for hit in extract_icu(data):
                claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        if b'FT_Library_Version' in data and b'FT_New_Library' in data:
            from .freetype_legacy_version import extract_freetype_legacy_version
            from .freetype_version import extract_freetype
            for hit in extract_freetype(data):
                claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
            for hit in extract_freetype_legacy_version(data):
                claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        for hit in self._samples.match(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.BINARY_SIGNATURE, hit.evidence, ''))
        from .vendor_version import extract_vendor_versions
        for hit in extract_vendor_versions(data, filename):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        sample_candidates = self._samples.candidates(data)
        if sample_candidates:
            properties.append({'name': 'firmware:reference:exact-file-candidates',
                               'value': json.dumps(sample_candidates, sort_keys=True)})

        # EMBA remains a supplementary source, attributed to its identified
        # product instead of assigning the first match to the containing ELF.
        covered = {identity_key(name) for name, *_ in claims}
        for hit in scan_binary_with_rules(data, filename):
            if identity_key(hit.name) in covered or not hit.resolved_version:
                continue
            for claim in hit.versions[:1]:
                # Legacy grep conversions also match diagnostic denials and
                # substrings such as "bc" inside "glibc". Require a real
                # product token in the observed text, beyond the rule label.
                observed = claim.evidence.split(': ', 1)[-1]
                if re.search(r'\b(?:not|without)\b', observed, re.IGNORECASE):
                    continue
                tokens = re.findall(r'[A-Za-z][A-Za-z0-9_+-]*', observed)
                if not any(identity_key(token) == identity_key(hit.name) for token in tokens):
                    continue
                # BusyBox's DHCP vendor class is "udhcp " BB_VER. It is
                # evidence of its applet, not another native library release.
                applet_banners = re.findall(
                    rb'(?:^|[\x00\r\n])udhcp(?:c|d)? ([0-9][A-Za-z0-9.+_@-]*)(?=[\x00\r\n\t ])',
                    data,
                ) if hit.name.lower() in ('udhcp', 'udhcpc', 'udhcpd') else []
                applet_versions = {value.decode('ascii') for value in applet_banners}
                if (component_type == 'application' and identity_key(filename) == 'busybox'
                        and hit.name.lower() in ('udhcp', 'udhcpc', 'udhcpd')
                        and len(applet_versions) == 1 and applet_versions.issubset({
                            version for name, version, *_ in claims
                            if identity_key(name) == 'busybox' and version
                        })):
                    properties.extend([
                        {'name': 'firmware:busybox:applet', 'value': hit.name},
                        {'name': 'firmware:busybox:applet:evidence',
                         'value': 'udhcp ' + next(iter(applet_versions))},
                    ])
                    continue
                # The converted supplementary rule may capture a numeric
                # prefix. Prefer complete applet banners, preserving conflicts.
                for version in sorted(applet_versions) or [hit.resolved_version]:
                    claims.append((hit.name, version, min(claim.confidence, .85),
                                   ExtractionMethod.STATIC_RULE, claim.evidence,
                                   'https://github.com/e-m-b-a/emba'))

        groups = defaultdict(list)
        for name, version, confidence, method, evidence, source in claims:
            if identity_key(name) == 'openssl' and version and openssl_compatibility_only(data, version):
                prop = {'name': 'firmware:compatibility:openssl', 'value': version}
                if prop not in properties:
                    properties.append(prop)
                continue
            if version.lower() in ('unknown', 'detected', 'boringssl') or version.endswith('+'):
                version = ''
            key = identity_key(name)
            if component_type == 'application' and name.lower() == 'libcurl':
                key = 'libcurl-runtime'
            groups[key].append((name, version, confidence, method, evidence, source))
        host_key = identity_key(filename)
        if host_key in ('ssl', 'crypto', 'openssl'):
            if 'boringssl' in groups:
                host_key = 'boringssl'
            elif 'openssl' in groups:
                host_key = 'openssl'
        host_claims = groups.pop(host_key, [])
        host = self._component(filename, component_type, location, host_claims, properties)
        if not host.resolved_version and not any(
                prop['name'] == 'firmware:version:conflict' for prop in host.properties):
            from .filename_release import extract_filename_release
            filename_release = extract_filename_release(filename)
            if filename_release is not None:
                identity, version, evidence = filename_release
                host.resolved_version = version
                host.purl += '@' + quote(version, safe='._-+')
                host.versions.append(VersionConfidence(
                    version=version, confidence=.85,
                    method=ExtractionMethod.STRING_PATTERN, evidence=evidence))
                host.properties.extend([
                    {'name': 'firmware:version:kind', 'value': 'filename-release'},
                    {'name': 'firmware:identity', 'value': identity},
                ])
                self._set_property(host, 'firmware:version:resolution-state', 'estimated')
        if not host.resolved_version and not any(
                prop['name'] == 'firmware:version:conflict' for prop in host.properties):
            estimate = self._rust_estimator.estimate(data, filename)
            if estimate is not None:
                host.resolved_version = estimate.version
                host.purl += '@' + quote(estimate.version, safe='._-+')
                host.versions.append(VersionConfidence(
                    version=estimate.version, confidence=min(.85, estimate.support),
                    method=ExtractionMethod.VERSION_ESTIMATE, evidence=estimate.evidence))
                host.properties.extend([
                    {'name': 'firmware:version:kind', 'value': estimate.kind},
                    {'name': 'firmware:version:candidates', 'value': json.dumps(estimate.candidates)},
                    {'name': 'firmware:rust:crate', 'value': estimate.crate},
                ])
                self._set_property(host, 'firmware:version:resolution-state', 'estimated')
        components = [host]
        for key, matches in groups.items():
            # An unversioned defined-symbol set is still useful identity
            # evidence. Its location is retained for later independent review.
            extra = self._component(matches[0][0], 'library', location, matches, [
                {'name': 'firmware:evidence:location', 'value': location},
                {'name': 'firmware:evidence:container', 'value': filename},
                {'name': 'firmware:relationship', 'value': 'contains-evidence-for'},
            ])
            components.append(extra)
        if self._database_enricher is not None:
            self._database_enricher.enrich(host, data, filename, location)
        if len(self._content_cache) < self._MAX_CONTENT_CACHE_ENTRIES:
            self._content_cache[cache_key] = [
                component.model_copy(deep=True) for component in components
            ]
        return components

    def _source_project_evidence(self, data: bytes) -> list[dict]:
        """Map embedded source-file paths to the longest manifest project."""
        projects: dict[str, dict] = {}
        for match in _SOURCE_PATH.finditer(data):
            source_path = match.group(0).decode("ascii", errors="ignore").lstrip("./")
            for project in self._source_project_paths:
                if source_path.startswith(project + "/"):
                    projects.setdefault(project, {
                        "project": project,
                        "source_path": source_path,
                        "file_offset": match.start(),
                    })
                    break
            if len(projects) >= 16:
                break
        return [projects[project] for project in sorted(projects)]

    @property
    def database_stats(self) -> dict:
        if self._database_enricher is None:
            return {}
        return self._database_enricher.stats.as_dict()

    @property
    def analysis_stats(self) -> dict:
        return {
            "content_cache_hits": self._content_cache_hits,
            "content_cache_entries": len(self._content_cache),
        }

    @staticmethod
    def _set_property(component: Component, name: str, value: str) -> None:
        component.properties = [
            prop for prop in component.properties if prop.get("name") != name
        ]
        component.properties.append({"name": name, "value": value})

    @staticmethod
    def _rebase_components(components: list[Component], location: str) -> list[Component]:
        """Clone cached content evidence and replace path-specific properties."""
        result = [component.model_copy(deep=True) for component in components]
        for component in result:
            original_location = next((
                str(prop.get("value", ""))
                for prop in component.properties
                if prop.get("name") == "firmware:evidence:location"
            ), "")
            if original_location:
                component.description = component.description.replace(
                    original_location,
                    location,
                )
                for version in component.versions:
                    version.evidence = version.evidence.replace(
                        original_location,
                        location,
                    )
            for prop in component.properties:
                value = str(prop.get("value", ""))
                if prop.get("name") == "firmware:evidence:location":
                    prop["value"] = location
                elif original_location and original_location in value:
                    prop["value"] = value.replace(original_location, location)
        return result

    @staticmethod
    def _component(name, component_type, location, matches, properties):
        versions = []
        observed = set()
        numeric_api_values = set()
        explicit_kinds = set()
        for identity, version, confidence, method, evidence, source in matches:
            if version:
                observed.add(version)
                if method == ExtractionMethod.DISASSEMBLY and evidence.startswith('{'):
                    try:
                        metadata = json.loads(evidence)
                        if metadata.get('encoding'):
                            numeric_api_values.add(version)
                        if metadata.get('version_kind') in ('vendor-build', 'runtime'):
                            explicit_kinds.add(metadata['version_kind'])
                    except (ValueError, TypeError, AttributeError):
                        pass
            claim = VersionConfidence(version=version, confidence=confidence, method=method, evidence=evidence)
            if claim not in versions:
                versions.append(claim)
            for key, value in [('firmware:identity', identity), ('firmware:evidence:source', source)]:
                prop = {'name': key, 'value': value}
                if value and prop not in properties:
                    properties.append(prop)
        # An integer API cannot encode a vendor/development suffix. Keep its
        # evidence, but prefer an independently observed complete string.
        for numeric in numeric_api_values:
            if any(full.startswith(numeric + separator)
                   for full in observed for separator in ('-', '+')):
                observed.discard(numeric)
                properties.append({'name': 'firmware:version:numeric-base', 'value': numeric})
        version = next(iter(observed)) if len(observed) == 1 else ''
        if len(observed) > 1:
            properties.append({'name': 'firmware:version:conflict', 'value': ', '.join(sorted(observed))})
        if version:
            kind = ('vendor-build' if explicit_kinds == {'vendor-build'} else
                    'runtime' if explicit_kinds == {'runtime'} else
                    'development' if _DEVELOPMENT.search(version) else 'observed-release')
            properties.append({'name': 'firmware:version:kind', 'value': kind})
        if not versions:
            versions = [VersionConfidence(version='', confidence=.5, method=ExtractionMethod.BINARY_SIGNATURE,
                                          evidence=f'ELF file at {location}; release version unknown')]
        state = (
            "conflict-unresolved"
            if any(prop.get("name") == "firmware:version:conflict" for prop in properties)
            else "equivalence-class"
            if len(observed) > 1
            else "exact"
            if version and any(
                item.version == version
                and item.confidence >= 0.9
                and item.method != ExtractionMethod.VERSION_ESTIMATE
                for item in versions
            )
            else "estimated"
            if version
            else "unknown"
        )
        if not any(prop.get("name") == "firmware:version:resolution-state" for prop in properties):
            properties.append({"name": "firmware:version:resolution-state", "value": state})
        return Component(name=name, component_type=component_type, resolved_version=version,
                         purl=f'pkg:generic/{quote(name, safe="._-")}' + (f'@{quote(version, safe="._-+")}' if version else ''),
                         description=f'{"Native library" if component_type == "library" else "ELF executable"} at {location}',
                         versions=versions, properties=properties)
