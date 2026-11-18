"""Attribute binary evidence to a file or an independently identified embedded library."""
import json
import re
from collections import defaultdict
from urllib.parse import quote

from .models import Component, ExtractionMethod, VersionConfidence
from .elf_deep_extractor import ELFDeepExtractor
from .emba_rules import scan_binary_with_rules
from .binary_reference import openssl_compatibility_only


def identity_key(name: str) -> str:
    name = name.rsplit('/', 1)[-1].lower().split('.so', 1)[0]
    if name.startswith('lib'):
        name = name[3:]
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
    }.get(name, name)


class BinaryInventory:
    """Keep exact releases, identity evidence and build/interface facts distinct."""

    def __init__(self):
        from .binary_reference import BinaryReferenceMatcher
        from .static_version import StaticVersionExtractor
        from .semantic_version import SemanticVersionExtractor
        from .binary_samples import BinarySampleMatcher
        self._reference = BinaryReferenceMatcher()
        self._static = StaticVersionExtractor()
        self._semantic = SemanticVersionExtractor()
        self._samples = BinarySampleMatcher()
        self._deep = ELFDeepExtractor()

    def extract(self, data: bytes, filename: str, location: str,
                component_type: str = 'library') -> list[Component]:
        if not data.startswith(b'\x7fELF'):
            return []
        properties = [{'name': 'firmware:evidence:location', 'value': location}]
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
        for hit in self._reference.match(data, filename):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.STATIC_RULE, hit.evidence, hit.source))
        for hit in self._static.extract(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        for hit in self._semantic.extract(data):
            claims.append((hit.name, hit.version, hit.confidence, ExtractionMethod.DISASSEMBLY, hit.evidence, ''))
        if b'u_getVersion' in data and b'u_versionFromString' in data:
            from .icu_version import extract_icu
            for hit in extract_icu(data):
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
                if re.search(r'\b(?:not|without)\b', observed, re.I):
                    continue
                tokens = re.findall(r'[A-Za-z][A-Za-z0-9_+-]*', observed)
                if not any(identity_key(token) == identity_key(hit.name) for token in tokens):
                    continue
                claims.append((hit.name, hit.resolved_version, min(claim.confidence, .85),
                               ExtractionMethod.STATIC_RULE, claim.evidence, 'https://github.com/e-m-b-a/emba'))

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
        return components

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
                        if metadata.get('version_kind') == 'vendor-build':
                            explicit_kinds.add('vendor-build')
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
                    'development' if re.search(r'dev|git|snapshot|alpha|beta|rc\d', version, re.I) else 'observed-release')
            properties.append({'name': 'firmware:version:kind', 'value': kind})
        if not versions:
            versions = [VersionConfidence(version='', confidence=.5, method=ExtractionMethod.BINARY_SIGNATURE,
                                          evidence=f'ELF file at {location}; release version unknown')]
        return Component(name=name, component_type=component_type, resolved_version=version,
                         purl=f'pkg:generic/{quote(name, safe="._-")}' + (f'@{quote(version, safe="._-+")}' if version else ''),
                         description=f'{"Native library" if component_type == "library" else "ELF executable"} at {location}',
                         versions=versions, properties=properties)
