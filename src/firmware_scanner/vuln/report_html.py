"""Standalone HTML vulnerability report generator."""

import html as html_mod
from .models import VulnScanResult, ComponentVulnResult, Severity, Vulnerability


def generate_vuln_html(result: VulnScanResult) -> str:
    firmware_name = result.firmware_path.split("/")[-1] if "/" in result.firmware_path else result.firmware_path.split("\\")[-1] if "\\" in result.firmware_path else result.firmware_path

    affected = [r for r in result.results if r.vulnerabilities]
    clean = [r for r in result.results if not r.vulnerabilities and not r.query_error]

    affected.sort(key=lambda r: _max_severity_score(r), reverse=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report - {html_mod.escape(firmware_name)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #2d3748; line-height: 1.6; padding: 2rem; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{ background: linear-gradient(135deg, #742a2a 0%, #c53030 50%, #e53e3e 100%); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }}
.header h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
.header .subtitle {{ opacity: 0.9; font-size: 0.95rem; }}
.card {{ background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.card h2 {{ font-size: 1.2rem; color: #1a365d; margin-bottom: 1rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }}
.stats {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1rem; }}
.stat {{ text-align: center; padding: 1rem; border-radius: 8px; min-width: 120px; }}
.stat .number {{ font-size: 2rem; font-weight: 700; }}
.stat .label {{ font-size: 0.8rem; color: #718096; text-transform: uppercase; }}
.stat-total {{ background: #edf2f7; }}
.stat-total .number {{ color: #2d3748; }}
.stat-critical {{ background: #fff5f5; }}
.stat-critical .number {{ color: #c53030; }}
.stat-high {{ background: #fffaf0; }}
.stat-high .number {{ color: #c05621; }}
.stat-medium {{ background: #fffff0; }}
.stat-medium .number {{ color: #975a16; }}
.stat-low {{ background: #ebf8ff; }}
.stat-low .number {{ color: #2b6cb0; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #edf2f7; color: #4a5568; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 1rem; text-align: left; }}
td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }}
tr:hover {{ background: #f7fafc; }}
.badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
.badge-critical {{ background: #fed7d7; color: #742a2a; }}
.badge-high {{ background: #feebc8; color: #7b341e; }}
.badge-medium {{ background: #fefcbf; color: #744210; }}
.badge-low {{ background: #bee3f8; color: #2a4365; }}
.badge-unknown {{ background: #e2e8f0; color: #4a5568; }}
.vuln-details {{ margin: 0.5rem 0 0.5rem 1rem; padding: 0.75rem; background: #f7fafc; border-left: 3px solid #e2e8f0; border-radius: 4px; }}
.vuln-details.severity-critical {{ border-left-color: #c53030; }}
.vuln-details.severity-high {{ border-left-color: #dd6b20; }}
.vuln-details.severity-medium {{ border-left-color: #d69e2e; }}
.vuln-details.severity-low {{ border-left-color: #3182ce; }}
.vuln-id {{ font-weight: 700; font-size: 0.9rem; }}
.vuln-summary {{ margin: 0.3rem 0; font-size: 0.85rem; color: #4a5568; }}
.vuln-meta {{ font-size: 0.8rem; color: #718096; display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 0.3rem; }}
.vuln-meta span {{ display: inline-flex; align-items: center; gap: 0.3rem; }}
.ref-links {{ margin-top: 0.3rem; }}
.ref-links a {{ font-size: 0.8rem; color: #3182ce; text-decoration: none; margin-right: 0.75rem; }}
.ref-links a:hover {{ text-decoration: underline; }}
details {{ margin-bottom: 0.5rem; }}
details summary {{ cursor: pointer; font-weight: 600; color: #2d3748; padding: 0.5rem 0; }}
details summary:hover {{ color: #3182ce; }}
.clean-list {{ columns: 3; column-gap: 2rem; }}
.clean-list li {{ font-size: 0.85rem; color: #4a5568; margin-bottom: 0.3rem; break-inside: avoid; }}
.error {{ padding: 0.5rem 1rem; background: #fffbeb; border-left: 3px solid #f6ad55; margin-bottom: 0.5rem; border-radius: 4px; font-size: 0.85rem; }}
.footer {{ text-align: center; color: #a0aec0; font-size: 0.8rem; margin-top: 2rem; }}
.score-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: white; }}
.score-critical {{ background: #c53030; }}
.score-high {{ background: #dd6b20; }}
.score-medium {{ background: #d69e2e; }}
.score-low {{ background: #3182ce; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <div class="subtitle">{html_mod.escape(firmware_name)} | SHA-256: {result.firmware_sha256[:16]}... | Scanned: {result.scan_timestamp[:19]}</div>
    </div>

    <div class="card">
        <h2>Summary</h2>
        <div class="stats">
            <div class="stat stat-total"><div class="number">{result.total_vulnerabilities}</div><div class="label">Total Vulns</div></div>
            <div class="stat stat-critical"><div class="number">{result.critical_count}</div><div class="label">Critical</div></div>
            <div class="stat stat-high"><div class="number">{result.high_count}</div><div class="label">High</div></div>
            <div class="stat stat-medium"><div class="number">{result.medium_count}</div><div class="label">Medium</div></div>
            <div class="stat stat-low"><div class="number">{result.low_count}</div><div class="label">Low</div></div>
        </div>
        <p style="font-size:0.9rem; color:#718096;">Scanned {result.total_components_scanned} components, {len(affected)} with known vulnerabilities.</p>
    </div>

    <div class="card">
        <h2>Affected Components ({len(affected)})</h2>
        {_render_affected_components(affected)}
    </div>

    {_render_clean_section(clean)}
    {_render_errors_section(result.errors)}

    <div class="footer">Generated by firmware-scanner | Vulnerability data from OSV (Google Open Source Vulnerabilities)</div>
</div>
</body>
</html>"""


def _render_affected_components(affected: list[ComponentVulnResult]) -> str:
    if not affected:
        return '<p style="color:#718096;font-size:0.9rem;">No vulnerabilities found.</p>'

    rows = []
    for comp in affected:
        max_sev = _highest_severity(comp)
        vuln_ids = [v.id for v in comp.vulnerabilities[:5]]
        ids_str = ", ".join(vuln_ids)
        if len(comp.vulnerabilities) > 5:
            ids_str += f" (+{len(comp.vulnerabilities) - 5} more)"

        details_html = _render_vuln_details(comp.vulnerabilities)

        rows.append(f"""<details>
<summary>{html_mod.escape(comp.component_name)} <span style="font-weight:normal;color:#718096;">v{html_mod.escape(comp.component_version)}</span> &mdash; <span class="badge badge-{max_sev.value}">{max_sev.value.upper()}</span> ({len(comp.vulnerabilities)} vuln{"s" if len(comp.vulnerabilities) != 1 else ""})</summary>
{details_html}
</details>""")

    return "\n".join(rows)


def _render_vuln_details(vulns: list[Vulnerability]) -> str:
    parts = []
    for v in vulns:
        sev_class = f"severity-{v.severity.value}"
        score_html = ""
        if v.cvss_score is not None:
            score_class = "score-" + v.severity.value
            score_html = f' <span class="score-badge {score_class}">{v.cvss_score:.1f}</span>'

        refs_html = ""
        if v.references:
            links = []
            for ref in v.references[:5]:
                ref_label = ref.type if ref.type else "Link"
                links.append(f'<a href="{html_mod.escape(ref.url)}" target="_blank">{html_mod.escape(ref_label)}</a>')
            refs_html = f'<div class="ref-links">{"".join(links)}</div>'

        aliases_str = ""
        if v.aliases:
            aliases_str = f'<span>Aliases: {html_mod.escape(", ".join(v.aliases[:5]))}</span>'

        parts.append(f"""<div class="vuln-details {sev_class}">
    <div class="vuln-id">{html_mod.escape(v.id)}{score_html} <span class="badge badge-{v.severity.value}">{v.severity.value.upper()}</span></div>
    <div class="vuln-summary">{html_mod.escape(v.summary or v.details[:200] if v.details else "No description available")}</div>
    <div class="vuln-meta">
        {f'<span>Affected: {html_mod.escape(v.affected_versions)}</span>' if v.affected_versions else ''}
        {f'<span>Fixed: {html_mod.escape(v.fixed_version)}</span>' if v.fixed_version else ''}
        {aliases_str}
        {f'<span>Published: {html_mod.escape(v.published[:10])}</span>' if v.published else ''}
    </div>
    {refs_html}
</div>""")

    return "\n".join(parts)


def _render_clean_section(clean: list[ComponentVulnResult]) -> str:
    if not clean:
        return ""
    items = [f"<li>{html_mod.escape(c.component_name)} v{html_mod.escape(c.component_version)}</li>" for c in clean]
    return f"""<div class="card">
        <h2>Components Without Known Vulnerabilities ({len(clean)})</h2>
        <ul class="clean-list">{"".join(items)}</ul>
    </div>"""


def _render_errors_section(errors: list[str]) -> str:
    if not errors:
        return ""
    items = [f'<div class="error">{html_mod.escape(e)}</div>' for e in errors]
    return f"""<div class="card">
        <h2>Warnings</h2>
        {"".join(items)}
    </div>"""


def _highest_severity(comp: ComponentVulnResult) -> Severity:
    order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.UNKNOWN: 0}
    if not comp.vulnerabilities:
        return Severity.UNKNOWN
    return max(comp.vulnerabilities, key=lambda v: order.get(v.severity, 0)).severity


def _max_severity_score(comp: ComponentVulnResult) -> int:
    order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.UNKNOWN: 0}
    if not comp.vulnerabilities:
        return -1
    return max(order.get(v.severity, 0) for v in comp.vulnerabilities)
