from datetime import datetime, timezone

from jinja2 import Environment

_TEMPLATE_SRC = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report: {{ domain }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f1117; color: #e2e8f0; padding: 2rem; }
  h1 { font-size: 1.6rem; font-weight: 700; color: #93c5fd; margin-bottom: .25rem; }
  .meta { font-size: .85rem; color: #64748b; margin-bottom: 2rem; }
  .meta span { margin-right: 1.5rem; }
  .section { margin-bottom: 2rem; }
  .section-title { font-size: 1rem; font-weight: 600; color: #7dd3fc;
                   border-bottom: 1px solid #1e293b; padding-bottom: .4rem; margin-bottom: .75rem; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { background: #1e293b; color: #94a3b8; font-weight: 600;
       text-align: left; padding: .5rem .75rem; }
  tr:nth-child(odd) td  { background: #161b27; }
  tr:nth-child(even) td { background: #0f1117; }
  td { padding: .45rem .75rem; border-bottom: 1px solid #1e293b;
       vertical-align: top; word-break: break-word; }
  td:first-child { font-weight: 500; color: #cbd5e1; width: 30%; white-space: nowrap; }
  .badge-ok  { color: #4ade80; }
  .badge-err { color: #f87171; }
  .badge-warn{ color: #facc15; }
  .badge-dim { color: #475569; }
</style>
</head>
<body>
<h1>&#128270; Recon Report: {{ domain }}</h1>
<p class="meta">
  <span>Generated: {{ generated }}</span>
  <span>Duration: {{ "%.1f"|format(duration_s) }}s</span>
  <span>Probes: {{ probe_count }}{% if cache_hits %} | Cache hits: {{ cache_hits }}/{{ probe_count }}{% endif %}</span>
</p>

{% for section in sections %}
<div class="section">
  <div class="section-title">{{ section.title }}</div>
  {% if section.rows %}
  <table>
    <thead><tr>{% for col in section.columns %}<th>{{ col }}</th>{% endfor %}</tr></thead>
    <tbody>
      {% for row in section.rows %}
      <tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="badge-dim">No data.</p>
  {% endif %}
</div>
{% endfor %}
</body>
</html>"""

_env = Environment(autoescape=True)
_template = _env.from_string(_TEMPLATE_SRC)


def _fmt(val) -> str:
    if val is None:
        return "—"
    if isinstance(val, list):
        return "<br>".join(str(v) for v in val)
    return str(val)


def _probe_section(title: str, probe: dict, fields: list[tuple[str, str]]) -> dict:
    if not probe.get("success"):
        return {
            "title": title,
            "columns": ["Field", "Value"],
            "rows": [["Error", probe.get("error") or "unknown error"]],
        }
    data = probe.get("data", {})
    rows = [[label, _fmt(data.get(key))] for label, key in fields]
    return {"title": title, "columns": ["Field", "Value"], "rows": rows}


def _build_sections(result: dict) -> list[dict]:
    sections: list[dict] = []
    domain_info = result.get("domain", {})
    sections.append({
        "title": "Domain",
        "columns": ["Field", "Value"],
        "rows": [
            ["Input", domain_info.get("input", "—")],
            ["Subdomain", domain_info.get("subdomain") or "—"],
            ["Domain", domain_info.get("domain", "—")],
            ["Suffix (TLD)", domain_info.get("suffix", "—")],
            ["Registered Domain", domain_info.get("registered_domain", "—")],
        ],
    })

    probes = result.get("probes", {})

    if "whois" in probes:
        sections.append(_probe_section("WHOIS", probes["whois"], [
            ("Registrar", "registrar"), ("Org", "org"), ("Country", "country"),
            ("Created", "creation_date"), ("Updated", "updated_date"),
            ("Expires", "expiration_date"), ("Name Servers", "name_servers"),
            ("Status", "status"),
        ]))

    if "dns" in probes:
        p = probes["dns"]
        if not p.get("success"):
            sections.append({"title": "DNS Records", "columns": ["Type", "Records"],
                              "rows": [["Error", p.get("error") or "unknown"]]})
        else:
            data = p.get("data", {})
            rows = []
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"]:
                records = data.get(rtype, [])
                rows.append([rtype, "<br>".join(records) if records else "—"])
            sections.append({"title": "DNS Records", "columns": ["Type", "Records"], "rows": rows})

    if "ssl" in probes:
        sections.append(_probe_section("SSL / TLS Certificate", probes["ssl"], [
            ("TLS Version", "tls_version"), ("Subject CN", "subject_cn"),
            ("Issuer CN", "issuer_cn"), ("Issuer Org", "issuer_o"),
            ("SANs", "sans"), ("Valid From", "valid_from"), ("Valid To", "valid_to"),
            ("Days Until Expiry", "days_until_expiry"), ("Serial Number", "serial_number"),
            ("Signature Algorithm", "signature_algorithm"),
            ("SHA-256 Fingerprint", "sha256_fingerprint"),
        ]))

    if "http" in probes:
        sections.append(_probe_section("HTTP Response", probes["http"], [
            ("Status Code", "status_code"), ("Final URL", "final_url"),
            ("Response Time (ms)", "response_time_ms"), ("Server", "server"),
            ("Content-Type", "content_type"), ("X-Powered-By", "x_powered_by"),
        ]))

    if "security_headers" in probes:
        p = probes["security_headers"]
        if not p.get("success"):
            sections.append({"title": "Security Headers", "columns": ["Field", "Value"],
                              "rows": [["Error", p.get("error") or "unknown"]]})
        else:
            data = p.get("data", {})
            grade = data.get("grade", "?")
            score = data.get("score", 0)
            rows = [[h, "Yes" if info.get("present") else "No",
                     (info.get("value", "") or "")[:80]]
                    for h, info in data.get("headers", {}).items()]
            sections.append({
                "title": f"Security Headers — Grade: {grade} ({score}/95)",
                "columns": ["Header", "Present", "Value Snippet"],
                "rows": rows,
            })

    if "tech" in probes:
        p = probes["tech"]
        if not p.get("success"):
            sections.append({"title": "Technology Fingerprint", "columns": ["Technology", "Category"],
                              "rows": [["Error", p.get("error") or "unknown"]]})
        else:
            techs = p.get("data", {}).get("technologies", [])
            rows = [[t.get("name", ""), t.get("category", ""), t.get("source", "")]
                    for t in techs] or [["No technologies detected", "", ""]]
            sections.append({"title": "Technology Fingerprint",
                              "columns": ["Technology", "Category", "Detected Via"], "rows": rows})

    if "robots" in probes:
        p = probes["robots"]
        if not p.get("success"):
            sections.append({"title": "Robots.txt / Sitemap", "columns": ["Field", "Value"],
                              "rows": [["Error", p.get("error") or "unknown"]]})
        else:
            data = p.get("data", {})
            disallowed = data.get("disallowed", [])
            sitemap_urls = data.get("sitemap_urls", [])
            rows = [
                ["robots.txt found", "Yes" if data.get("robots_exists") else "No"],
                ["Disallowed paths (*)", str(len(disallowed))],
                ["Sitemap URLs", str(len(sitemap_urls))],
                ["Sitemap reachable", "Yes" if data.get("sitemap_exists") else "No"],
            ]
            if sitemap_urls:
                rows.append(["Sitemaps", "<br>".join(sitemap_urls[:5])])
            sections.append({"title": "Robots.txt / Sitemap", "columns": ["Field", "Value"], "rows": rows})

    if "ports" in probes:
        p = probes["ports"]
        if not p.get("success"):
            sections.append({"title": "Open Ports (TCP connect)", "columns": ["Port", "State", "Latency"],
                              "rows": [["Error", p.get("error") or "unknown", ""]]})
        else:
            rows = [[str(e.get("port", "")), e.get("state", ""),
                     f"{e['latency_ms']} ms" if e.get("latency_ms") is not None else "—"]
                    for e in p.get("data", {}).get("ports", [])]
            sections.append({"title": "Open Ports (TCP connect)",
                              "columns": ["Port", "State", "Latency"], "rows": rows})

    if "crt_sh" in probes:
        p = probes["crt_sh"]
        if not p.get("success"):
            sections.append({"title": "Subdomains (crt.sh)", "columns": ["Subdomain"],
                              "rows": [[p.get("error") or "unknown"]]})
        else:
            data = p.get("data", {})
            subs = data.get("subdomains", [])
            shown = subs[:50]
            rows = [[s] for s in shown]
            if len(subs) > 50:
                rows.append([f"… and {len(subs) - 50} more"])
            sections.append({"title": f"Subdomains (crt.sh / CT logs) — Total: {len(subs)}",
                              "columns": ["Subdomain"], "rows": rows or [["No subdomains found"]]})

    if "geo" in probes:
        p = probes["geo"]
        if not p.get("success"):
            sections.append({"title": "IP Geolocation", "columns": ["IP", "City", "Country", "Org"],
                              "rows": [["Error", p.get("error") or "unknown", "", ""]]})
        else:
            locs = p.get("data", {}).get("locations", [])
            rows = [[loc.get("ip", ""), loc.get("city", ""), loc.get("region", ""),
                     loc.get("country", ""), loc.get("org", ""), loc.get("timezone", "")]
                    for loc in locs] or [["No A records resolved", "", "", "", "", ""]]
            sections.append({"title": "IP Geolocation (ipinfo.io)",
                              "columns": ["IP", "City", "Region", "Country", "Org / ASN", "Timezone"],
                              "rows": rows})

    if "ssl_labs" in probes and probes["ssl_labs"].get("success"):
        sections.append(_probe_section("SSL Labs Full Grade", probes["ssl_labs"], [
            ("Grade", "grade"), ("IP", "ip"), ("Protocols", "protocols"),
            ("Key Exchange", "key_exchange"), ("Forward Secrecy", "forward_secrecy"),
            ("Heartbleed", "heartbleed"), ("POODLE", "poodle"),
        ]))

    return sections


def render(result: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    domain = result.get("domain", {}).get("registered_domain", "unknown")
    duration_s = result.get("total_duration_ms", 0) / 1000
    probe_count = result.get("probe_count", 0)
    cache_hits = result.get("cache_hits", 0)

    sections = _build_sections(result)

    return _template.render(
        domain=domain,
        generated=now,
        duration_s=duration_s,
        probe_count=probe_count,
        cache_hits=cache_hits,
        sections=sections,
    )
