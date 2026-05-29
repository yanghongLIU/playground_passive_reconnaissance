from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

console = Console()


def _domain_table(domain_info: dict) -> Table:
    t = Table(title="Domain", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Field", style="bold")
    t.add_column("Value")
    t.add_row("Input", domain_info.get("input", ""))
    t.add_row("Subdomain", domain_info.get("subdomain", "") or "[dim]—[/dim]")
    t.add_row("Domain", domain_info.get("domain", ""))
    t.add_row("Suffix (TLD)", domain_info.get("suffix", ""))
    t.add_row("Registered Domain", domain_info.get("registered_domain", ""))
    return t


def _whois_table(probe: dict) -> Table:
    t = Table(title="WHOIS", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Field", style="bold")
    t.add_column("Value")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]

    def fmt(val):
        if val is None:
            return "[dim]—[/dim]"
        if isinstance(val, list):
            return "\n".join(val)
        return str(val)

    expiry_raw = data.get("expiration_date")
    expiry_str = fmt(expiry_raw)

    t.add_row("Registrar", fmt(data.get("registrar")))
    t.add_row("Org", fmt(data.get("org")))
    t.add_row("Country", fmt(data.get("country")))
    t.add_row("Created", fmt(data.get("creation_date")))
    t.add_row("Updated", fmt(data.get("updated_date")))
    t.add_row("Expires", expiry_str)
    t.add_row("Name Servers", fmt(data.get("name_servers")))
    t.add_row("Status", fmt(data.get("status")))
    return t


def _dns_table(probe: dict) -> Table:
    t = Table(title="DNS Records", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Type", style="bold")
    t.add_column("Records")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"]:
        records = data.get(rtype, [])
        if records:
            t.add_row(rtype, "\n".join(records))
        else:
            t.add_row(f"[dim]{rtype}[/dim]", "[dim]—[/dim]")
    return t


def _ssl_table(probe: dict) -> Table:
    t = Table(title="SSL / TLS Certificate", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Field", style="bold")
    t.add_column("Value")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    days = data.get("days_until_expiry")
    if days is not None:
        if days > 30:
            days_str = f"[green]{days}[/green]"
        elif days >= 10:
            days_str = f"[yellow]{days}[/yellow]"
        else:
            days_str = f"[red]{days}[/red]"
    else:
        days_str = "[dim]—[/dim]"

    sans = data.get("sans", [])
    sans_str = ", ".join(sans) if sans else "[dim]—[/dim]"

    t.add_row("TLS Version", data.get("tls_version") or "[dim]—[/dim]")
    t.add_row("Subject CN", data.get("subject_cn") or "[dim]—[/dim]")
    t.add_row("Issuer CN", data.get("issuer_cn") or "[dim]—[/dim]")
    t.add_row("Issuer Org", data.get("issuer_o") or "[dim]—[/dim]")
    t.add_row("SANs", sans_str)
    t.add_row("Valid From", data.get("valid_from") or "[dim]—[/dim]")
    t.add_row("Valid To", data.get("valid_to") or "[dim]—[/dim]")
    t.add_row("Days Until Expiry", days_str)
    t.add_row("Serial Number", data.get("serial_number") or "[dim]—[/dim]")
    t.add_row("Signature Algorithm", data.get("signature_algorithm") or "[dim]—[/dim]")
    t.add_row("SHA-256 Fingerprint", data.get("sha256_fingerprint") or "[dim]—[/dim]")
    return t


def _http_table(probe: dict) -> Table:
    t = Table(title="HTTP Response", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Field", style="bold")
    t.add_column("Value")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    status = data.get("status_code")
    if status is not None:
        if 200 <= status < 300:
            status_str = f"[green]{status}[/green]"
        elif 300 <= status < 400:
            status_str = f"[yellow]{status}[/yellow]"
        else:
            status_str = f"[red]{status}[/red]"
    else:
        status_str = "[dim]—[/dim]"

    chain = data.get("redirect_chain", [])
    chain_str = " → ".join(chain) if chain else "[dim]none[/dim]"

    t.add_row("Status Code", status_str)
    t.add_row("Final URL", data.get("final_url") or "[dim]—[/dim]")
    t.add_row("Response Time", f"{data.get('response_time_ms', 0):.0f} ms")
    t.add_row("Redirect Chain", chain_str)
    t.add_row("Server", data.get("server") or "[dim]—[/dim]")
    t.add_row("Content-Type", data.get("content_type") or "[dim]—[/dim]")
    t.add_row("X-Powered-By", data.get("x_powered_by") or "[dim]—[/dim]")
    return t


def _security_headers_table(probe: dict) -> Table:
    if not probe["success"]:
        t = Table(title="Security Headers", box=box.ROUNDED, show_header=True, header_style="bold cyan")
        t.add_column("Field", style="bold")
        t.add_column("Value")
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    grade = data.get("grade", "?")
    score = data.get("score", 0)

    if grade in ("A+", "A"):
        grade_str = f"[green]{grade}[/green]"
    elif grade == "B":
        grade_str = f"[yellow]{grade}[/yellow]"
    else:
        grade_str = f"[red]{grade}[/red]"

    t = Table(
        title=f"Security Headers — Grade: {grade_str} ({score}/95)",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    t.add_column("Header", style="bold")
    t.add_column("Present")
    t.add_column("Value Snippet")
    t.add_column("Points", justify="right")

    for header_name, info in data.get("headers", {}).items():
        present = info.get("present", False)
        value = info.get("value", "")
        weight = info.get("weight", 0)
        snippet = (value[:60] + "…") if len(value) > 60 else value
        present_str = "[green]✓[/green]" if present else "[red]✗[/red]"
        points_str = f"[green]+{weight}[/green]" if present else f"[dim]+{weight}[/dim]"
        t.add_row(header_name, present_str, snippet or "[dim]—[/dim]", points_str)

    return t


def _tech_table(probe: dict) -> Table:
    t = Table(title="Technology Fingerprint", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Technology", style="bold")
    t.add_column("Category")
    t.add_column("Detected Via", style="dim")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error", "")
        return t

    techs = probe["data"].get("technologies", [])
    if not techs:
        t.add_row("[dim]No technologies detected[/dim]", "", "")
    else:
        for tech in techs:
            t.add_row(
                tech.get("name", ""),
                tech.get("category", ""),
                tech.get("source", ""),
            )
    return t


def _robots_table(probe: dict) -> Table:
    t = Table(title="Robots.txt / Sitemap", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Field", style="bold")
    t.add_column("Value")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    robots_exists = data.get("robots_exists", False)
    disallowed = data.get("disallowed", [])
    allowed = data.get("allowed", [])
    sitemap_urls = data.get("sitemap_urls", [])
    sitemap_exists = data.get("sitemap_exists", False)

    t.add_row("robots.txt found", "[green]Yes[/green]" if robots_exists else "[red]No[/red]")
    t.add_row("Disallowed paths (*)", str(len(disallowed)))
    t.add_row("Allowed paths (*)", str(len(allowed)))

    if disallowed:
        sample = disallowed[:5]
        suffix = f" (+{len(disallowed) - 5} more)" if len(disallowed) > 5 else ""
        t.add_row("Disallowed sample", "\n".join(sample) + suffix)

    t.add_row("Sitemap URLs", str(len(sitemap_urls)))
    if sitemap_urls:
        t.add_row("Sitemaps", "\n".join(sitemap_urls[:5]))
    t.add_row("Sitemap reachable", "[green]Yes[/green]" if sitemap_exists else "[dim]No[/dim]")
    return t


def _ports_table(probe: dict) -> Table:
    t = Table(title="Open Ports (TCP connect)", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Port", style="bold", justify="right")
    t.add_column("State")
    t.add_column("Latency", justify="right")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error", "")
        return t

    for entry in probe["data"].get("ports", []):
        port = str(entry.get("port", ""))
        state = entry.get("state", "")
        latency = entry.get("latency_ms")

        if state == "open":
            state_str = "[green]open[/green]"
            lat_str = f"{latency} ms" if latency is not None else "[dim]—[/dim]"
        elif state == "filtered":
            state_str = "[yellow]filtered[/yellow]"
            lat_str = "[dim]—[/dim]"
        else:
            state_str = "[red]closed[/red]"
            lat_str = "[dim]—[/dim]"

        t.add_row(port, state_str, lat_str)

    return t


def _crt_sh_table(probe: dict) -> Table:
    t = Table(title="Subdomains (crt.sh / CT logs)", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Subdomain")

    if not probe["success"]:
        t.add_row(probe.get("error") or "unknown error")
        return t

    data = probe["data"]
    subdomains = data.get("subdomains", [])
    count = data.get("count", len(subdomains))
    shown = subdomains[:30]

    if not shown:
        t.add_row("[dim]No subdomains found in CT logs[/dim]")
    else:
        for sub in shown:
            t.add_row(sub)
        if count > 30:
            t.add_row(f"[dim]+ {count - 30} more[/dim]")

    t.caption = f"Total: {count}"
    return t


def _geo_table(probe: dict) -> Table:
    t = Table(title="IP Geolocation (ipinfo.io)", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("IP", style="bold")
    t.add_column("City")
    t.add_column("Region")
    t.add_column("Country")
    t.add_column("Org / ASN")
    t.add_column("Timezone")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error", "", "", "", "")
        return t

    locations = probe["data"].get("locations", [])
    if not locations:
        t.add_row("[dim]No A records resolved[/dim]", "", "", "", "", "")
    else:
        for loc in locations:
            if "error" in loc:
                t.add_row(loc.get("ip", ""), f"[red]{loc['error']}[/red]", "", "", "", "")
            else:
                t.add_row(
                    loc.get("ip", "") or "[dim]—[/dim]",
                    loc.get("city", "") or "[dim]—[/dim]",
                    loc.get("region", "") or "[dim]—[/dim]",
                    loc.get("country", "") or "[dim]—[/dim]",
                    loc.get("org", "") or "[dim]—[/dim]",
                    loc.get("timezone", "") or "[dim]—[/dim]",
                )
    return t


def _ssl_labs_table(probe: dict) -> Table:
    data = probe["data"]
    grade = data.get("grade", "?")

    if grade in ("A+",):
        grade_color = "bright_green"
    elif grade in ("A", "A-"):
        grade_color = "green"
    elif grade in ("B",):
        grade_color = "yellow"
    elif grade in ("C", "D"):
        grade_color = "dark_orange"
    else:
        grade_color = "red"

    t = Table(
        title=f"SSL Labs — Grade: [{grade_color}]{grade}[/{grade_color}]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    t.add_column("Field", style="bold")
    t.add_column("Value")

    if not probe["success"]:
        t.add_row("[red]Error[/red]", probe.get("error") or "unknown error")
        return t

    t.add_row("Grade", f"[{grade_color}]{grade}[/{grade_color}]")
    t.add_row("IP", data.get("ip", "") or "[dim]—[/dim]")
    protocols = data.get("protocols", [])
    t.add_row("Protocols", "\n".join(protocols) if protocols else "[dim]—[/dim]")
    t.add_row("Key Exchange", data.get("key_exchange", "") or "[dim]—[/dim]")
    suites = data.get("cipher_suites", [])
    t.add_row("Cipher Suites (top)", "\n".join(suites) if suites else "[dim]—[/dim]")
    t.add_row("Forward Secrecy", str(data.get("forward_secrecy", "—")))
    t.add_row("Heartbleed", "[red]Yes[/red]" if data.get("heartbleed") else "[green]No[/green]")
    t.add_row("POODLE", "[red]Yes[/red]" if data.get("poodle") else "[green]No[/green]")
    return t


def render(result: dict) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    duration_s = result.get("total_duration_ms", 0) / 1000
    probe_count = result.get("probe_count", 0)
    cache_hits = result.get("cache_hits", 0)
    registered = result["domain"].get("registered_domain", "")

    cache_str = f"  |  Cache hits: {cache_hits}/{probe_count}" if cache_hits else ""

    console.print()
    console.print(Rule(f"[bold white]RECON REPORT: {registered}[/bold white]", style="bright_blue"))
    console.print(
        f"[dim]Generated: {now}  |  Duration: {duration_s:.1f}s  |  Probes: {probe_count}{cache_str}[/dim]"
    )
    console.print()

    console.print(_domain_table(result["domain"]))
    console.print()

    probes = result.get("probes", {})

    if "whois" in probes:
        console.print(_whois_table(probes["whois"]))
        console.print()

    if "dns" in probes:
        console.print(_dns_table(probes["dns"]))
        console.print()

    if "ssl" in probes:
        console.print(_ssl_table(probes["ssl"]))
        console.print()

    if "http" in probes:
        console.print(_http_table(probes["http"]))
        console.print()

    if "security_headers" in probes:
        console.print(_security_headers_table(probes["security_headers"]))
        console.print()

    if "tech" in probes:
        console.print(_tech_table(probes["tech"]))
        console.print()

    if "robots" in probes:
        console.print(_robots_table(probes["robots"]))
        console.print()

    if "ports" in probes:
        console.print(_ports_table(probes["ports"]))
        console.print()

    if "crt_sh" in probes:
        console.print(_crt_sh_table(probes["crt_sh"]))
        console.print()

    if "geo" in probes:
        console.print(_geo_table(probes["geo"]))
        console.print()

    if "ssl_labs" in probes and probes["ssl_labs"].get("success"):
        console.print(_ssl_labs_table(probes["ssl_labs"]))
        console.print()
