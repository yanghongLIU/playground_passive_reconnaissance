import pandas as pd


def _to_df(rows: list[tuple[str, str]]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=["Field", "Value"])


def render(result: dict) -> dict[str, pd.DataFrame]:
    frames: dict[str, pd.DataFrame] = {}
    domain_info = result.get("domain", {})

    frames["domain"] = _to_df([
        ("Input", domain_info.get("input", "")),
        ("Subdomain", domain_info.get("subdomain") or ""),
        ("Domain", domain_info.get("domain", "")),
        ("Suffix (TLD)", domain_info.get("suffix", "")),
        ("Registered Domain", domain_info.get("registered_domain", "")),
    ])

    probes = result.get("probes", {})

    if "whois" in probes:
        p = probes["whois"]
        if p.get("success"):
            d = p.get("data", {})
            frames["whois"] = _to_df([
                ("Registrar", str(d.get("registrar", ""))),
                ("Org", str(d.get("org", ""))),
                ("Country", str(d.get("country", ""))),
                ("Created", str(d.get("creation_date", ""))),
                ("Updated", str(d.get("updated_date", ""))),
                ("Expires", str(d.get("expiration_date", ""))),
                ("Name Servers", ", ".join(d.get("name_servers", []) or [])),
                ("Status", str(d.get("status", ""))),
            ])
        else:
            frames["whois"] = _to_df([("Error", p.get("error") or "unknown")])

    if "dns" in probes:
        p = probes["dns"]
        if p.get("success"):
            d = p.get("data", {})
            rows = []
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"]:
                records = d.get(rtype, [])
                rows.append((rtype, ", ".join(records) if records else ""))
            frames["dns"] = _to_df(rows)
        else:
            frames["dns"] = _to_df([("Error", p.get("error") or "unknown")])

    if "ssl" in probes:
        p = probes["ssl"]
        if p.get("success"):
            d = p.get("data", {})
            frames["ssl"] = _to_df([
                ("TLS Version", str(d.get("tls_version", ""))),
                ("Subject CN", str(d.get("subject_cn", ""))),
                ("Issuer CN", str(d.get("issuer_cn", ""))),
                ("Issuer Org", str(d.get("issuer_o", ""))),
                ("SANs", ", ".join(d.get("sans", []) or [])),
                ("Valid From", str(d.get("valid_from", ""))),
                ("Valid To", str(d.get("valid_to", ""))),
                ("Days Until Expiry", str(d.get("days_until_expiry", ""))),
                ("Serial Number", str(d.get("serial_number", ""))),
                ("Signature Algorithm", str(d.get("signature_algorithm", ""))),
                ("SHA-256 Fingerprint", str(d.get("sha256_fingerprint", ""))),
            ])
        else:
            frames["ssl"] = _to_df([("Error", p.get("error") or "unknown")])

    if "http" in probes:
        p = probes["http"]
        if p.get("success"):
            d = p.get("data", {})
            frames["http"] = _to_df([
                ("Status Code", str(d.get("status_code", ""))),
                ("Final URL", str(d.get("final_url", ""))),
                ("Response Time (ms)", str(d.get("response_time_ms", ""))),
                ("Server", str(d.get("server", ""))),
                ("Content-Type", str(d.get("content_type", ""))),
                ("X-Powered-By", str(d.get("x_powered_by", ""))),
                ("Redirect Chain", " → ".join(d.get("redirect_chain", []) or [])),
            ])
        else:
            frames["http"] = _to_df([("Error", p.get("error") or "unknown")])

    if "security_headers" in probes:
        p = probes["security_headers"]
        if p.get("success"):
            d = p.get("data", {})
            rows = [("Grade", str(d.get("grade", ""))), ("Score", str(d.get("score", "")))]
            for h, info in d.get("headers", {}).items():
                rows.append((h, "Yes" if info.get("present") else "No"))
            frames["security_headers"] = _to_df(rows)
        else:
            frames["security_headers"] = _to_df([("Error", p.get("error") or "unknown")])

    if "tech" in probes:
        p = probes["tech"]
        if p.get("success"):
            techs = p.get("data", {}).get("technologies", [])
            rows = [(t.get("name", ""), t.get("category", "")) for t in techs]
            frames["tech"] = pd.DataFrame(rows, columns=["Field", "Value"]) if rows else _to_df([])
        else:
            frames["tech"] = _to_df([("Error", p.get("error") or "unknown")])

    if "robots" in probes:
        p = probes["robots"]
        if p.get("success"):
            d = p.get("data", {})
            frames["robots"] = _to_df([
                ("robots.txt found", str(d.get("robots_exists", False))),
                ("Disallowed paths (*)", str(len(d.get("disallowed", []) or []))),
                ("Allowed paths (*)", str(len(d.get("allowed", []) or []))),
                ("Sitemap URLs", str(len(d.get("sitemap_urls", []) or []))),
                ("Sitemap reachable", str(d.get("sitemap_exists", False))),
            ])
        else:
            frames["robots"] = _to_df([("Error", p.get("error") or "unknown")])

    if "ports" in probes:
        p = probes["ports"]
        if p.get("success"):
            ports = p.get("data", {}).get("ports", [])
            rows = [(str(e.get("port", "")), e.get("state", ""),
                     str(e.get("latency_ms", "")) if e.get("latency_ms") is not None else "")
                    for e in ports]
            frames["ports"] = pd.DataFrame(rows, columns=["Field", "Value", "Latency (ms)"])
        else:
            frames["ports"] = _to_df([("Error", p.get("error") or "unknown")])

    if "crt_sh" in probes:
        p = probes["crt_sh"]
        if p.get("success"):
            subs = p.get("data", {}).get("subdomains", [])
            frames["crt_sh"] = pd.DataFrame({"Field": range(1, len(subs) + 1),
                                              "Value": subs})
        else:
            frames["crt_sh"] = _to_df([("Error", p.get("error") or "unknown")])

    if "geo" in probes:
        p = probes["geo"]
        if p.get("success"):
            locs = p.get("data", {}).get("locations", [])
            rows = [(loc.get("ip", ""), loc.get("city", ""), loc.get("region", ""),
                     loc.get("country", ""), loc.get("org", ""), loc.get("timezone", ""))
                    for loc in locs]
            frames["geo"] = pd.DataFrame(rows, columns=["IP", "City", "Region", "Country", "Org/ASN", "Timezone"])
        else:
            frames["geo"] = _to_df([("Error", p.get("error") or "unknown")])

    if "ssl_labs" in probes and probes["ssl_labs"].get("success"):
        d = probes["ssl_labs"].get("data", {})
        frames["ssl_labs"] = _to_df([
            ("Grade", str(d.get("grade", ""))),
            ("IP", str(d.get("ip", ""))),
            ("Protocols", ", ".join(d.get("protocols", []) or [])),
            ("Key Exchange", str(d.get("key_exchange", ""))),
            ("Forward Secrecy", str(d.get("forward_secrecy", ""))),
            ("Heartbleed", str(d.get("heartbleed", ""))),
            ("POODLE", str(d.get("poodle", ""))),
        ])

    return frames
