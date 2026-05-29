# playground_passive_reconnaissance
Scope & Ethics

This tool performs **passive reconnaissance only** against publicly available data:

- WHOIS records (public registry data)
- DNS records (public)
- SSL/TLS certificate (publicly served on port 443)
- HTTP response headers (publicly served)
- Server/technology fingerprints (from public response signatures)
- robots.txt / sitemap.xml (explicitly published as public)
- Certificate Transparency logs via crt.sh (public log)
- **Light TCP connect probe** on a small set of common web ports (80, 443, 8080, 8443) — connect-only, no banner grabbing beyond what the server willingly returns, no SYN scan, no nmap

**Explicitly out of scope:**

- Active port scanning beyond the agreed common-port shortlist
- Raw SYN scanning, OS fingerprinting, or anything requiring root/raw sockets
- Vulnerability probing or exploitation
- Authentication bypass / scraping behind login
- Aggressive crawling (we respect `robots.txt` and add polite delays)
- **Any service that requires a paid API key or account** — see section 5

The tool will include rate-limiting, timeouts, a custom User-Agent that identifies the tool, and respect the standard `robots.txt` allow/disallow rules where applicable.

### Design principles
- **Each probe is an async function** returning a `ProbeResult` dataclass with `name`, `success`, `data`, `error`, `duration_ms`, `cached: bool`. One failing probe never aborts the run.
- **Orchestrator uses `asyncio.gather(..., return_exceptions=True)`** — probes run in parallel, exceptions become failed results, not crashes.
- **All probes share a common timeout** (default 10s, configurable per-probe; SSL Labs gets a 180s override).
- **Domain is always a parameter** — passed into the orchestrator, never globally configured.
- **Renderers are pluggable** — same data shape, different output. `rich` is default.
- **Cache layer** sits between the orchestrator and each probe. Cache key = `(probe_name, target, relevant_args)`. Storage: JSON files under `~/.cache/recon/` with mtime-based 1h TTL. `--no-cache` flag bypasses; `--clear-cache` purges.
- **Sync wrappers exist** for the importable API so users in non-async contexts (Jupyter, scripts) can call `recon(target)` without writing `await`.
- **Single User-Agent constant** in `config.py`: `recon-tool/0.1 (+contact: yanghong.liu@instabox.se)`. All HTTP requests must use it.


### Included probes (free, keyless)

| Service / Technique | Key needed? | What it adds | Implementation |
|---|---|---|---|
| **crt.sh** | No | Subdomains from Certificate Transparency logs | `httpx` GET against public JSON endpoint |
| **ipinfo.io** (free tier) | No | IP geolocation, ASN, org | `httpx` GET, ~1k/day anonymous limit. Cached aggressively. |
| **SSL Labs API** | No | Full TLS grade (A+/A/B...), cipher suites, vuln checks | Public API, opt-in via `--ssl-labs` flag (slow, ~90-120s per scan) |
| **Direct DNS (`dnspython`)** | No | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, PTR | Self-implemented |
| **Direct WHOIS (`python-whois`)** | No | Registrar, dates, nameservers, registrant org | Self-implemented |
| **Direct TLS (`asyncio` + `ssl` + `cryptography`)** | No | Certificate parsing — issuer, SANs, validity, fingerprint, TLS version | Self-implemented |
| **Direct HTTP (`httpx`)** | No | Headers, redirect chain, security headers grading, robots.txt, sitemap | Self-implemented |
| **TCP connect probe (`asyncio.open_connection`)** | No | Port open/closed/filtered on 80, 443, 8080, 8443 | Self-implemented |

### Dropped services (would have required paid keys) — and how we replace them

| Dropped service | Would have provided | Self-implemented replacement in this tool |
|---|---|---|
| **Shodan** | External port/service fingerprinting, banners, CVE matches | Our own `port_probe.py` using `asyncio.open_connection` against the shortlist 80/443/8080/8443. Banners limited to whatever the server volunteers in HTTP/TLS handshake. No CVE matching. |
| **SecurityTrails** | Historical DNS, richer subdomain data, WHOIS history | `crt_sh_probe.py` for subdomains (CT logs go back years — covers historical TLS-issuing subdomains) + live `dns_probe.py` for current state. No WHOIS history (registrars don't expose it without paid services — accepted gap). |
| **VirusTotal (paid tier)** | Domain reputation, passive DNS, malware flags | Not replaced. Reputation/abuse scoring is out of scope for this tool. |
| **AbuseIPDB** | IP abuse reports | Not replaced. Same — out of scope. |
| **Censys (paid)** | Host + cert dataset | Subset covered by crt.sh (certs) and our own port probe (hosts). |

No `.env` file, no `IPINFO_TOKEN`, no `SHODAN_API_KEY`, no `SECURITYTRAILS_API_KEY` — none of these will exist in the codebase. `python-dotenv` is **removed** from dependencies.

