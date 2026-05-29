# recon — Passive Reconnaissance Tool

A personal hobby project by **Yanghong Liu**. Built for fun and learning — not a production security product.

Given any domain or URL, it gathers publicly available information in parallel and renders a clean terminal report.

---

## What it does

Runs 13 passive probes concurrently — **no API keys, no paid services, no active scanning**:

| Probe | What it fetches |
|---|---|
| WHOIS | Registrar, creation/expiry dates, nameservers |
| DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records |
| SSL/TLS | Certificate issuer, SANs, validity, TLS version |
| HTTP | Headers, status code, redirect chain |
| Tech fingerprint | Server, framework, CMS, JS libraries (via Wappalyzer) |
| Security headers | HSTS, CSP, X-Frame-Options etc. → grade A–F |
| robots.txt | Disallowed paths and sitemap URLs |
| CT logs (crt.sh) | Passive subdomain enumeration via certificate transparency |
| IP geolocation | Country, city, ASN, org via ipinfo.io (anonymous) |
| Open ports | TCP connect probe on 80, 443, 8080, 8443 |
| SSL Labs (opt-in) | Full TLS grade — A+/A/B/C/F (slow, ~90–120s) |

Results are cached locally for 1 hour (`~/.cache/recon/`) so repeated runs are instant.

---

## Quick start

```bash
# install dependencies (Python 3.13+)
pip install -r requirements.txt

# run from the repo root
python -m network.core example.com
```

## Usage

```bash
# basic scan — pretty rich tables
python -m network.core example.com

# pass a full URL (domain is extracted automatically)
python -m network.core https://sv.wikipedia.org/wiki/Instabox

# specific probes only
python -m network.core example.com --probes dns,whois,ssl

# different output formats
python -m network.core example.com --format json
python -m network.core example.com --format html
python -m network.core example.com --format pandas

# include the slow SSL Labs grade
python -m network.core example.com --ssl-labs

# bypass / clear cache
python -m network.core example.com --no-cache
python -m network.core --clear-cache

# verbose logging
python -m network.core example.com -v    # INFO
python -m network.core example.com -vv   # DEBUG
```

## Use as a library

```python
from network.core import recon

result = recon("https://example.com")          # returns dict
result = recon("example.com", output="json")   # returns rendered string
```

---

## Ethics & scope

This tool is **strictly passive** — it only reads publicly available data. It does not:
- perform active port scanning, SYN scans, or OS fingerprinting
- probe for vulnerabilities or attempt exploitation
- crawl behind authentication
- use any paid API or require any credentials

Rate limiting, polite timeouts, and a self-identifying User-Agent are baked in.

---

## License

Personal project — © Yanghong Liu. Not for redistribution or commercial use.
