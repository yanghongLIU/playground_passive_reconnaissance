import asyncio
import re
import time

import httpx
from bs4 import BeautifulSoup

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe

_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", r"nginx", "Nginx", "Web Server"),
    ("server", r"apache", "Apache", "Web Server"),
    ("server", r"lighttpd", "Lighttpd", "Web Server"),
    ("server", r"iis", "IIS", "Web Server"),
    ("server", r"cloudflare", "Cloudflare", "CDN"),
    ("server", r"AmazonS3", "Amazon S3", "Hosting"),
    ("server", r"openresty", "OpenResty", "Web Server"),
    ("x-powered-by", r"php", "PHP", "Programming Language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"),
    ("x-powered-by", r"express", "Express", "Framework"),
    ("x-powered-by", r"next\.js", "Next.js", "Framework"),
    ("x-generator", r"wordpress", "WordPress", "CMS"),
    ("x-generator", r"drupal", "Drupal", "CMS"),
    ("x-generator", r"joomla", "Joomla", "CMS"),
    ("via", r"varnish", "Varnish", "Cache"),
    ("via", r"squid", "Squid", "Cache"),
    ("x-cache", r".", "Caching Layer", "Cache"),
    ("cf-ray", r".", "Cloudflare", "CDN"),
    ("x-amz-cf-id", r".", "Amazon CloudFront", "CDN"),
    ("x-fastly-request-id", r".", "Fastly", "CDN"),
    ("x-akamai-transformed", r".", "Akamai", "CDN"),
]

_HTML_SIGNATURES: list[tuple[str, str, str]] = [
    (r"wp-content|wp-includes", "WordPress", "CMS"),
    (r"/sites/default/files|drupal\.js", "Drupal", "CMS"),
    (r"Joomla!", "Joomla", "CMS"),
    (r"cdn\.shopify\.com|Shopify", "Shopify", "E-commerce"),
    (r"squarespace\.com", "Squarespace", "CMS"),
    (r"wixstatic\.com|wix\.com", "Wix", "CMS"),
    (r"__NEXT_DATA__|_next/static", "Next.js", "Framework"),
    (r"__nuxt__|nuxtjs\.org", "Nuxt.js", "Framework"),
    (r"react\.development\.js|react\.production\.min\.js|React\.createElement", "React", "JavaScript Framework"),
    (r"vue\.min\.js|Vue\.component|new Vue\(", "Vue.js", "JavaScript Framework"),
    (r"angular\.min\.js|ng-version|ng-app", "Angular", "JavaScript Framework"),
    (r"jquery\.min\.js|jquery-\d", "jQuery", "JavaScript Library"),
    (r"bootstrap\.min\.css|bootstrap\.bundle", "Bootstrap", "CSS Framework"),
    (r"gtag\(|google-analytics\.com|GA_MEASUREMENT_ID", "Google Analytics", "Analytics"),
    (r"gtm\.js|googletagmanager\.com", "Google Tag Manager", "Analytics"),
]


def _fingerprint_from_headers(headers: dict) -> list[dict]:
    lowered = {k.lower(): v for k, v in headers.items()}
    found: dict[str, dict] = {}
    for header_key, pattern, tech_name, category in _HEADER_SIGNATURES:
        value = lowered.get(header_key, "")
        if value and re.search(pattern, value, re.IGNORECASE):
            if tech_name not in found:
                found[tech_name] = {"name": tech_name, "category": category, "source": f"header:{header_key}"}
    return list(found.values())


def _fingerprint_from_html(html: str) -> list[dict]:
    found: dict[str, dict] = {}
    for pattern, tech_name, category in _HTML_SIGNATURES:
        if re.search(pattern, html, re.IGNORECASE):
            if tech_name not in found:
                found[tech_name] = {"name": tech_name, "category": category, "source": "html"}
    return list(found.values())


async def _detect_technologies(domain: str, timeout: float) -> list[dict]:
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
            timeout=timeout,
        ) as client:
            resp = await client.get(f"https://{domain}")
            headers = dict(resp.headers)
            html = resp.text
    except Exception:
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                resp = await client.get(f"http://{domain}")
                headers = dict(resp.headers)
                html = resp.text
        except Exception:
            return []

    techs_from_headers = _fingerprint_from_headers(headers)
    techs_from_html = _fingerprint_from_html(html)

    merged: dict[str, dict] = {}
    for t in techs_from_headers + techs_from_html:
        if t["name"] not in merged:
            merged[t["name"]] = t

    return list(merged.values())


class TechProbe(BaseProbe):
    name = "tech"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            technologies = await _detect_technologies(domain, timeout)
            return ProbeResult(
                name=self.name,
                success=True,
                data={"technologies": technologies},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
