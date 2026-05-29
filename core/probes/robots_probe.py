import re
import time

import httpx

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


def _parse_robots(text: str) -> tuple[list[str], list[str], list[str]]:
    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []

    in_wildcard_agent = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        lower = line.lower()
        if lower.startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip()
            in_wildcard_agent = agent == "*"
        elif lower.startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)
        elif in_wildcard_agent and lower.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif in_wildcard_agent and lower.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                allowed.append(path)

    return disallowed, allowed, sitemaps


class RobotsProbe(BaseProbe):
    name = "robots"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                robots_url = f"https://{domain}/robots.txt"
                resp = await client.get(robots_url)

                if resp.status_code == 200:
                    robots_text = resp.text
                    disallowed, allowed, sitemaps = _parse_robots(robots_text)
                    robots_exists = True
                else:
                    robots_text = ""
                    disallowed, allowed, sitemaps = [], [], []
                    robots_exists = False

                sitemap_exists = False
                sitemap_checked_url = f"https://{domain}/sitemap.xml"
                if not sitemaps:
                    try:
                        sm_resp = await client.head(sitemap_checked_url)
                        sitemap_exists = sm_resp.status_code == 200
                        if sitemap_exists:
                            sitemaps = [sitemap_checked_url]
                    except Exception:
                        pass
                else:
                    try:
                        sm_resp = await client.head(sitemaps[0])
                        sitemap_exists = sm_resp.status_code == 200
                    except Exception:
                        sitemap_exists = True

                return ProbeResult(
                    name=self.name,
                    success=True,
                    data={
                        "robots_exists": robots_exists,
                        "disallowed": disallowed,
                        "allowed": allowed,
                        "sitemap_urls": sitemaps,
                        "sitemap_exists": sitemap_exists,
                    },
                    duration_ms=(time.monotonic() - start) * 1000,
                )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
