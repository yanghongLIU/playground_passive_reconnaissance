import time

import dns.asyncresolver
import dns.exception
import httpx

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


async def _resolve_a(domain: str, timeout: float) -> list[str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answer = await resolver.resolve(domain, "A")
        return [r.to_text() for r in answer]
    except Exception:
        return []


async def _lookup_ip(client: httpx.AsyncClient, ip: str) -> dict | None:
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json")
        if resp.status_code == 429:
            return {"ip": ip, "error": "rate-limited"}
        resp.raise_for_status()
        d = resp.json()
        return {
            "ip": ip,
            "hostname": d.get("hostname", ""),
            "city": d.get("city", ""),
            "region": d.get("region", ""),
            "country": d.get("country", ""),
            "org": d.get("org", ""),
            "timezone": d.get("timezone", ""),
            "loc": d.get("loc", ""),
        }
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


class GeoProbe(BaseProbe):
    name = "geo"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            ips = await _resolve_a(domain, timeout)
            if not ips:
                return ProbeResult(
                    name=self.name,
                    success=True,
                    data={"locations": []},
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                locations = []
                for ip in ips:
                    result = await _lookup_ip(client, ip)
                    if result:
                        locations.append(result)

            return ProbeResult(
                name=self.name,
                success=True,
                data={"locations": locations},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
