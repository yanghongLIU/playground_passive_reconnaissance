import time

import httpx

from network.recon.config import USER_AGENT, DEFAULT_TIMEOUT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


async def _fetch(domain: str, timeout: float) -> dict:
    headers = {"User-Agent": USER_AGENT}
    redirect_chain: list[str] = []

    async with httpx.AsyncClient(
        headers=headers,
        follow_redirects=True,
        timeout=timeout,
    ) as client:
        try:
            t0 = time.monotonic()
            resp = await client.get(f"https://{domain}")
            elapsed_ms = (time.monotonic() - t0) * 1000
            protocol = "https"
        except Exception:
            t0 = time.monotonic()
            resp = await client.get(f"http://{domain}")
            elapsed_ms = (time.monotonic() - t0) * 1000
            protocol = "http"

        for h in resp.history:
            redirect_chain.append(str(h.url))

        response_headers = dict(resp.headers)
        return {
            "protocol_used": protocol,
            "final_url": str(resp.url),
            "status_code": resp.status_code,
            "response_time_ms": round(elapsed_ms, 1),
            "redirect_chain": redirect_chain,
            "headers": response_headers,
            "server": resp.headers.get("server", ""),
            "content_type": resp.headers.get("content-type", ""),
            "x_powered_by": resp.headers.get("x-powered-by", ""),
        }


class HttpProbe(BaseProbe):
    name = "http"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            data = await _fetch(domain, timeout)
            return ProbeResult(
                name=self.name,
                success=True,
                data=data,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
