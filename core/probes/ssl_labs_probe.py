import asyncio
import time

import httpx

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe

_POLL_INTERVAL = 10
_MAX_WAIT = 180


class SslLabsProbe(BaseProbe):
    name = "ssl_labs"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done&ignoreMismatch=on"

        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                timeout=30.0,
                follow_redirects=True,
            ) as client:
                while True:
                    elapsed = time.monotonic() - start
                    if elapsed > _MAX_WAIT:
                        return ProbeResult(
                            name=self.name,
                            success=False,
                            error=f"SSL Labs scan timed out after {_MAX_WAIT}s",
                            duration_ms=elapsed * 1000,
                        )

                    try:
                        resp = await client.get(url)
                        resp.raise_for_status()
                        body = resp.json()
                    except httpx.HTTPStatusError as exc:
                        return ProbeResult(
                            name=self.name,
                            success=False,
                            error=f"HTTP {exc.response.status_code}",
                            duration_ms=(time.monotonic() - start) * 1000,
                        )
                    except Exception as exc:
                        return ProbeResult(
                            name=self.name,
                            success=False,
                            error=str(exc),
                            duration_ms=(time.monotonic() - start) * 1000,
                        )

                    status = body.get("status", "")
                    if status in ("DNS", "IN_PROGRESS"):
                        await asyncio.sleep(_POLL_INTERVAL)
                        continue

                    if status == "ERROR":
                        return ProbeResult(
                            name=self.name,
                            success=False,
                            error=body.get("statusMessage", "SSL Labs returned ERROR"),
                            duration_ms=(time.monotonic() - start) * 1000,
                        )

                    if status == "READY":
                        data = _parse_result(body)
                        return ProbeResult(
                            name=self.name,
                            success=True,
                            data=data,
                            duration_ms=(time.monotonic() - start) * 1000,
                        )

                    await asyncio.sleep(_POLL_INTERVAL)

        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )


def _parse_result(body: dict) -> dict:
    endpoints = body.get("endpoints", [])
    if not endpoints:
        return {"grade": "?", "endpoints": []}

    ep = endpoints[0]
    details = ep.get("details") or {}

    protocols = [
        p.get("name", "") + " " + p.get("version", "")
        for p in details.get("protocols", [])
    ]

    key_exchange = details.get("keyExchange", {})
    if isinstance(key_exchange, dict):
        kex_str = key_exchange.get("keyAlg", "") + " " + str(key_exchange.get("keySize", ""))
    else:
        kex_str = str(key_exchange)

    suite_list = []
    for suite_group in details.get("suites", []):
        if isinstance(suite_group, dict):
            for s in suite_group.get("list", []):
                suite_list.append(s.get("name", ""))

    chain_issues = details.get("certChains", [{}])[0].get("issues", 0) if details.get("certChains") else 0

    return {
        "grade": ep.get("grade", "?"),
        "grade_trust_ignored": ep.get("gradeTrustIgnored", "?"),
        "ip": ep.get("ipAddress", ""),
        "protocols": protocols,
        "key_exchange": kex_str.strip() or "—",
        "cipher_suites": suite_list[:10],
        "cert_chain_issues": chain_issues,
        "forward_secrecy": details.get("forwardSecrecy", 0),
        "heartbleed": details.get("heartbleed", False),
        "poodle": details.get("poodle", False),
    }
