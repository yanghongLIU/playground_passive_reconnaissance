import asyncio
import time

import whois

from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


def _serialize(value) -> str | list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value)


def _run_whois(domain: str) -> dict:
    w = whois.whois(domain)
    return {
        "registrar": _serialize(w.registrar),
        "creation_date": _serialize(w.creation_date),
        "updated_date": _serialize(w.updated_date),
        "expiration_date": _serialize(w.expiration_date),
        "name_servers": _serialize(w.name_servers),
        "org": _serialize(w.org),
        "country": _serialize(w.country),
        "status": _serialize(w.status),
    }


class WhoisProbe(BaseProbe):
    name = "whois"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_run_whois, domain),
                timeout=timeout,
            )
            return ProbeResult(
                name=self.name,
                success=True,
                data=data,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except TimeoutError:
            return ProbeResult(
                name=self.name,
                success=False,
                error="timeout",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
