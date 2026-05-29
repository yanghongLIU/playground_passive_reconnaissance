import asyncio
import time

from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe

_PORTS = [80, 443, 8080, 8443]
_PORT_TIMEOUT = 3.0


async def _check_port(host: str, port: int) -> dict:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_PORT_TIMEOUT,
        )
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"port": port, "state": "open", "latency_ms": latency_ms}
    except asyncio.TimeoutError:
        return {"port": port, "state": "filtered", "latency_ms": None}
    except (ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed", "latency_ms": None}


class PortProbe(BaseProbe):
    name = "ports"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            results = await asyncio.gather(*[_check_port(domain, p) for p in _PORTS])
            return ProbeResult(
                name=self.name,
                success=True,
                data={"ports": list(results)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ProbeResult(
                name=self.name,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
