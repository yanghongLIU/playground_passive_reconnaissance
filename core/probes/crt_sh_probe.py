import time

import httpx

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


class CrtShProbe(BaseProbe):
    name = "crt_sh"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

            try:
                entries = resp.json()
            except Exception:
                return ProbeResult(
                    name=self.name,
                    success=False,
                    error="invalid JSON response from crt.sh",
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            seen: set[str] = set()
            for entry in entries:
                raw = entry.get("name_value", "")
                for name in raw.splitlines():
                    name = name.strip().lstrip("*.")
                    if name and name != domain and "." in name:
                        seen.add(name)

            subdomains = sorted(seen)
            return ProbeResult(
                name=self.name,
                success=True,
                data={"subdomains": subdomains, "count": len(subdomains)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
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
