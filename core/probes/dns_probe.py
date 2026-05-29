import asyncio
import time

import dns.asyncresolver
import dns.exception

from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(domain, rtype)
        return [r.to_text() for r in answer]
    except (dns.exception.DNSException, Exception):
        return []


async def _ptr_for_a_records(resolver: dns.asyncresolver.Resolver, a_records: list[str]) -> list[str]:
    results = []
    for ip in a_records:
        try:
            rev = dns.reversename.from_address(ip)
            answer = await resolver.resolve(rev, "PTR")
            results.extend(r.to_text() for r in answer)
        except Exception:
            pass
    return results


class DnsProbe(BaseProbe):
    name = "dns"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            tasks = [_query(resolver, domain, rtype) for rtype in _RECORD_TYPES]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

            data: dict[str, list[str]] = {}
            for rtype, result in zip(_RECORD_TYPES, raw_results):
                data[rtype] = result if isinstance(result, list) else []

            ptr_records = await _ptr_for_a_records(resolver, data.get("A", []))
            data["PTR"] = ptr_records

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
