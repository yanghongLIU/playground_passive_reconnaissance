import asyncio
import time

from network.recon import cache
from network.recon.config import DEFAULT_TIMEOUT
from network.recon.domain_utils import extract_domain
from network.recon.models import ProbeResult
from network.recon.probes.crt_sh_probe import CrtShProbe
from network.recon.probes.dns_probe import DnsProbe
from network.recon.probes.geo_probe import GeoProbe
from network.recon.probes.http_probe import HttpProbe
from network.recon.probes.port_probe import PortProbe
from network.recon.probes.robots_probe import RobotsProbe
from network.recon.probes.security_headers_probe import SecurityHeadersProbe
from network.recon.probes.ssl_labs_probe import SslLabsProbe
from network.recon.probes.ssl_probe import SslProbe
from network.recon.probes.tech_probe import TechProbe
from network.recon.probes.whois_probe import WhoisProbe

_ALL_PROBES = {
    "whois": WhoisProbe(),
    "dns": DnsProbe(),
    "ssl": SslProbe(),
    "http": HttpProbe(),
    "security_headers": SecurityHeadersProbe(),
    "tech": TechProbe(),
    "robots": RobotsProbe(),
    "ports": PortProbe(),
    "crt_sh": CrtShProbe(),
    "geo": GeoProbe(),
}

_SSL_LABS_PROBE = SslLabsProbe()
_MAX_SSL_LABS_TIMEOUT = 180.0

_REGISTERED_DOMAIN_PROBES = {"whois", "crt_sh"}


async def _run_probe(
    name: str,
    probe,
    target: str,
    timeout: float,
    use_cache: bool,
) -> ProbeResult:
    if use_cache:
        cached_data = cache.get(name, target)
        if cached_data is not None:
            return ProbeResult(
                name=name,
                success=cached_data.get("success", True),
                data=cached_data.get("data", {}),
                error=cached_data.get("error"),
                duration_ms=cached_data.get("duration_ms", 0.0),
                cached=True,
            )

    result: ProbeResult = await probe.run(target, timeout)

    if result.success:
        cache.set(name, target, {
            "success": result.success,
            "data": result.data,
            "error": result.error,
            "duration_ms": result.duration_ms,
        })

    return result


async def recon_async(
    target: str,
    *,
    probes: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    use_cache: bool = True,
    ssl_labs: bool = False,
    clear_cache: bool = False,
) -> dict:
    if clear_cache:
        cache.clear()

    domain_info = extract_domain(target)
    registered = domain_info["registered_domain"]
    subdomain = domain_info.get("subdomain", "")
    full_host = f"{subdomain}.{registered}" if subdomain else registered

    selected = list(_ALL_PROBES.keys()) if probes is None else [p for p in probes if p in _ALL_PROBES]

    probe_names = list(selected)
    probe_coros = [
        _run_probe(
            name,
            _ALL_PROBES[name],
            registered if name in _REGISTERED_DOMAIN_PROBES else full_host,
            timeout,
            use_cache,
        )
        for name in probe_names
    ]

    if ssl_labs and (probes is None or "ssl_labs" in probes):
        probe_names.append("ssl_labs")
        probe_coros.append(
            _run_probe("ssl_labs", _SSL_LABS_PROBE, full_host, _MAX_SSL_LABS_TIMEOUT, use_cache)
        )

    start = time.monotonic()
    raw = await asyncio.gather(*probe_coros, return_exceptions=True)

    results: dict[str, ProbeResult] = {}
    cache_hit_count = 0
    for name, outcome in zip(probe_names, raw):
        if isinstance(outcome, BaseException):
            results[name] = ProbeResult(name=name, success=False, error=str(outcome))
        else:
            results[name] = outcome
            if outcome.cached:
                cache_hit_count += 1

    return {
        "domain": domain_info,
        "probes": {name: result.__dict__ for name, result in results.items()},
        "total_duration_ms": (time.monotonic() - start) * 1000,
        "probe_count": len(results),
        "cache_hits": cache_hit_count,
    }


def recon(target: str, *, output: str = "dict", **kwargs) -> dict | str:
    result = asyncio.run(recon_async(target, **kwargs))

    if output == "dict":
        return result

    if output == "rich":
        from network.recon.renderers.rich_renderer import render
        render(result)
        return result

    if output == "json":
        from network.recon.renderers.json_renderer import render
        return render(result)

    return result
