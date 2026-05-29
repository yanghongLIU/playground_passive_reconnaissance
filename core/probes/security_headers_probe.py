import time

import httpx

from network.recon.config import USER_AGENT
from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe

_HEADERS_CONFIG = [
    ("Strict-Transport-Security", 20),
    ("Content-Security-Policy", 20),
    ("X-Frame-Options", 15),
    ("X-Content-Type-Options", 15),
    ("Referrer-Policy", 10),
    ("Permissions-Policy", 10),
    ("X-XSS-Protection", 5),
]


def _grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def _check_hsts(value: str) -> bool:
    if not value:
        return False
    for part in value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                age = int(part.split("=", 1)[1].strip())
                return age >= 31536000
            except ValueError:
                return False
    return False


def _check_xcto(value: str) -> bool:
    return value.strip().lower() == "nosniff"


def _analyze_headers(response_headers: dict) -> dict:
    lowered = {k.lower(): v for k, v in response_headers.items()}
    score = 0
    header_results = {}

    for header_name, weight in _HEADERS_CONFIG:
        value = lowered.get(header_name.lower(), "")
        if header_name == "Strict-Transport-Security":
            present = _check_hsts(value)
        elif header_name == "X-Content-Type-Options":
            present = _check_xcto(value)
        else:
            present = bool(value)

        if present:
            score += weight
        header_results[header_name] = {
            "present": present,
            "value": value,
            "weight": weight,
        }

    return {
        "headers": header_results,
        "score": score,
        "grade": _grade(score),
    }


class SecurityHeadersProbe(BaseProbe):
    name = "security_headers"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                resp = await client.head(f"https://{domain}")
                data = _analyze_headers(dict(resp.headers))
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
