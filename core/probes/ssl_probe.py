import asyncio
import hashlib
import ssl
import time
from datetime import datetime, timezone

import certifi
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from network.recon.models import ProbeResult
from network.recon.probes.base import BaseProbe


def _get_cn(name: x509.Name) -> str | None:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return None


def _get_o(name: x509.Name) -> str | None:
    try:
        return name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except (IndexError, Exception):
        return None


def _parse_cert(der_bytes: bytes, tls_version: str) -> dict:
    cert = x509.load_der_x509_certificate(der_bytes)

    now = datetime.now(timezone.utc)
    valid_to = cert.not_valid_after_utc
    days_until_expiry = (valid_to - now).days

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    sha256_fp = hashlib.sha256(der_bytes).hexdigest()
    sha256_fp_colon = ":".join(sha256_fp[i:i+2].upper() for i in range(0, len(sha256_fp), 2))

    sig_algo = cert.signature_algorithm_oid.dotted_string
    try:
        sig_algo = cert.signature_hash_algorithm.name.upper() + "with" + cert.public_key().__class__.__name__.replace("RSAPublicKey", "RSA").replace("EllipticCurvePublicKey", "ECDSA").replace("DSAPublicKey", "DSA")
    except Exception:
        pass

    return {
        "issuer_cn": _get_cn(cert.issuer),
        "issuer_o": _get_o(cert.issuer),
        "subject_cn": _get_cn(cert.subject),
        "sans": list(sans),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": valid_to.isoformat(),
        "days_until_expiry": days_until_expiry,
        "serial_number": str(cert.serial_number),
        "signature_algorithm": sig_algo,
        "sha256_fingerprint": sha256_fp_colon,
        "tls_version": tls_version,
    }


class SslProbe(BaseProbe):
    name = "ssl"

    async def run(self, domain: str, timeout: float) -> ProbeResult:
        start = time.monotonic()
        try:
            ctx = ssl.create_default_context(cafile=certifi.where())
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=ctx),
                timeout=timeout,
            )
            ssl_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
            tls_version = ssl_obj.version() or "unknown"
            der_bytes = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            data = _parse_cert(der_bytes, tls_version)
            return ProbeResult(
                name=self.name,
                success=True,
                data=data,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except asyncio.TimeoutError:
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
