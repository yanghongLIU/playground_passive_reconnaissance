import json
import os
import time
from pathlib import Path

from network.recon.config import CACHE_DIR

_TTL: dict[str, float] = {
    "whois": 86400.0,
    "geo": 86400.0,
    "ssl_labs": 21600.0,
}
_DEFAULT_TTL = 3600.0


def _domain_dir(domain: str) -> Path:
    safe = domain.replace("..", "_").replace("/", "_").replace("\\", "_")
    return CACHE_DIR / safe


def _cache_path(probe_name: str, domain: str) -> Path:
    return _domain_dir(domain) / f"{probe_name}.json"


def _ttl(probe_name: str) -> float:
    return _TTL.get(probe_name, _DEFAULT_TTL)


def get(probe_name: str, domain: str) -> dict | None:
    path = _cache_path(probe_name, domain)
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > _ttl(probe_name):
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def set(probe_name: str, domain: str, data: dict) -> None:
    path = _cache_path(probe_name, domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
    os.replace(tmp, path)


def is_cached(probe_name: str, domain: str) -> bool:
    return get(probe_name, domain) is not None


def clear(domain: str | None = None) -> None:
    if domain is None:
        target = CACHE_DIR
    else:
        target = _domain_dir(domain)
    if not target.exists():
        return
    for f in target.rglob("*.json"):
        try:
            f.unlink()
        except OSError:
            pass
    for d in sorted(target.rglob("*"), reverse=True):
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass
    if domain is None:
        try:
            target.rmdir()
        except OSError:
            pass
