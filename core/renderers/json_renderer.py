import json
from datetime import date, datetime


def _default(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def render(result: dict) -> str:
    return json.dumps(result, indent=2, default=_default)
