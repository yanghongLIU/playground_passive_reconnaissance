from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    name: str
    success: bool
    data: dict = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0
    cached: bool = False
