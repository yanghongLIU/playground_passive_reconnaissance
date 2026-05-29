from abc import ABC, abstractmethod

from network.recon.models import ProbeResult


class BaseProbe(ABC):
    name: str = ""

    @abstractmethod
    async def run(self, domain: str, timeout: float) -> ProbeResult:
        ...
