from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    source: str
    instance: str = "cluster"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Result:
    component: str
    version: str
    dependency: str
    dependency_version: str
    status: str
    reason: str
    rule: str
    evidence: str
    instance: str = "cluster"
    evidence_status: str = "unknown"
    evidence_retrieved_at: str = ""
    evidence_checksum: str = ""
    evidence_provider: str = ""
    evidence_title: str = ""
    evidence_basis: str = ""
    evidence_confidence: str = ""
    evidence_verified_at: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ProviderState:
    name: str
    source_url: str
    status: str
    retrieved_at: str = ""
    checksum: str = ""
    age_seconds: float = 0
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
