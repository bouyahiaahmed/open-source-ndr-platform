from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    CRIT = "crit"
    UNKNOWN = "unknown"


STATUS_RANK = {
    Status.OK: 0,
    Status.UNKNOWN: 1,
    Status.WARN: 2,
    Status.CRIT: 3,
}


@dataclass
class CheckResult:
    id: str
    name: str
    component: str
    status: Status
    summary: str
    details: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float | int] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ComponentSummary:
    name: str
    label: str
    status: Status
    total: int
    ok: int
    warn: int
    crit: int
    unknown: int
    score: int

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ScanSummary:
    scan_id: str
    generated_at: str
    duration_ms: float
    status: Status
    score: int
    components: list[ComponentSummary]
    checks: list[CheckResult]
    highlights: list[str] = field(default_factory=list)
    pipeline: list[dict[str, Any]] = field(default_factory=list)
    sensors: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "score": self.score,
            "components": [component.to_dict() for component in self.components],
            "checks": [check.to_dict() for check in self.checks],
            "highlights": self.highlights,
            "pipeline": self.pipeline,
            "sensors": self.sensors,
            "data": self.data,
        }


def worst_status(statuses: list[Status]) -> Status:
    if not statuses:
        return Status.UNKNOWN
    return max(statuses, key=lambda s: STATUS_RANK[s])


def score_from_checks(checks: list[CheckResult]) -> int:
    if not checks:
        return 0
    penalty = 0
    for check in checks:
        if check.status == Status.CRIT:
            penalty += 18
        elif check.status == Status.WARN:
            penalty += 7
        elif check.status == Status.UNKNOWN:
            penalty += 3
    return max(0, min(100, 100 - penalty))


def now_ms() -> float:
    return time.perf_counter() * 1000
