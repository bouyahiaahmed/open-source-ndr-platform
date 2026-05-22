from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_METRIC_RE = re.compile(r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+(?P<value>[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)')
_LABEL_RE = re.compile(r'(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>(?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class Sample:
    name: str
    labels: dict[str, str]
    value: float

    @property
    def key(self) -> str:
        label_str = ",".join(f"{k}={v}" for k, v in sorted(self.labels.items()))
        return f"{self.name}{{{label_str}}}"


def parse_prometheus(text: str) -> list[Sample]:
    samples: list[Sample] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _METRIC_RE.match(line)
        if not match:
            continue
        labels: dict[str, str] = {}
        raw_labels = match.group("labels") or ""
        for label_match in _LABEL_RE.finditer(raw_labels):
            labels[label_match.group("key")] = label_match.group("value").replace('\\"', '"')
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        samples.append(Sample(name=match.group("name"), labels=labels, value=value))
    return samples


def sum_matching(samples: Iterable[Sample], name_contains: list[str] | None = None, label_contains: dict[str, str] | None = None) -> float:
    total = 0.0
    for sample in samples:
        if name_contains and not any(part.lower() in sample.name.lower() for part in name_contains):
            continue
        if label_contains:
            ok = True
            for key, value in label_contains.items():
                if value.lower() not in sample.labels.get(key, "").lower():
                    ok = False
                    break
            if not ok:
                continue
        total += sample.value
    return total


def top_samples(samples: Iterable[Sample], name_contains: list[str], limit: int = 10) -> list[dict[str, object]]:
    chosen = [s for s in samples if any(part.lower() in s.name.lower() for part in name_contains)]
    chosen.sort(key=lambda s: abs(s.value), reverse=True)
    return [{"name": s.name, "labels": s.labels, "value": s.value} for s in chosen[:limit]]
