"""
Correlation window: turns a pile of per-detector flags into a smaller
number of Incidents, one per entity with at least one flag. This is the
step that doesn't exist in a plain "run three models and list the alerts"
setup -- it's what lets the agent reason about one user's whole picture
instead of three unrelated alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detectors import Flag


@dataclass
class Incident:
    incident_id: str
    entity: str
    signals: list[Flag] = field(default_factory=list)

    @property
    def sources(self) -> set[str]:
        return {s.source for s in self.signals}

    @property
    def max_score(self) -> float:
        return max((s.score for s in self.signals), default=0.0)


def correlate(*flag_lists: list[Flag]) -> list[Incident]:
    """Group every flag by entity (user), regardless of which detector
    produced it. A real correlation window would also bound this by time;
    here every flag already carries roughly the same observation window,
    so entity is the whole grouping key."""
    by_entity: dict[str, Incident] = {}
    for flags in flag_lists:
        for flag in flags:
            incident = by_entity.setdefault(
                flag.user, Incident(incident_id=f"INC-{flag.user}", entity=flag.user)
            )
            incident.signals.append(flag)

    # Multi-signal incidents first -- that's the whole point of correlating.
    return sorted(by_entity.values(), key=lambda i: (len(i.sources), i.max_score), reverse=True)
