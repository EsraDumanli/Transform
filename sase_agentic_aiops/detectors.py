"""
The ML detection layer -- three small models, the same ones covered in the
anomaly-detection field guide, unchanged in role: they score, they don't
decide. Each returns a list of Flag objects; the correlator is what turns
flags into incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from telemetry import AccessEvent, UserProfile


@dataclass
class Flag:
    source: str       # "isolation_forest" | "time_series_baseline" | "peer_clustering"
    user: str
    score: float       # higher = more anomalous, roughly comparable within a source
    detail: str
    ts: datetime | None = None


def run_isolation_forest(events: list[AccessEvent], contamination: float = 0.03) -> list[Flag]:
    """Event-level outlier scoring on [bytes_sent, bytes_recv, geo_velocity, hour]."""
    X = np.array([[e.bytes_sent, e.bytes_recv, e.geo_velocity_kmh, e.hour_of_day] for e in events])
    X_scaled = StandardScaler().fit_transform(X)

    clf = IsolationForest(n_estimators=150, contamination=contamination, random_state=7)
    clf.fit(X_scaled)
    raw_scores = -clf.score_samples(X_scaled)  # higher = more anomalous
    is_outlier = clf.predict(X_scaled) == -1

    flags = []
    for event, score, outlier in zip(events, raw_scores, is_outlier):
        if outlier:
            flags.append(Flag(
                source="isolation_forest",
                user=event.user,
                score=float(score),
                detail=(f"{event.bytes_sent/1e6:.0f}MB up / {event.bytes_recv/1e6:.0f}MB down, "
                        f"geo_velocity={event.geo_velocity_kmh:.0f}km/h from {event.geo}"),
                ts=event.ts,
            ))
    return flags


def run_time_series_baseline(series: dict[str, list[float]], z_threshold: float = 3.0) -> list[Flag]:
    """Rolling baseline drift: compare the last 5 days to the prior 25.

    This is deliberately not a single-point z-score against the whole series
    mean -- a slow ramp barely moves a 30-day mean, but it moves the gap
    between "recent" and "established baseline" a lot, which is the point.
    """
    flags = []
    for user, values in series.items():
        arr = np.array(values)
        if len(arr) < 10:
            continue
        baseline, recent = arr[:-5], arr[-5:]
        mu, sigma = baseline.mean(), baseline.std() or 1.0
        recent_mean = recent.mean()
        z = (recent_mean - mu) / sigma
        if abs(z) >= z_threshold:
            flags.append(Flag(
                source="time_series_baseline",
                user=user,
                score=float(abs(z)),
                detail=(f"last 5-day avg {recent_mean/1e6:.1f}MB vs 25-day baseline "
                        f"{mu/1e6:.1f}MB (z={z:.1f})"),
            ))
    return flags


def run_peer_clustering(profiles: list[UserProfile], eps: float = 1.0, min_samples: int = 4) -> list[Flag]:
    """DBSCAN over per-user behavior vectors. Points DBSCAN can't fit into
    any dense neighborhood (label -1) are users who don't resemble their
    peers on this feature set -- flagged regardless of whether any single
    feature looks extreme."""
    X = np.array([[p.avg_bytes, p.max_geo_velocity, p.distinct_devices, p.off_hours_ratio]
                  for p in profiles])
    X_scaled = StandardScaler().fit_transform(X)

    labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(X_scaled)

    flags = []
    for profile, label in zip(profiles, labels):
        if label == -1:
            flags.append(Flag(
                source="peer_clustering",
                user=profile.user,
                score=1.0,
                detail=(f"{profile.distinct_devices} devices, "
                        f"{profile.off_hours_ratio*100:.0f}% off-hours activity "
                        f"-- doesn't fit any peer cluster"),
            ))
    return flags
