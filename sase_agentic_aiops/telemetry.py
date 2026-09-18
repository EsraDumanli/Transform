"""
Synthetic SASE telemetry generators.

Three independent generators, sharing one pool of user ids, so a single
"anomalous" user can show up in more than one detector's output -- which is
exactly the situation the correlator is built to combine into one incident.

Nothing here talks to a real SASE platform. It exists so the rest of the
pipeline (detectors -> correlator -> agent -> gate -> action) has realistic
looking, reproducible data to run on.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

USERS = [f"user_{i:03d}" for i in range(1, 41)]

# Users deliberately seeded with anomalous behavior, so the pipeline has
# something real to find. Everyone else behaves like ordinary noise.
PLANTED_EXFIL_USER = "user_007"        # single-event: impossible travel + huge upload
PLANTED_PEER_OUTLIER_USER = "user_022" # aggregate profile: many devices, off-hours heavy
PLANTED_DRIFT_USER = "user_015"        # time-series: usage ramps up over the month

DEVICES = ["laptop-a1", "laptop-b2", "mobile-c3", "tablet-d4", "laptop-e5"]
GEOS = ["San Jose, US", "Redwood City, US", "Austin, US", "Toronto, CA", "Dublin, IE"]


@dataclass
class AccessEvent:
    ts: datetime
    user: str
    device_id: str
    src_ip: str
    geo: str
    geo_velocity_kmh: float
    bytes_sent: float
    bytes_recv: float
    hour_of_day: int
    policy_verdict: str


def _rand_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def generate_access_events(events_per_user: int = 12, seed: int = 7) -> list[AccessEvent]:
    """Event-level telemetry: what Isolation Forest scores.

    Normal events cluster in a plausible range for bytes/velocity/hour.
    user_007 gets one event with an impossible geo_velocity and a huge
    bytes_sent -- a single-event anomaly an outlier-scoring model should
    catch on its own, no history required.
    """
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    events: list[AccessEvent] = []

    for user in USERS:
        for i in range(events_per_user):
            ts = now - timedelta(hours=rng.uniform(0, 24 * 7))
            device = rng.choice(DEVICES)
            geo = rng.choice(GEOS)
            hour = ts.hour
            bytes_sent = max(0.0, rng.gauss(4_000_000, 1_200_000))
            bytes_recv = max(0.0, rng.gauss(9_000_000, 2_000_000))
            geo_velocity = abs(rng.gauss(20, 15))  # plausible ground/air travel noise
            verdict = "allow"
            events.append(AccessEvent(ts, user, device, _rand_ip(rng), geo, geo_velocity,
                                       bytes_sent, bytes_recv, hour, verdict))

    # Plant the exfil-shaped event: two logins an hour apart, continents apart,
    # plus an upload two orders of magnitude above baseline.
    exfil_ts = now - timedelta(hours=2)
    events.append(AccessEvent(
        ts=exfil_ts, user=PLANTED_EXFIL_USER, device_id="laptop-unknown-f9",
        src_ip=_rand_ip(rng), geo="Lagos, NG", geo_velocity_kmh=9200.0,
        bytes_sent=411_000_000, bytes_recv=2_100_000, hour_of_day=exfil_ts.hour,
        policy_verdict="allow",
    ))
    return events


def generate_daily_usage_series(days: int = 30, seed: int = 11) -> dict[str, list[float]]:
    """Per-user daily aggregate bytes, for the time-series baseline detector.

    Everyone gets a flat-ish 30-day series. user_015 gets a slow ramp that
    only looks wrong once you compare the last few days to the first
    twenty-five -- the case a single-point outlier check would miss and a
    rolling baseline should catch.
    """
    rng = random.Random(seed)
    series: dict[str, list[float]] = {}
    for user in USERS:
        base = rng.uniform(2_500_000, 6_000_000)
        vals = [max(0.0, rng.gauss(base, base * 0.08)) for _ in range(days)]
        if user == PLANTED_DRIFT_USER:
            for d in range(days - 6, days):
                ramp = 1.0 + 0.35 * (d - (days - 6) + 1)
                vals[d] = base * ramp
        series[user] = vals
    return series


@dataclass
class UserProfile:
    user: str
    avg_bytes: float
    max_geo_velocity: float
    distinct_devices: int
    off_hours_ratio: float


def build_user_profiles(events: list[AccessEvent]) -> list[UserProfile]:
    """Aggregate event-level telemetry into one feature vector per user,
    for the DBSCAN peer-clustering detector. user_022 is nudged toward a
    profile that looks nothing like its peers: many devices, mostly
    off-hours, without any single event extreme enough for Isolation
    Forest to flag on its own -- the case peer comparison is for.
    """
    by_user: dict[str, list[AccessEvent]] = {}
    for e in events:
        by_user.setdefault(e.user, []).append(e)

    profiles = []
    for user, evs in by_user.items():
        avg_bytes = sum(e.bytes_sent for e in evs) / len(evs)
        max_vel = max(e.geo_velocity_kmh for e in evs)
        distinct_devices = len({e.device_id for e in evs})
        off_hours = sum(1 for e in evs if e.hour_of_day < 6 or e.hour_of_day > 22) / len(evs)

        if user == PLANTED_PEER_OUTLIER_USER:
            distinct_devices = max(distinct_devices, 5)
            off_hours = 0.85

        profiles.append(UserProfile(user, avg_bytes, max_vel, distinct_devices, off_hours))
    return profiles
