"""Four detectors for the abuse patterns that actually hit game platforms.

Each returns a list of `Signal` objects. Detectors never decide guilt on their
own - they contribute weighted evidence, and `triage.py` combines them. That
separation matters because almost every individual signal has a legitimate
explanation, and a system that bans on one signal bans real players.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .events import LOGIN_FAIL, LOGIN_SUCCESS, SESSION_START, Event
from .geo import haversine_km, implied_speed_kmh
from .graph import UnionFind


@dataclass
class Signal:
    kind: str
    subject: str            # account id, or "ip:x.x.x.x" for infrastructure findings
    weight: int
    description: str
    evidence: Dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# 1. Credential stuffing
# --------------------------------------------------------------------------
def detect_credential_stuffing(
    events: List[Event],
    window_s: int = 900,
    min_accounts: int = 8,
    min_fail_ratio: float = 0.7,
) -> List[Signal]:
    """Find source IPs replaying breached credential lists.

    The tell is not volume on its own - a busy CGNAT egress is high volume too.
    It is many *distinct* accounts inside a short window with a failure ratio
    far above the platform baseline, because the attacker is guessing.
    """
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.event_type in (LOGIN_SUCCESS, LOGIN_FAIL):
            by_ip[event.ip].append(event)

    signals: List[Signal] = []
    for ip, bucket in by_ip.items():
        bucket.sort(key=lambda e: e.ts)
        counts: Counter = Counter()
        left = fails = 0
        attack_start = attack_end = None
        targeted: set = set()
        peak_accounts = 0
        peak_ratio = 0.0

        for right, event in enumerate(bucket):
            counts[event.account_id] += 1
            fails += 1 if event.event_type == LOGIN_FAIL else 0
            while bucket[right].ts - bucket[left].ts > window_s:
                leaving = bucket[left]
                counts[leaving.account_id] -= 1
                if counts[leaving.account_id] == 0:
                    del counts[leaving.account_id]
                fails -= 1 if leaving.event_type == LOGIN_FAIL else 0
                left += 1

            total = right - left + 1
            ratio = fails / total if total else 0.0
            if len(counts) >= min_accounts and ratio >= min_fail_ratio:
                attack_start = bucket[left].ts if attack_start is None else attack_start
                attack_end = bucket[right].ts
                targeted.update(counts)
                peak_accounts = max(peak_accounts, len(counts))
                peak_ratio = max(peak_ratio, ratio)

        if attack_start is None:
            continue

        signals.append(Signal(
            kind="credential_stuffing_source",
            subject=f"ip:{ip}",
            weight=0,   # infrastructure finding, not an account score
            description=(
                f"{peak_accounts} distinct accounts targeted from {ip} within "
                f"{window_s // 60}min, peak failure ratio {peak_ratio:.0%}"
            ),
            evidence={
                "ip": ip,
                "peak_distinct_accounts": peak_accounts,
                "peak_failure_ratio": round(peak_ratio, 3),
                "window_start": attack_start,
                "window_end": attack_end,
                "accounts_targeted": len(targeted),
            },
        ))

        # Any success from an attacking IP during the attack is a probable
        # account takeover: the attacker guessed right.
        for event in bucket:
            if (event.event_type == LOGIN_SUCCESS
                    and attack_start <= event.ts <= attack_end):
                signals.append(Signal(
                    kind="suspected_account_takeover",
                    subject=event.account_id,
                    weight=34,
                    description=f"Successful login from credential-stuffing source {ip}",
                    evidence={"ip": ip, "ts": event.ts},
                ))
    return signals


# --------------------------------------------------------------------------
# 2. Impossible travel
# --------------------------------------------------------------------------
def detect_impossible_travel(
    events: List[Event],
    max_kmh: float = 900.0,
    min_km: float = 500.0,
) -> List[Signal]:
    """Consecutive successful logins that no aircraft could connect.

    `max_kmh` sits above commercial cruise speed on purpose. Flagging a real
    passenger who flew Manila to Singapore is a support ticket and an annoyed
    player, so the threshold buys headroom rather than catching every hop.
    `min_km` suppresses the noise from coarse city-level IP geolocation, which
    routinely misplaces an address by tens of kilometres.
    """
    by_account: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == LOGIN_SUCCESS:
            by_account[event.account_id].append(event)

    signals: List[Signal] = []
    for account, logins in by_account.items():
        logins.sort(key=lambda e: e.ts)
        for previous, current in zip(logins, logins[1:]):
            distance = haversine_km(previous.lat, previous.lon, current.lat, current.lon)
            if distance < min_km:
                continue
            speed = implied_speed_kmh(distance, current.ts - previous.ts)
            if speed <= max_kmh:
                continue
            signals.append(Signal(
                kind="impossible_travel",
                subject=account,
                weight=30,
                description=(
                    f"{previous.city} to {current.city}: {distance:,.0f}km in "
                    f"{(current.ts - previous.ts) / 3600:.1f}h "
                    f"({'instant' if speed == float('inf') else f'{speed:,.0f}km/h'})"
                ),
                evidence={
                    "from": previous.city, "to": current.city,
                    "distance_km": round(distance, 1),
                    "hours": round((current.ts - previous.ts) / 3600, 2),
                    "implied_kmh": None if speed == float("inf") else round(speed, 1),
                },
            ))
    return signals


# --------------------------------------------------------------------------
# 3. Shared-infrastructure clustering
# --------------------------------------------------------------------------
def link_accounts(
    events: List[Event],
    min_cluster_accounts: int = 3,
    ip_fanout_limit: int = 12,
    device_fanout_limit: int = 25,
    exclude_ips: Optional[Set[str]] = None,
) -> List[Signal]:
    """Cluster accounts that share devices or narrow IPs.

    Two guards, both learned from the output being wrong first.

    IPs are weak links: carrier-grade NAT, campus networks and internet cafes
    put hundreds of unrelated players behind one address, so an IP only creates
    edges while its fanout stays under `ip_fanout_limit`.

    Device identifiers are strong links, but they are *client-reported*, so an
    attacker replaying credentials from one machine stamps their own device ID
    onto every account they touch. The first version of this function linked
    unconditionally on device and returned a single 110-account cluster that
    was really one attacker plus their victims. Two changes fixed it: only
    successful authentications create edges (a failed login proves nothing
    about the account), and devices get a fanout ceiling of their own. Sources
    already confirmed as attacking infrastructure are excluded outright via
    `exclude_ips`, which the pipeline fills from the stuffing detector.
    """
    exclude_ips = exclude_ips or set()
    # Sessions originating from a confirmed attacking source are the attacker's
    # infrastructure, not the account holder's. Linking through them would put
    # every victim of one stuffing run into a single "cluster" and get a group
    # of compromised players actioned as if they were an offender ring.
    linkable = [
        e for e in events
        if e.event_type in (LOGIN_SUCCESS, SESSION_START) and e.ip not in exclude_ips
    ]

    ip_fanout: Dict[str, set] = defaultdict(set)
    device_fanout: Dict[str, set] = defaultdict(set)
    for event in linkable:
        ip_fanout[event.ip].add(event.account_id)
        device_fanout[event.device_id].add(event.account_id)

    uf = UnionFind()
    for event in linkable:
        account_node = ("acct", event.account_id)
        uf.add(account_node)
        if len(device_fanout[event.device_id]) <= device_fanout_limit:
            uf.union(account_node, ("dev", event.device_id))
        if len(ip_fanout[event.ip]) <= ip_fanout_limit:
            uf.union(account_node, ("ip", event.ip))

    signals: List[Signal] = []
    for root, members in uf.components().items():
        accounts = sorted(node[1] for node in members if node[0] == "acct")
        if len(accounts) < min_cluster_accounts:
            continue
        devices = sorted(node[1] for node in members if node[0] == "dev")
        bonus = min((len(accounts) - min_cluster_accounts) * 3, 12)
        for account in accounts:
            signals.append(Signal(
                kind="shared_infrastructure_cluster",
                subject=account,
                weight=26 + bonus,
                description=(
                    f"Linked to {len(accounts) - 1} other accounts across "
                    f"{len(devices)} shared device identifier(s)"
                ),
                evidence={
                    "cluster_size": len(accounts),
                    "devices": devices[:5],
                    "peers": [a for a in accounts if a != account][:10],
                },
            ))
    return signals


# --------------------------------------------------------------------------
# 4. Automation / farming behaviour
# --------------------------------------------------------------------------
def detect_automation(
    events: List[Event],
    min_sessions: int = 12,
    max_interval_cv: float = 0.15,
    min_hours_covered: int = 20,
) -> List[Signal]:
    """Behavioural tells of a script rather than a person.

    Humans are irregular. A scheduler is not: it starts sessions on a near
    constant interval, so the coefficient of variation of the gaps collapses.
    Separately, a single human account active in 20+ distinct hours of the day
    across the sample is either shared or automated.
    """
    by_account: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == SESSION_START:
            by_account[event.account_id].append(event)

    signals: List[Signal] = []
    for account, sessions in by_account.items():
        if len(sessions) < min_sessions:
            continue
        sessions.sort(key=lambda e: e.ts)
        gaps = [b.ts - a.ts for a, b in zip(sessions, sessions[1:]) if b.ts > a.ts]
        if len(gaps) >= 3:
            mean_gap = statistics.fmean(gaps)
            cv = statistics.pstdev(gaps) / mean_gap if mean_gap else 0.0
            if cv < max_interval_cv:
                signals.append(Signal(
                    kind="metronomic_sessions",
                    subject=account,
                    weight=30,
                    description=(
                        f"{len(sessions)} sessions on a {mean_gap / 3600:.1f}h interval "
                        f"with variation of only {cv:.1%}"
                    ),
                    evidence={"sessions": len(sessions),
                              "mean_gap_hours": round(mean_gap / 3600, 2),
                              "interval_cv": round(cv, 4)},
                ))

        import time as _t
        hours = {_t.gmtime(e.ts).tm_hour for e in sessions}
        if len(hours) >= min_hours_covered:
            signals.append(Signal(
                kind="round_the_clock_activity",
                subject=account,
                weight=20,
                description=f"Sessions started in {len(hours)} of 24 hours of the day",
                evidence={"distinct_hours": len(hours), "sessions": len(sessions)},
            ))
    return signals
