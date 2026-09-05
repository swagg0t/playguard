"""Combine detector signals into a ranked analyst queue.

Two separate outputs, because they need different responses:

  * `infrastructure` - attacking sources. These get rate-limited or blocked.
  * `accounts`       - accounts carrying evidence. Some are attackers, some are
                       victims, and the queue records which, so a compromised
                       player gets a password reset instead of a ban.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .detectors import (
    Signal,
    detect_automation,
    detect_credential_stuffing,
    detect_impossible_travel,
    link_accounts,
)
from .events import Event

# Signals that mean the account holder is the target, not the offender.
VICTIM_SIGNALS = {"suspected_account_takeover", "impossible_travel"}

_TIERS = [
    (70, "P1", "Suspend session tokens and escalate to a human analyst now."),
    (45, "P2", "Queue for analyst review within 24h; apply step-up auth on next login."),
    (25, "P3", "Watchlist; re-evaluate on the next batch."),
    (0,  "P4", "No action; retained for correlation only."),
]


def _tier(score: int):
    for floor, tier, action in _TIERS:
        if score >= floor:
            return tier, action
    raise AssertionError("unreachable")


def run_detectors(events: List[Event]) -> List[Signal]:
    """Run detectors in dependency order.

    Stuffing runs first because its output changes how linking should read the
    data: once an IP is confirmed as attacking infrastructure, the device and
    address it presents belong to the attacker, and clustering through them
    would group a stuffing run's victims into a fake offender ring.
    """
    stuffing = detect_credential_stuffing(events)
    attacker_ips = {
        signal.evidence["ip"] for signal in stuffing
        if signal.kind == "credential_stuffing_source"
    }
    return (
        stuffing
        + detect_impossible_travel(events)
        + link_accounts(events, exclude_ips=attacker_ips)
        + detect_automation(events)
    )


def build_queue(events: List[Event], signals: List[Signal] = None) -> Dict:
    signals = run_detectors(events) if signals is None else signals

    infrastructure = [s for s in signals if s.subject.startswith("ip:")]
    per_account: Dict[str, List[Signal]] = defaultdict(list)
    for signal in signals:
        if not signal.subject.startswith("ip:"):
            per_account[signal.subject].append(signal)

    rows = []
    for account, account_signals in per_account.items():
        score = min(sum(s.weight for s in account_signals), 100)
        tier, action = _tier(score)
        kinds = {s.kind for s in account_signals}
        classification = (
            "compromised_account" if kinds & VICTIM_SIGNALS and not (kinds - VICTIM_SIGNALS)
            else "abusive_account" if kinds - VICTIM_SIGNALS
            else "unclassified"
        )
        rows.append({
            "account_id": account,
            "risk_score": score,
            "tier": tier,
            "classification": classification,
            "recommended_action": (
                "Force credential reset and notify the player; do not ban."
                if classification == "compromised_account" else action
            ),
            "signals": [
                {"kind": s.kind, "weight": s.weight, "detail": s.description, "evidence": s.evidence}
                for s in sorted(account_signals, key=lambda s: -s.weight)
            ],
        })

    rows.sort(key=lambda r: (-r["risk_score"], r["account_id"]))
    return {
        "accounts": rows,
        "infrastructure": [
            {"subject": s.subject, "kind": s.kind, "detail": s.description, "evidence": s.evidence}
            for s in infrastructure
        ],
        "signal_counts": _count_kinds(signals),
    }


def _count_kinds(signals: List[Signal]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for signal in signals:
        counts[signal.kind] += 1
    return dict(sorted(counts.items()))
