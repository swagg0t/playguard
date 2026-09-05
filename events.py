"""Event model.

One line of a game platform's auth/session telemetry. Real backends emit far
more fields; these are the ones every abuse detector in this project needs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator, List, Optional

LOGIN_SUCCESS = "login_success"
LOGIN_FAIL = "login_fail"
SESSION_START = "session_start"


@dataclass(frozen=True)
class Event:
    ts: float               # unix seconds
    account_id: str
    event_type: str
    ip: str
    device_id: str
    city: str
    lat: float
    lon: float
    country: str
    asn: Optional[str] = None

    @staticmethod
    def from_dict(raw: dict) -> "Event":
        return Event(
            ts=float(raw["ts"]),
            account_id=raw["account_id"],
            event_type=raw["event_type"],
            ip=raw["ip"],
            device_id=raw["device_id"],
            city=raw.get("city", ""),
            lat=float(raw.get("lat", 0.0)),
            lon=float(raw.get("lon", 0.0)),
            country=raw.get("country", ""),
            asn=raw.get("asn"),
        )


def load_events(path: str) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(Event.from_dict(json.loads(line)))
    events.sort(key=lambda e: e.ts)
    return events


def load_labels(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
