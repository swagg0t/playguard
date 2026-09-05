"""Generate a deterministic, labelled telemetry sample.

There is no public dataset of game-platform abuse, and using real player data
would be a privacy problem even if there were. So the benchmark is synthetic
and the ground truth ships with it, which is also the only way to report an
honest false-positive rate.

Populations:
    benign            legitimate players, irregular hours, one or two devices
    traveller         benign players who really do fly - the near-miss case
                      the impossible-travel threshold must NOT catch
    compromised       benign until an attacker logs in with stuffed credentials
    bot_farm          scripted accounts on a fixed schedule sharing devices
    multi_accounting  one operator running several accounts off one device

    python3 playguard/generate_dataset.py
"""

from __future__ import annotations

import json
import os
import random
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
RNG = random.Random(4671)

DAY = 86400
SPAN_DAYS = 14
START = datetime(2026, 2, 1, tzinfo=timezone.utc).timestamp()

CITIES = {
    "Manila":     (14.5995, 120.9842, "PH"),
    "Singapore":  (1.3521, 103.8198, "SG"),
    "London":     (51.5072, -0.1276, "GB"),
    "Madrid":     (40.4168, -3.7038, "ES"),
    "Seoul":      (37.5665, 126.9780, "KR"),
    "Sao Paulo":  (-23.5558, -46.6396, "BR"),
    "Toronto":    (43.6532, -79.3832, "CA"),
    "Warsaw":     (52.2297, 21.0122, "PL"),
}
CITY_NAMES = list(CITIES)


def _ip(a, b, c, d) -> str:
    return f"{a}.{b}.{c}.{d}"


def _event(ts, account, kind, ip, device, city):
    lat, lon, country = CITIES[city]
    return {"ts": round(ts, 1), "account_id": account, "event_type": kind,
            "ip": ip, "device_id": device, "city": city,
            "lat": lat, "lon": lon, "country": country}


def _login_and_session(events, ts, account, ip, device, city, fail_chance=0.06):
    if RNG.random() < fail_chance:
        events.append(_event(ts - 12, account, "login_fail", ip, device, city))
    events.append(_event(ts, account, "login_success", ip, device, city))
    events.append(_event(ts + RNG.uniform(2, 40), account, "session_start", ip, device, city))


def build() -> tuple:
    events: list = []
    labels: dict = {}

    # Two carrier-grade NAT egresses shared by many unrelated players. Their
    # fanout must push them past the linking guard.
    cgnat = [_ip(203, 177, 40, 11), _ip(203, 177, 40, 12)]
    cgnat_members = set()

    # ---------------- benign players ----------------
    shared_household_device = {}
    for i in range(155):
        account = f"acct_{i:04d}"
        labels[account] = "benign"
        city = RNG.choice(CITY_NAMES)
        device = f"dev_{i:04d}"
        # 8 households share one device between two accounts: a real pattern
        # that must stay below the cluster threshold.
        if 20 <= i < 36 and i % 2 == 1:
            device = shared_household_device[i - 1]
        elif 20 <= i < 36:
            shared_household_device[i] = device

        if i % 4 == 0:
            ip = RNG.choice(cgnat)
            cgnat_members.add(account)
        else:
            ip = _ip(112, RNG.randint(10, 250), RNG.randint(0, 255), RNG.randint(1, 254))

        for day in range(SPAN_DAYS):
            for _ in range(RNG.choice([0, 1, 1, 2, 2, 3])):
                ts = START + day * DAY + RNG.uniform(15, 23) * 3600
                _login_and_session(events, ts, account, ip, device, city)

    # ---------------- benign travellers ----------------
    for i in range(155, 159):
        account = f"acct_{i:04d}"
        labels[account] = "benign"
        home, away = RNG.sample(CITY_NAMES, 2)
        device, ip = f"dev_{i:04d}", _ip(112, RNG.randint(10, 250), RNG.randint(0, 255), RNG.randint(1, 254))
        for day in range(SPAN_DAYS):
            city = home if day < 7 else away
            ts = START + day * DAY + RNG.uniform(15, 23) * 3600
            _login_and_session(events, ts, account, ip, device, city)
        # The real flight: a long hop, but at a speed an aircraft can manage.
        events.append(_event(START + 6.6 * DAY, account, "login_success", ip, device, home))
        events.append(_event(START + 7.4 * DAY, account, "login_success", ip, device, away))

    # ---------------- accounts that get taken over ----------------
    compromised = [f"acct_{i:04d}" for i in range(159, 174)]
    attacker_ips = [_ip(45, 12, 88, 200), _ip(91, 240, 17, 63)]
    for i, account in enumerate(compromised):
        labels[account] = "compromised"
        city = RNG.choice(CITY_NAMES)
        device, ip = f"dev_{159 + i:04d}", _ip(112, RNG.randint(10, 250), RNG.randint(0, 255), RNG.randint(1, 254))
        for day in range(SPAN_DAYS):
            for _ in range(RNG.choice([1, 1, 2])):
                ts = START + day * DAY + RNG.uniform(15, 23) * 3600
                _login_and_session(events, ts, account, ip, device, city)

    # ---------------- the credential stuffing runs ----------------
    victims_by_ip = {attacker_ips[0]: compromised[:8], attacker_ips[1]: compromised[8:]}
    for run, (attack_ip, victims) in enumerate(victims_by_ip.items()):
        base = START + (9 + run) * DAY + 3 * 3600
        attack_device = f"dev_bot_{run}"
        attack_city = "Warsaw" if run else "Sao Paulo"
        # Sprayed failures against accounts the attacker guessed wrong on.
        for n in range(70):
            target = f"acct_{RNG.randint(0, 154):04d}"
            events.append(_event(base + n * 9 + RNG.uniform(0, 4), target,
                                 "login_fail", attack_ip, attack_device, attack_city))
        # The hits.
        for n, victim in enumerate(victims):
            ts = base + 120 + n * 21
            events.append(_event(ts, victim, "login_success", attack_ip, attack_device, attack_city))
            events.append(_event(ts + 30, victim, "session_start", attack_ip, attack_device, attack_city))

    # ---------------- scripted farms ----------------
    farm_index = 0
    for farm in range(3):
        farm_ip = _ip(185, 60 + farm, RNG.randint(0, 255), RNG.randint(1, 254))
        farm_devices = [f"dev_farm{farm}_{d}" for d in range(2)]
        farm_city = RNG.choice(CITY_NAMES)
        interval = 5 * 3600 + 11 * 60          # deliberately not a divisor of 24h
        for member in range(7):
            account = f"acct_farm{farm}_{member}"
            labels[account] = "bot_farm"
            device = farm_devices[member % len(farm_devices)]
            ts = START + RNG.uniform(0, 3600) + member * 400
            while ts < START + SPAN_DAYS * DAY:
                _login_and_session(events, ts, account, farm_ip, device, farm_city, fail_chance=0.01)
                ts += interval + RNG.uniform(-180, 180)
            farm_index += 1

    # ---------------- one operator, many accounts ----------------
    for cluster in range(2):
        cluster_device = f"dev_multi_{cluster}"
        cluster_ip = _ip(122, 33 + cluster, RNG.randint(0, 255), RNG.randint(1, 254))
        cluster_city = RNG.choice(CITY_NAMES)
        for member in range(6):
            account = f"acct_multi{cluster}_{member}"
            labels[account] = "multi_accounting"
            for day in range(SPAN_DAYS):
                for _ in range(RNG.choice([0, 1, 1, 2])):
                    ts = START + day * DAY + RNG.uniform(9, 23) * 3600
                    _login_and_session(events, ts, account, cluster_ip, cluster_device, cluster_city)

    events.sort(key=lambda e: e["ts"])
    return events, labels, sorted(cgnat_members)


if __name__ == "__main__":
    events, labels, cgnat_members = build()
    events_path = os.path.join(HERE, "data", "events.jsonl")
    labels_path = os.path.join(HERE, "data", "labels.json")
    os.makedirs(os.path.dirname(events_path), exist_ok=True)

    with open(events_path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    with open(labels_path, "w", encoding="utf-8") as fh:
        json.dump(labels, fh, indent=2, sort_keys=True)

    from collections import Counter
    print(f"events   : {len(events):,}")
    print(f"accounts : {len(labels):,}")
    print(f"labels   : {dict(Counter(labels.values()))}")
    print(f"CGNAT-shared benign accounts: {len(cgnat_members)}")
