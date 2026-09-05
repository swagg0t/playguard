import unittest

from playguard.detectors import (
    detect_automation,
    detect_credential_stuffing,
    detect_impossible_travel,
    link_accounts,
)
from playguard.events import Event
from playguard.geo import haversine_km, implied_speed_kmh
from playguard.graph import UnionFind
from playguard.triage import build_queue

BASE = 1_770_000_000.0
MANILA = ("Manila", 14.5995, 120.9842, "PH")
LONDON = ("London", 51.5072, -0.1276, "GB")


def event(ts, account, kind, ip="1.1.1.1", device="dev_a", place=MANILA):
    city, lat, lon, country = place
    return Event(ts=ts, account_id=account, event_type=kind, ip=ip,
                 device_id=device, city=city, lat=lat, lon=lon, country=country)


class TestGeo(unittest.TestCase):
    def test_manila_to_london_distance(self):
        self.assertAlmostEqual(haversine_km(14.5995, 120.9842, 51.5072, -0.1276), 10750, delta=120)

    def test_zero_elapsed_time_is_infinite_speed(self):
        self.assertEqual(implied_speed_kmh(500, 0), float("inf"))


class TestUnionFind(unittest.TestCase):
    def test_transitive_merge(self):
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        self.assertEqual(uf.find("a"), uf.find("c"))
        self.assertEqual(len(uf.components()), 1)

    def test_separate_groups_stay_separate(self):
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("c", "d")
        self.assertEqual(len(uf.components()), 2)


class TestCredentialStuffing(unittest.TestCase):
    def _attack(self):
        return [event(BASE + i * 5, f"victim_{i}", "login_fail", ip="9.9.9.9") for i in range(20)]

    def test_detects_spray(self):
        signals = detect_credential_stuffing(self._attack())
        kinds = {s.kind for s in signals}
        self.assertIn("credential_stuffing_source", kinds)

    def test_success_during_attack_flags_takeover(self):
        events = self._attack() + [event(BASE + 50, "victim_3", "login_success", ip="9.9.9.9")]
        takeovers = [s for s in detect_credential_stuffing(events)
                     if s.kind == "suspected_account_takeover"]
        self.assertEqual([s.subject for s in takeovers], ["victim_3"])

    def test_busy_but_successful_ip_is_not_an_attack(self):
        # Same volume and account spread, but people are logging in fine.
        events = [event(BASE + i * 5, f"player_{i}", "login_success", ip="8.8.8.8") for i in range(20)]
        self.assertEqual(detect_credential_stuffing(events), [])


class TestImpossibleTravel(unittest.TestCase):
    def test_flags_manila_to_london_in_one_hour(self):
        events = [event(BASE, "a", "login_success", place=MANILA),
                  event(BASE + 3600, "a", "login_success", place=LONDON)]
        self.assertEqual(len(detect_impossible_travel(events)), 1)

    def test_real_flight_is_not_flagged(self):
        # ~10,750km over 15h is about 717km/h - a plausible long-haul flight.
        events = [event(BASE, "a", "login_success", place=MANILA),
                  event(BASE + 15 * 3600, "a", "login_success", place=LONDON)]
        self.assertEqual(detect_impossible_travel(events), [])

    def test_short_hops_ignored_because_geoip_is_coarse(self):
        near = ("Quezon City", 14.6760, 121.0437, "PH")
        events = [event(BASE, "a", "login_success", place=MANILA),
                  event(BASE + 60, "a", "login_success", place=near)]
        self.assertEqual(detect_impossible_travel(events), [])


class TestLinking(unittest.TestCase):
    def test_shared_device_forms_a_cluster(self):
        events = [event(BASE + i, f"acct_{i}", "login_success", ip=f"5.5.5.{i}", device="shared")
                  for i in range(5)]
        signals = link_accounts(events)
        self.assertEqual(len(signals), 5)
        self.assertEqual(signals[0].evidence["cluster_size"], 5)

    def test_two_accounts_on_one_device_is_a_household_not_a_ring(self):
        events = [event(BASE + i, f"acct_{i}", "login_success", ip=f"5.5.5.{i}", device="shared")
                  for i in range(2)]
        self.assertEqual(link_accounts(events), [])

    def test_high_fanout_ip_does_not_link(self):
        events = [event(BASE + i, f"acct_{i}", "login_success", ip="203.0.113.9", device=f"dev_{i}")
                  for i in range(40)]
        self.assertEqual(link_accounts(events), [])

    def test_failed_logins_do_not_create_links(self):
        events = [event(BASE + i, f"acct_{i}", "login_fail", ip="7.7.7.7", device="attacker")
                  for i in range(6)]
        self.assertEqual(link_accounts(events), [])

    def test_excluded_attacker_ip_does_not_cluster_its_victims(self):
        events = [event(BASE + i, f"victim_{i}", "login_success", ip="9.9.9.9", device="attacker")
                  for i in range(6)]
        self.assertEqual(link_accounts(events, exclude_ips={"9.9.9.9"}), [])


class TestAutomation(unittest.TestCase):
    def test_metronomic_schedule_is_flagged(self):
        events = [event(BASE + i * 18660, "bot", "session_start") for i in range(40)]
        kinds = {s.kind for s in detect_automation(events)}
        self.assertIn("metronomic_sessions", kinds)

    def test_irregular_human_schedule_is_not_flagged(self):
        gaps = [3600, 90000, 15000, 200000, 40000, 7000, 120000, 33000,
                61000, 9000, 150000, 22000, 88000, 5000]
        ts, events = BASE, []
        for gap in gaps:
            ts += gap
            events.append(event(ts, "human", "session_start"))
        kinds = {s.kind for s in detect_automation(events)}
        self.assertNotIn("metronomic_sessions", kinds)

    def test_too_few_sessions_to_judge(self):
        events = [event(BASE + i * 18660, "quiet", "session_start") for i in range(4)]
        self.assertEqual(detect_automation(events), [])


class TestTriage(unittest.TestCase):
    def test_victim_is_classified_for_reset_not_ban(self):
        events = [event(BASE + i * 5, f"victim_{i}", "login_fail", ip="9.9.9.9") for i in range(20)]
        events.append(event(BASE + 50, "victim_3", "login_success", ip="9.9.9.9", place=LONDON))
        events.insert(0, event(BASE - 3600, "victim_3", "login_success", ip="1.2.3.4", place=MANILA))

        queue = build_queue(events)
        row = next(r for r in queue["accounts"] if r["account_id"] == "victim_3")
        self.assertEqual(row["classification"], "compromised_account")
        self.assertIn("reset", row["recommended_action"].lower())
        self.assertEqual(len(queue["infrastructure"]), 1)

    def test_queue_is_ranked_by_score(self):
        events = [event(BASE + i, f"acct_{i}", "login_success", ip=f"5.5.5.{i}", device="shared")
                  for i in range(5)]
        scores = [r["risk_score"] for r in build_queue(events)["accounts"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
