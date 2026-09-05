![GitHub Repo Banner](https://ghrb.waren.build/banner?header=%21%5Bpython%5D+swagg0t%2Fplayguard&bg=FFFFFF&color=000000&headerfont=Roboto+Mono&watermarkpos=bottom-right)
<!-- Created with GitHub Repo Banner by Waren Gonzaga: https://ghrb.waren.build -->

Reads a game backend's authentication and session telemetry and produces a ranked analyst queue: which accounts need action, why, and, critically, whether the account holder is the offender or the victim.

Python 3.9+. No third-party dependencies.

---

## The four patterns it detects

| Detector | Pattern | The tell |
|---|---|---|
| `detect_credential_stuffing` | Breached credential lists replayed against the login endpoint | Many *distinct* accounts from one source in a short window, at a failure ratio far above baseline |
| `detect_impossible_travel` | Session hijack or shared/sold account | Consecutive successful logins no aircraft could connect |
| `link_accounts` | Multi-accounting, referral fraud, RMT farms | Accounts sharing device identifiers or narrow IPs |
| `detect_automation` | Bots and gold farming | Session intervals too regular to be human; activity across 20+ hours of the day |

No detector decides guilt on its own. Every one of these signals has an innocent explanation: shared households, real flights, night shifts, so `triage.py` combines weighted evidence and the queue records which signals fired. A system that actions on one signal bans real players.

## Attacker v. Victim

The queue separates two outputs because they need opposite responses:

- **`infrastructure`** — attacking sources. Rate-limit or block.
- **`accounts`** — accounts carrying evidence, each classified
  `abusive_account` or `compromised_account`.

An account successfully logged into from a confirmed stuffing source is a victim. Its recommended action is a forced credential reset and a player notification, explicitly NOT a ban. Getting this wrong means punishing customers for having been attacked.

## Two engineering problems worth reading the code for

**The 110-account cluster.** The first version of `link_accounts` treated device identifiers as unconditional links and returned one cluster of 110 accounts. Device IDs are *client-reported*: an attacker replaying credentials from a single machine stamps their device ID onto every account they touch, so the "cluster" was one attacker plus their victims. Three changes fixed it: only successful authentications create edges (a failed login proves nothing about the account), devices get a fanout ceiling, and sources already confirmed as attacking infrastructure are excluded outright. That last one means the detectors run in dependency order: stuffing first, because its output changes how linking should read the data.

**IP fanout.** Carrier-grade NAT, campus networks and internet cafes put hundreds of unrelated players behind one address. An IP only creates edges while its fanout stays under a ceiling. The benchmark deliberately puts 39 legitimate accounts behind two CGNAT egresses to prove the guard holds.

## Running it

```bash
python3 playguard/generate_dataset.py    # build the labelled synthetic sample
python3 -m playguard triage --out queue.json
python3 -m playguard evaluate
python3 -m unittest discover -s playguard/tests -t .
```

## Benchmark

There is no public dataset of game-platform abuse, and using real player telemetry would be a privacy problem even if there were. So the sample is synthetic and ships its own ground truth, which is also the only honest way to report a false-positive rate.

10,791 events, 207 accounts, 14 days. Populations: 159 benign (including 4 real travellers and 39 accounts behind shared CGNAT), 15 taken over via stuffing, 21 scripted farm accounts, 12 multi-accounting.

| Score threshold | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| 25 | 0.941 | 1.000 | 0.970 | 0.019 |
| **30** | **0.941** | **1.000** | **0.970** | **0.019** |
| 35 | 1.000 | 0.917 | 0.957 | 0.000 |
| 40 | 1.000 | 0.667 | 0.800 | 0.000 |

Recall by abuse type at the operating point: bot farms 21/21, compromised accounts 15/15, multi-accounting 12/12.

The threshold choice is a judgement, not a maximum. 35 has a zero false-positive rate but misses 4 takeover victims whose attacker happened to be geolocated near them, so only the takeover signal fired. 30 catches all 15 at the cost of 3 false positives. Because a score of 30 lands in tier P3: "watchlist, re-evaluate next batch", not an enforcement action, the cost of
those 3 is an analyst glance, and the cost of the 4 misses is a player losing their account. 30 is the right call for this weighting; a platform with a different cost model should pick differently, which is why the sweep ships.

Detection runs at roughly 240,000 events/second on the sample.

**These numbers describe synthetic data with clean class separation.** They show that the detectors and the scoring combine correctly and that the guards hold against the specific confounders built into the sample. They are not a claim about production traffic, where the classes overlap far more.

## Known limits

- Signal weights are hand-set. With labelled enforcement outcomes they should
  be fitted, and the combination is naive additive summing.
- Impossible travel trusts IP geolocation, which VPNs defeat entirely. A real
  deployment needs a VPN/proxy reputation feed alongside it.
- No behavioural biometrics or in-game economy signals, which are where the
  strongest RMT detection actually lives.
- Detection is batch. Streaming would need windowed state rather than the
  full-history passes here.

## Tests

20 unit tests, including the negative cases that matter most: a busy but successful IP is not an attack, a real 15-hour flight is not impossible travel, two accounts on one device is a household and not a ring, a high-fanout IP does not link, failed logins create no links, and an excluded attacker IP does not cluster its victims.
