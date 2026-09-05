"""Command line interface.

    python -m playguard triage   --events playguard/data/events.jsonl
    python -m playguard evaluate --events playguard/data/events.jsonl \
                                 --labels playguard/data/labels.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .evaluate import confusion, per_label_recall, sweep
from .events import load_events, load_labels
from .triage import build_queue

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EVENTS = os.path.join(HERE, "data", "events.jsonl")
DEFAULT_LABELS = os.path.join(HERE, "data", "labels.json")


def _queue(path):
    events = load_events(path)
    started = time.perf_counter()
    queue = build_queue(events)
    return events, queue, time.perf_counter() - started


def cmd_triage(args) -> int:
    events, queue, elapsed = _queue(args.events)
    print(f"Events ingested : {len(events):,}")
    print(f"Detection time  : {elapsed:.3f}s ({len(events) / elapsed:,.0f} events/s)")
    print(f"Signals raised  : {queue['signal_counts']}")
    print(f"Accounts queued : {len(queue['accounts'])}")

    if queue["infrastructure"]:
        print("\nATTACKING INFRASTRUCTURE")
        print("-" * 78)
        for row in queue["infrastructure"]:
            print(f"  {row['subject']:<22} {row['detail']}")

    print(f"\n{'ACCOUNT':<22} {'SCORE':>5} {'TIER':<5} {'CLASSIFICATION':<20} TOP SIGNAL")
    print("-" * 108)
    for row in queue["accounts"][: args.limit]:
        top = row["signals"][0]["detail"] if row["signals"] else ""
        print(f"{row['account_id']:<22} {row['risk_score']:>5} {row['tier']:<5} "
              f"{row['classification']:<20} {top[:44]}")
    if len(queue["accounts"]) > args.limit:
        print(f"... {len(queue['accounts']) - args.limit} more in the JSON report")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(queue, fh, indent=2)
        print(f"\nFull queue written to {args.out}")
    return 0


def cmd_evaluate(args) -> int:
    events, queue, elapsed = _queue(args.events)
    labels = load_labels(args.labels)

    print(f"Events {len(events):,} | accounts {len(labels):,} | detection {elapsed:.3f}s\n")
    print(f"{'THRESH':>7} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} {'PREC':>7} {'RECALL':>7} {'F1':>7} {'FPR':>7}")
    print("-" * 64)
    for row in sweep(queue, labels, list(range(10, 105, 5))):
        print(f"{row['threshold']:>7} {row['true_positives']:>5} {row['false_positives']:>5} "
              f"{row['false_negatives']:>5} {row['true_negatives']:>5} {row['precision']:>7.3f} "
              f"{row['recall']:>7.3f} {row['f1']:>7.3f} {row['false_positive_rate']:>7.3f}")

    headline = confusion(queue, labels, args.threshold)
    print(f"\nOperating point (score >= {args.threshold}):")
    print(f"  precision {headline['precision']:.3f} | recall {headline['recall']:.3f} "
          f"| F1 {headline['f1']:.3f} | false-positive rate {headline['false_positive_rate']:.3f}")
    print("\nRecall by abuse type:")
    for label, stats in per_label_recall(queue, labels, args.threshold).items():
        print(f"  {label:<20} {stats['caught']:>3}/{stats['total']:<3} = {stats['recall']:.3f}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="playguard", description="Game platform abuse triage")
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="rank accounts by risk")
    triage.add_argument("--events", default=DEFAULT_EVENTS)
    triage.add_argument("--out", default=None)
    triage.add_argument("--limit", type=int, default=20)
    triage.set_defaults(func=cmd_triage)

    ev = sub.add_parser("evaluate", help="precision/recall against labelled data")
    ev.add_argument("--events", default=DEFAULT_EVENTS)
    ev.add_argument("--labels", default=DEFAULT_LABELS)
    ev.add_argument("--threshold", type=int, default=30)
    ev.set_defaults(func=cmd_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
