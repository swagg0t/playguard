"""Score the queue against ground truth.

A detection system without a measured false-positive rate is a system that
bans paying customers. The synthetic dataset ships labels so the operating
threshold can be chosen from a curve instead of from intuition.
"""

from __future__ import annotations

from typing import Dict, List


def confusion(queue: Dict, labels: Dict[str, str], threshold: int) -> Dict:
    flagged = {row["account_id"] for row in queue["accounts"] if row["risk_score"] >= threshold}
    abusive = {account for account, label in labels.items() if label != "benign"}
    everyone = set(labels)

    tp = len(flagged & abusive)
    fp = len(flagged - abusive)
    fn = len(abusive - flagged)
    tn = len(everyone - flagged - abusive)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "threshold": threshold,
        "true_positives": tp, "false_positives": fp,
        "false_negatives": fn, "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def sweep(queue: Dict, labels: Dict[str, str], thresholds: List[int]) -> List[Dict]:
    return [confusion(queue, labels, t) for t in thresholds]


def per_label_recall(queue: Dict, labels: Dict[str, str], threshold: int) -> Dict[str, Dict]:
    """Recall broken out by abuse type - an aggregate number can hide a
    detector that catches nothing."""
    flagged = {row["account_id"] for row in queue["accounts"] if row["risk_score"] >= threshold}
    buckets: Dict[str, Dict] = {}
    for account, label in labels.items():
        if label == "benign":
            continue
        bucket = buckets.setdefault(label, {"total": 0, "caught": 0})
        bucket["total"] += 1
        bucket["caught"] += 1 if account in flagged else 0
    for bucket in buckets.values():
        bucket["recall"] = round(bucket["caught"] / bucket["total"], 4) if bucket["total"] else 0.0
    return dict(sorted(buckets.items()))
