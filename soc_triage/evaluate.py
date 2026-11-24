"""Compare agent priorities against analyst-labelled ground truth."""
from __future__ import annotations

from collections import Counter

from .agent import TriageResult

ORDER = ["P1", "P2", "P3", "P4"]


def evaluate(results: list[TriageResult], labels: dict[str, str]) -> dict:
    rows, exact, within_one, missed_critical = [], 0, 0, 0
    confusion: Counter = Counter()
    for r in results:
        want = labels.get(r.alert_id)
        if want is None:
            continue
        confusion[(want, r.priority)] += 1
        diff = abs(ORDER.index(want) - ORDER.index(r.priority))
        exact += diff == 0
        within_one += diff <= 1
        if want == "P1" and r.priority not in ("P1", "P2"):
            missed_critical += 1
        rows.append({"alert_id": r.alert_id, "expected": want, "got": r.priority, "ok": diff == 0})
    n = len(rows) or 1
    return {
        "total": len(rows),
        "exact_accuracy": round(exact / n, 3),
        "within_one_level": round(within_one / n, 3),
        "missed_critical": missed_critical,
        "rows": sorted(rows, key=lambda x: x["alert_id"]),
        "confusion": {f"{a}->{b}": c for (a, b), c in sorted(confusion.items())},
    }
