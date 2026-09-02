"""Aggregate per-event findings into a per-process risk score, and grade
the rule engine itself against a labeled fixture (precision/recall/F1) --
same "prove the tool before trusting it" approach as the vuln scanner's
Bandit/dataset benchmark.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from hids.collector import load_json_fixture
from hids.events import Event
from hids.rules import Finding, evaluate


@dataclass
class ProcessRisk:
    process_guid: str
    image: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.severity for f in self.findings)


def score_events(events: list[Event]) -> list[ProcessRisk]:
    """Group findings by process_guid (falls back to image+pid when a
    non-process event, e.g. 4698, has no ProcessGuid) and sum severity."""
    by_process: dict[str, ProcessRisk] = {}
    for event in events:
        findings = evaluate(event)
        if not findings:
            continue
        key = event.process_guid or f"{event.image or event.extra.get('TaskName', '')}:{event.process_id}"
        if key not in by_process:
            by_process[key] = ProcessRisk(process_guid=key, image=event.image or event.extra.get("TaskName", ""))
        by_process[key].findings.extend(findings)

    return sorted(by_process.values(), key=lambda p: p.score, reverse=True)


def load_labeled_fixture(path: str | Path) -> list[tuple[Event, bool, str | None]]:
    """Load a labeled benchmark fixture into (event, is_malicious, expected_rule) rows.

    The fixture is a JSON list; each row carries a ``label`` ("malicious" /
    "benign") and, optionally, an ``expected_rule`` naming the rule that
    *should* fire (used to check the rule fired for the right reason, not just
    that something fired). ``load_json_fixture`` yields exactly one event per
    row, in order; assert that so a future divergence fails loudly instead of
    being silently truncated by ``zip``.
    """
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    events = list(load_json_fixture(path))
    if len(events) != len(payload):
        raise ValueError(
            f"fixture {path} has {len(payload)} rows but produced {len(events)} events"
        )
    return [
        (event, row.get("label") == "malicious", row.get("expected_rule"))
        for event, row in zip(events, payload)
    ]


@dataclass
class BenchmarkResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    # Malicious cases where a rule fired, but not the rule the fixture named.
    wrong_rule: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def benchmark(labeled_events: list[tuple]) -> BenchmarkResult:
    """Grade the rule engine against labeled cases, one row per case.

    Each row is ``(event, is_malicious)`` or ``(event, is_malicious, expected_rule)``.
    A case is a "true positive" if labeled malicious AND at least one rule
    fired; "false negative" if malicious and nothing fired; "false positive"
    if labeled benign but a rule fired anyway. When a row names an
    ``expected_rule`` and that rule is not among the ones that fired, the case
    is still counted as a true positive but also tallied in ``wrong_rule`` so
    "a rule fired" can be distinguished from "the right rule fired".
    """
    tp = fp = fn = wrong = 0
    for row in labeled_events:
        event, is_malicious = row[0], row[1]
        expected_rule = row[2] if len(row) > 2 else None
        fired_rules = {f.rule_id for f in evaluate(event)}
        fired = bool(fired_rules)
        if is_malicious and fired:
            tp += 1
            if expected_rule and expected_rule not in fired_rules:
                wrong += 1
        elif is_malicious and not fired:
            fn += 1
        elif not is_malicious and fired:
            fp += 1
    return BenchmarkResult(
        true_positives=tp, false_positives=fp, false_negatives=fn, wrong_rule=wrong
    )
