from pathlib import Path
from unittest.mock import patch

import pytest

from hids.collector import load_json_fixture
from hids.scorer import benchmark, load_labeled_fixture, score_events

FIXTURE = Path(__file__).parent / "fixtures" / "labeled_events.json"


def test_benchmark_achieves_perfect_score_on_hand_curated_fixture():
    result = benchmark(load_labeled_fixture(FIXTURE))

    assert result.false_positives == 0, "a rule fired on a case labeled benign"
    assert result.false_negatives == 0, "no rule fired on a case labeled malicious"
    assert result.wrong_rule == 0, "a malicious case fired a rule other than the one it was written to exercise"
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_score_events_groups_findings_by_process_and_ranks_by_severity():
    events = list(load_json_fixture(FIXTURE))
    risks = score_events(events)

    assert risks, "expected at least one risky process"
    scores = [r.score for r in risks]
    assert scores == sorted(scores, reverse=True), "risks must be ranked highest score first"


def test_load_labeled_fixture_rejects_event_count_mismatch():
    # If the event loader ever stops yielding exactly one event per row, the
    # zip in load_labeled_fixture would silently misalign labels -- guard it.
    with patch("hids.scorer.load_json_fixture", return_value=[]):
        with pytest.raises(ValueError):
            load_labeled_fixture(FIXTURE)
