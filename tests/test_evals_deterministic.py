"""Runs the deterministic-checks eval (evals/deterministic.py) against
evals/fixtures.py as part of the normal test suite. Fully offline — no AWS,
no Claude. This is a regression guard: the checks are rules, so precision
and recall should be exactly 1.0 on well-formed fixtures; a drop here means
a check's behavior silently changed.
"""
from evals import deterministic
from evals.fixtures import FIXTURES


def test_deterministic_precision_and_recall_are_perfect():
    per_check, totals, mismatches = deterministic.score(FIXTURES)

    assert totals['precision'] == 1.0, f"false positives: {[m for m in mismatches if m[1] == 'fp']}"
    assert totals['recall'] == 1.0, f"false negatives: {[m for m in mismatches if m[1] == 'fn']}"


def test_every_check_type_is_exercised_by_the_fixture_set():
    # Guards against a fixture-set regression that accidentally stops
    # covering one of the four checks (a silent gap, not a wrong answer).
    per_check, _, _ = deterministic.score(FIXTURES)
    exercised = {check for check, stats in per_check.items() if stats['tp'] > 0}
    assert exercised == {'sg_allows_all', 'sg_rule_no_description', 'sg_stale_rule', 'sg_unused'}


def test_per_check_precision_and_recall_individually_perfect():
    per_check, _, mismatches = deterministic.score(FIXTURES)
    for check_id, stats in per_check.items():
        assert stats['precision'] == 1.0, (check_id, mismatches)
        assert stats['recall'] == 1.0, (check_id, mismatches)
