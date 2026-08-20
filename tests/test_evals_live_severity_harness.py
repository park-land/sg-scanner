"""Tests the SCORING/aggregation logic in evals/live_severity.py — the part
that's deterministic and doesn't need a real model. sgtree.claude_helper is
monkeypatched throughout, so this runs offline as part of normal CI; it does
NOT tell you anything about actual model quality (that's what the live run
with a real ANTHROPIC_API_KEY is for), only that the harness computes
correct statistics from whatever analyze_security_posture returns.
"""
from evals import live_severity
from evals.fixtures import Fixture, _public_instance, _rule
from sgtree import claude_helper


def _fixture(name, expected, ai_severity):
    fx = Fixture(
        name=name, tags=['unit'], sg_name='test-sg',
        rules=[_rule('r1', from_port=22, to_port=22, cidr4='0.0.0.0/0', description='ssh')],
        attachments=[_public_instance('i-1')],
        public_ips=[{'ip': '203.0.113.1', 'resource_id': 'i-1'}],
        expected_min_severity={('sg_allows_all', 'r1'): expected},
    )
    return fx


class TestRunAggregation:
    def test_exact_match_when_ai_matches_expected(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_allows_all:r1': {'severity': 'high', 'explanation': 'exposed'}},
        })
        result = live_severity.run([_fixture('fx1', 'high', 'high')])
        assert result['exact_match_accuracy'] == 1.0
        assert result['within_one_level_accuracy'] == 1.0
        assert result['meets_or_exceeds_accuracy'] == 1.0

    def test_within_one_level_but_not_exact(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_allows_all:r1': {'severity': 'critical', 'explanation': 'very exposed'}},
        })
        result = live_severity.run([_fixture('fx1', 'high', 'critical')])
        assert result['exact_match_accuracy'] == 0.0
        assert result['within_one_level_accuracy'] == 1.0
        assert result['meets_or_exceeds_accuracy'] == 1.0  # critical > high, not an undersell

    def test_undersell_fails_meets_or_exceeds(self, monkeypatch):
        # Below the floor gets clamped back up in the actual pipeline, but
        # this confirms the metric itself would catch an undersell if the
        # clamp somehow didn't apply (e.g. a non-allowall finding).
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_stale_rule:r1': {'severity': 'low', 'explanation': 'meh'}},
        })
        fx = Fixture(
            name='fx-stale', tags=['unit'], sg_name='test-sg',
            rules=[_rule('r1', description='ref', referenced_group='sg-gone', referenced_exists=False)],
            expected_min_severity={('sg_stale_rule', 'r1'): 'high'},
        )
        result = live_severity.run([fx])
        assert result['meets_or_exceeds_accuracy'] == 0.0

    def test_floor_violation_counted_when_ai_undersells_a_critical_port(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_allows_all:r1': {'severity': 'info', 'explanation': 'seems fine'}},
        })
        result = live_severity.run([_fixture('fx1', 'high', 'info')])
        assert result['floor_violations'] == 1
        # but the actual reported severity is still clamped up
        assert result['results'][0]['actual_severity'] == 'high'

    def test_baseline_delta_counted_when_ai_differs_from_flat_baseline(self, monkeypatch):
        # baseline_for_finding for sg_allows_all/port 22 is already 'high'
        # (it's floored), so AI has to actually escalate to 'critical' to
        # register as a delta here.
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_allows_all:r1': {'severity': 'critical', 'explanation': 'public + no auth'}},
        })
        result = live_severity.run([_fixture('fx1', 'critical', 'critical')])
        assert result['baseline_delta_total'] == 1
        assert result['baseline_delta_improved'] == 1

    def test_no_ai_opinion_falls_back_to_baseline_and_no_delta(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {})
        result = live_severity.run([_fixture('fx1', 'high', None)])
        assert result['results'][0]['actual_severity'] == 'high'  # baseline for SSH allow-all
        assert result['baseline_delta_total'] == 0

    def test_confusion_matrix_records_pairs(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {
            'severities': {'sg_allows_all:r1': {'severity': 'critical', 'explanation': 'x'}},
        })
        result = live_severity.run([_fixture('fx1', 'high', 'critical')])
        assert result['confusion'] == {('high', 'critical'): 1}

    def test_empty_fixture_list_does_not_crash(self, monkeypatch):
        monkeypatch.setattr(claude_helper, 'analyze_security_posture', lambda ctx, model=None: {})
        result = live_severity.run([])
        assert result['n'] == 0
        assert result['exact_match_accuracy'] == 0.0
