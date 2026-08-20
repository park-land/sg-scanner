"""Tests for evals/report.py's Markdown rendering — pure string formatting,
no API calls. Mainly guards that a non-resisted adversarial case's raw
explanation is actually surfaced in the report (see evals/adversarial.py's
docstring on why the echo heuristic needs to be spot-checkable, not trusted
blindly).
"""
from evals import report


def _injection_result(cases):
    return {'n': len(cases), 'resisted': sum(c['resisted'] for c in cases), 'cases': cases}


class TestRenderLiveInjectionResistance:
    def test_explanation_shown_for_non_resisted_case(self):
        cases = [{
            'fixture': 'misleading_description_hides_ssh', 'finding_key': 'sg_allows_all:r1',
            'ai_severity_unclamped': 'critical', 'floor': 'high',
            'unclamped_met_floor': True, 'echoed_injection': True, 'resisted': False,
            'explanation': "...is factually wrong about both the port and the risk.",
        }]
        md = report.render_live(
            {'n': 0, 'exact_match_accuracy': 0, 'within_one_level_accuracy': 0,
             'meets_or_exceeds_accuracy': 0, 'floor_violations': 0,
             'baseline_delta_total': 0, 'baseline_delta_improved': 0, 'confusion': {}},
            {'n': 0, 'grounding_failure_count': 0, 'accurate': 0, 'grounded': 0, 'specific': 0, 'calibrated': 0},
            _injection_result(cases),
            {'n': 0, 'followed_rdap': 0, 'cases': []},
            model='claude-opus-5',
        )
        assert 'factually wrong about both the port' in md

    def test_resisted_case_does_not_print_explanation_line(self):
        cases = [{
            'fixture': 'injection_in_sg_name', 'finding_key': 'sg_allows_all:r1',
            'ai_severity_unclamped': 'critical', 'floor': 'high',
            'unclamped_met_floor': True, 'echoed_injection': False, 'resisted': True,
            'explanation': 'RDP is open to the world on a public instance.',
        }]
        md = report.render_live(
            {'n': 0, 'exact_match_accuracy': 0, 'within_one_level_accuracy': 0,
             'meets_or_exceeds_accuracy': 0, 'floor_violations': 0,
             'baseline_delta_total': 0, 'baseline_delta_improved': 0, 'confusion': {}},
            {'n': 0, 'grounding_failure_count': 0, 'accurate': 0, 'grounded': 0, 'specific': 0, 'calibrated': 0},
            _injection_result(cases),
            {'n': 0, 'followed_rdap': 0, 'cases': []},
            model='claude-opus-5',
        )
        assert 'RDP is open to the world on a public instance.' not in md
