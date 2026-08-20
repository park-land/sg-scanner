"""Tests evals/judge.py's parsing and aggregation — the deterministic parts
that don't need a real model. sgtree.claude_helper._call is monkeypatched;
no live API calls. Whether the *scores* a real judge model would assign are
any good is exactly what the live eval run (ANTHROPIC_API_KEY required) is
for — this file only proves the harness computes correct statistics from
whatever the judge model returns.
"""
import json

from evals import judge
from sgtree import claude_helper


def _item(item_id='item-1', kind='severity_explanation'):
    return {'id': item_id, 'kind': kind, 'input_facts': {'port': 22}, 'output_text': 'SSH open to the world.'}


class TestJudgeBatch:
    def test_parses_well_formed_response(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'item-1': {'accurate': 5, 'grounded': 5, 'specific': 4, 'calibrated': 5,
                       'grounding_failure': False, 'notes': ''},
        }))
        result = judge.judge_batch([_item()])
        assert result['item-1']['scores'] == {'accurate': 5, 'grounded': 5, 'specific': 4, 'calibrated': 5}
        assert result['item-1']['grounding_failure'] is False

    def test_out_of_range_score_drops_the_item(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'item-1': {'accurate': 7, 'grounded': 5, 'specific': 4, 'calibrated': 5, 'grounding_failure': False},
        }))
        assert judge.judge_batch([_item()]) == {}

    def test_missing_axis_drops_the_item(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'item-1': {'accurate': 5, 'grounded': 5, 'specific': 4},  # no calibrated
        }))
        assert judge.judge_batch([_item()]) == {}

    def test_grounding_failure_flag_preserved(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'item-1': {'accurate': 2, 'grounded': 1, 'specific': 3, 'calibrated': 2,
                       'grounding_failure': True, 'notes': 'Invented an attachment not in input_facts.'},
        }))
        result = judge.judge_batch([_item()])
        assert result['item-1']['grounding_failure'] is True
        assert 'attachment' in result['item-1']['notes']

    def test_empty_input_short_circuits_without_calling_claude(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('must not call Claude with no items')))
        assert judge.judge_batch([]) == {}

    def test_string_score_is_coerced(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'item-1': {'accurate': '5', 'grounded': '4', 'specific': '3', 'calibrated': '5',
                       'grounding_failure': False},
        }))
        result = judge.judge_batch([_item()])
        assert result['item-1']['scores']['accurate'] == 5


class TestSummarize:
    def test_averages_across_items(self):
        scored = {
            'a': {'scores': {'accurate': 5, 'grounded': 5, 'specific': 5, 'calibrated': 5}, 'grounding_failure': False, 'notes': ''},
            'b': {'scores': {'accurate': 3, 'grounded': 3, 'specific': 3, 'calibrated': 3}, 'grounding_failure': True, 'notes': 'x'},
        }
        summary = judge.summarize(scored)
        assert summary['n'] == 2
        assert summary['accurate'] == 4.0
        assert summary['grounding_failure_count'] == 1

    def test_empty_scored_dict_does_not_divide_by_zero(self):
        summary = judge.summarize({})
        assert summary['n'] == 0
        assert summary['accurate'] == 0.0
