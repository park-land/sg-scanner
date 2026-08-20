"""Unit tests for sgtree/claude_helper.py's response parsing — specifically
that every enrichment call returns {id: {<value_key>: str, 'reasoning': str}}
and tolerates a malformed/partial response instead of raising. _call is
monkeypatched throughout; no real API calls.
"""
import json

from sgtree import claude_helper


class TestParseJsonObject:
    """A real live run surfaced this: with enough items in a batch, the
    model sometimes mirrors the "one JSON object per line" framing used for
    the *input* into its *output* too — producing several syntactically
    valid {...} objects, one per line, instead of a single combined object.
    That's invalid as a whole (multiple top-level JSON values), and without
    this tolerance the entire batch's real, well-formed answers were
    silently lost (parsed to {}), not just reformatted."""

    def test_single_combined_object_parses_normally(self):
        text = json.dumps({'a': 1, 'b': 2})
        assert claude_helper._parse_json_object(text) == {'a': 1, 'b': 2}

    def test_newline_delimited_objects_are_merged(self):
        text = '{"a": {"x": 1}}\n{"b": {"x": 2}}\n{"c": {"x": 3}}'
        assert claude_helper._parse_json_object(text) == {
            'a': {'x': 1}, 'b': {'x': 2}, 'c': {'x': 3},
        }

    def test_newline_delimited_with_blank_lines_between(self):
        text = '{"a": 1}\n\n{"b": 2}\n'
        assert claude_helper._parse_json_object(text) == {'a': 1, 'b': 2}

    def test_one_bad_line_among_valid_ones_drops_everything(self):
        # Conservative on purpose: can't tell which lines are trustworthy
        # once the shape assumption (one JSON object per line) breaks.
        text = '{"a": 1}\nnot json\n{"b": 2}'
        assert claude_helper._parse_json_object(text) == {}

    def test_non_object_line_drops_everything(self):
        text = '{"a": 1}\n[1, 2, 3]'
        assert claude_helper._parse_json_object(text) == {}

    def test_completely_unparseable_text_returns_empty_dict(self):
        assert claude_helper._parse_json_object('not json at all') == {}


class TestParseGuessWithReasoning:
    def test_parses_well_formed_response(self):
        text = json.dumps({'id-1': {'label': 'RDS Proxy', 'reasoning': 'Description says RDSProxy.'}})
        result = claude_helper._parse_guess_with_reasoning(text, 'label')
        assert result == {'id-1': {'label': 'RDS Proxy', 'reasoning': 'Description says RDSProxy.'}}

    def test_missing_reasoning_defaults_to_empty_string(self):
        text = json.dumps({'id-1': {'label': 'RDS Proxy'}})
        result = claude_helper._parse_guess_with_reasoning(text, 'label')
        assert result == {'id-1': {'label': 'RDS Proxy', 'reasoning': ''}}

    def test_entry_with_empty_guess_is_dropped(self):
        text = json.dumps({'id-1': {'label': '', 'reasoning': 'nothing to go on'}})
        assert claude_helper._parse_guess_with_reasoning(text, 'label') == {}

    def test_entry_that_is_a_bare_string_not_a_dict_is_dropped(self):
        # Old-format response (pre-reasoning) must not crash the new parser.
        text = json.dumps({'id-1': 'RDS Proxy'})
        assert claude_helper._parse_guess_with_reasoning(text, 'label') == {}

    def test_unparseable_json_returns_empty_dict(self):
        assert claude_helper._parse_guess_with_reasoning('not json at all', 'label') == {}

    def test_none_text_returns_empty_dict(self):
        assert claude_helper._parse_guess_with_reasoning(None, 'label') == {}

    def test_fenced_code_block_is_tolerated(self):
        text = '```json\n' + json.dumps({'id-1': {'label': 'X', 'reasoning': 'Y'}}) + '\n```'
        result = claude_helper._parse_guess_with_reasoning(text, 'label')
        assert result == {'id-1': {'label': 'X', 'reasoning': 'Y'}}


class TestClassifyEnisEndToEnd:
    def test_returns_label_and_reasoning(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'eni-1': {'label': 'RDS Proxy', 'reasoning': "Description contains 'RDSProxy'."},
        }))
        result = claude_helper.classify_enis([{'eni_id': 'eni-1', 'description': 'RDSProxyInterface'}])
        assert result == {'eni-1': {'label': 'RDS Proxy', 'reasoning': "Description contains 'RDSProxy'."}}

    def test_empty_input_short_circuits_without_calling_claude(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('must not call Claude with no input')))
        assert claude_helper.classify_enis([]) == {}


class TestGuessExternalSourcesEndToEnd:
    def test_returns_guess_and_reasoning(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'sgr-1': {'guess': 'home access for Alice Chen', 'reasoning': "Description reads 'Alice's home IP'."},
        }))
        result = claude_helper.guess_external_sources([{'rule_id': 'sgr-1', 'description': "Alice's home IP"}])
        assert result == {'sgr-1': {'guess': 'home access for Alice Chen',
                                     'reasoning': "Description reads 'Alice's home IP'."}}

    def test_empty_input_short_circuits_without_calling_claude(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('must not call Claude with no input')))
        assert claude_helper.guess_external_sources([]) == {}


class TestSuggestRuleDescriptionsEndToEnd:
    def test_returns_description_and_reasoning(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'sgr-1': {'description': 'SSH from bastion', 'reasoning': 'Port 22 is the well-known SSH port.'},
        }))
        result = claude_helper.suggest_rule_descriptions([{'rule_id': 'sgr-1', 'from_port': 22, 'to_port': 22}])
        assert result == {'sgr-1': {'description': 'SSH from bastion',
                                     'reasoning': 'Port 22 is the well-known SSH port.'}}

    def test_empty_input_short_circuits_without_calling_claude(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('must not call Claude with no input')))
        assert claude_helper.suggest_rule_descriptions([]) == {}


class TestParsePostureResponse:
    def test_parses_well_formed_full_response(self):
        text = json.dumps({
            'severities': {
                'sg_allows_all:sgr-1': {'severity': 'critical', 'explanation': 'Postgres open to a public ALB.'},
            },
            'reachability': {'verdict': 'internet-exposed', 'explanation': 'Public ALB attached.'},
            'remediation': {'top_fix': 'Restrict sgr-1 to the ALB security group.', 'summary': 'Overall picture.'},
            'additional_risks': [
                {'rule_id': 'sgr-2', 'concern': 'Broad internal CIDR on an admin port.',
                 'severity': 'medium', 'reasoning': 'Covers 10.0.0.0/8.'},
            ],
        })
        result = claude_helper._parse_posture_response(text)
        assert result['severities']['sg_allows_all:sgr-1']['severity'] == 'critical'
        assert result['reachability']['verdict'] == 'internet-exposed'
        assert result['remediation']['top_fix'] == 'Restrict sgr-1 to the ALB security group.'
        assert result['additional_risks'][0]['rule_id'] == 'sgr-2'

    def test_missing_sections_are_simply_absent(self):
        text = json.dumps({'severities': {'k': {'severity': 'low'}}})
        result = claude_helper._parse_posture_response(text)
        assert 'severities' in result
        assert 'reachability' not in result
        assert 'remediation' not in result
        assert 'additional_risks' not in result

    def test_empty_severities_dict_is_dropped(self):
        text = json.dumps({'severities': {}})
        assert claude_helper._parse_posture_response(text) == {}

    def test_malformed_severity_entry_is_skipped_not_crashing(self):
        text = json.dumps({'severities': {
            'k1': 'not-a-dict',
            'k2': {'explanation': 'no severity field'},
            'k3': {'severity': 'high', 'explanation': 'fine'},
        }})
        result = claude_helper._parse_posture_response(text)
        assert list(result['severities']) == ['k3']

    def test_additional_risk_missing_required_fields_is_dropped(self):
        text = json.dumps({'additional_risks': [
            {'rule_id': 'sgr-1'},  # no concern
            {'concern': 'no rule_id'},
            {'rule_id': 'sgr-2', 'concern': 'valid one', 'severity': 'low'},
        ]})
        result = claude_helper._parse_posture_response(text)
        assert len(result['additional_risks']) == 1
        assert result['additional_risks'][0]['rule_id'] == 'sgr-2'

    def test_reachability_without_verdict_is_dropped(self):
        text = json.dumps({'reachability': {'explanation': 'no verdict key'}})
        assert claude_helper._parse_posture_response(text) == {}

    def test_unparseable_json_returns_empty_dict(self):
        assert claude_helper._parse_posture_response('not json') == {}

    def test_top_level_non_dict_returns_empty_dict(self):
        assert claude_helper._parse_posture_response(json.dumps(['a', 'list'])) == {}


class TestAnalyzeSecurityPostureEndToEnd:
    def test_returns_parsed_response(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda model, system, user: json.dumps({
            'severities': {'sg_allows_all:sgr-1': {'severity': 'critical', 'explanation': 'exposed DB'}},
        }))
        result = claude_helper.analyze_security_posture({
            'findings': [{'finding_key': 'sg_allows_all:sgr-1'}],
            'exposure_signals': {'is_unused': False},
        })
        assert result['severities']['sg_allows_all:sgr-1']['severity'] == 'critical'

    def test_empty_context_short_circuits_without_calling_claude(self, monkeypatch):
        monkeypatch.setattr(claude_helper, '_call', lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('must not call Claude with no findings and no exposure signals')))
        assert claude_helper.analyze_security_posture({'findings': [], 'exposure_signals': None}) == {}

    def test_system_prompt_carries_the_anti_injection_notice(self, monkeypatch):
        captured = {}

        def fake_call(model, system, user):
            captured['system'] = system
            return '{}'

        monkeypatch.setattr(claude_helper, '_call', fake_call)
        claude_helper.analyze_security_posture({
            'findings': [{'finding_key': 'k'}], 'exposure_signals': {'is_unused': False},
        })
        assert 'untrusted' in captured['system'].lower()
        assert 'not instructions' in captured['system'].lower()

    def test_system_prompt_states_the_floor_cannot_be_lowered(self, monkeypatch):
        captured = {}

        def fake_call(model, system, user):
            captured['system'] = system
            return '{}'

        monkeypatch.setattr(claude_helper, '_call', fake_call)
        claude_helper.analyze_security_posture({
            'findings': [{'finding_key': 'k'}], 'exposure_signals': {'is_unused': False},
        })
        assert 'floor' in captured['system'].lower()
        assert '22' in captured['system']
