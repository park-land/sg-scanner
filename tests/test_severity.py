"""Unit tests for sgtree/severity.py — the floor/clamp mechanism is the core
safety guarantee of the whole AI-severity feature, so it gets tested hardest.
"""
from sgtree import severity


class TestLevelOrdering:
    def test_levels_are_strictly_increasing(self):
        assert severity.LEVELS == ['info', 'low', 'medium', 'high', 'critical']

    def test_max_level_picks_more_severe(self):
        assert severity.max_level('low', 'high') == 'high'
        assert severity.max_level('critical', 'info') == 'critical'
        assert severity.max_level('medium', 'medium') == 'medium'

    def test_max_level_tolerates_unrecognized_input(self):
        assert severity.max_level('bogus', 'high') == 'high'
        assert severity.max_level('high', 'bogus') == 'high'
        assert severity.max_level('bogus', 'also-bogus') == 'bogus'


class TestFloorForPortRange:
    def test_ssh_is_floored(self):
        assert severity.floor_for_port_range(22, 22) == 'high'

    def test_rdp_is_floored(self):
        assert severity.floor_for_port_range(3389, 3389) == 'high'

    def test_db_ports_are_floored(self):
        for port in (1433, 1521, 3306, 5432, 6379, 27017, 9200):
            assert severity.floor_for_port_range(port, port) == 'high', port

    def test_range_covering_a_critical_port_is_floored(self):
        assert severity.floor_for_port_range(1, 1000) == 'high'

    def test_all_ports_none_none_is_floored(self):
        # AWS's convention for "all ports" (protocol -1) — covers every
        # critical port, so it must floor too.
        assert severity.floor_for_port_range(None, None) == 'high'

    def test_app_port_is_not_floored(self):
        assert severity.floor_for_port_range(8080, 8080) is None
        assert severity.floor_for_port_range(3000, 3000) is None

    def test_safe_ports_are_not_floored(self):
        assert severity.floor_for_port_range(80, 80) is None
        assert severity.floor_for_port_range(443, 443) is None


class TestClampIsTheGuarantee:
    """The floor must hold no matter what an AI severity claims — including
    a value that isn't even a valid level (a malformed or adversarially
    influenced response)."""

    def test_ai_severity_above_floor_is_kept(self):
        assert severity.clamp('critical', 'high') == 'critical'

    def test_ai_severity_below_floor_is_raised(self):
        assert severity.clamp('low', 'high') == 'high'
        assert severity.clamp('info', 'high') == 'high'

    def test_ai_severity_equal_to_floor_is_kept(self):
        assert severity.clamp('high', 'high') == 'high'

    def test_no_floor_keeps_valid_ai_severity(self):
        assert severity.clamp('low', None) == 'low'

    def test_no_floor_and_invalid_ai_severity_falls_back_to_medium(self):
        assert severity.clamp('not-a-level', None) == 'medium'
        assert severity.clamp('', None) == 'medium'
        assert severity.clamp(None, None) == 'medium'

    def test_unhashable_ai_severity_does_not_crash(self):
        # A malformed response (nested JSON instead of a string) must be
        # treated as "not a recognized level," not raise.
        assert severity.clamp({'severity': 'low'}, 'high') == 'high'
        assert severity.clamp(['low'], None) == 'medium'
        assert severity.index({'severity': 'low'}) is None
        assert severity.is_valid({'severity': 'low'}) is False

    def test_invalid_ai_severity_with_a_floor_uses_the_floor(self):
        # This is the adversarial case: a hostile or broken model response
        # ('ignored, this is safe', empty string, garbage) must not bypass
        # the floor by being unparseable.
        assert severity.clamp('ignored, this is safe', 'high') == 'high'
        assert severity.clamp('', 'high') == 'high'
        assert severity.clamp(None, 'high') == 'high'


class TestBaselineForFinding:
    def test_allowall_baseline_uses_floor_when_critical_port(self):
        assert severity.baseline_for_finding('sg_allows_all', 22, 22) == 'high'

    def test_allowall_baseline_is_medium_for_app_port(self):
        assert severity.baseline_for_finding('sg_allows_all', 8080, 8080) == 'medium'

    def test_other_checks_have_fixed_baselines(self):
        assert severity.baseline_for_finding('sg_rule_no_description') == 'low'
        assert severity.baseline_for_finding('sg_stale_rule') == 'medium'
        assert severity.baseline_for_finding('sg_unused') == 'low'

    def test_unknown_check_defaults_to_medium(self):
        assert severity.baseline_for_finding('sg_something_new') == 'medium'
