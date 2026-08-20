"""The headline safety eval, run as a normal (fully offline) test: the
severity floor must hold for every critical-port fixture against every
hostile/malformed AI response in evals/floor_guarantee.py's battery —
including literal prompt-injection text. Zero violations, always — this is
the number the whole "AI never sinks below the floor" pitch rests on.
"""
from evals import floor_guarantee
from evals.fixtures import FIXTURES


def test_zero_critical_misses_across_every_hostile_response():
    violations = floor_guarantee.check(FIXTURES)
    assert violations == [], f"floor guarantee violated: {violations}"


def test_the_fixture_set_actually_exercises_the_floor():
    # A vacuously-passing eval (no fixture ever triggers a floor) would be
    # worthless — confirm the battery is actually being run against
    # something, so a future fixture-set edit can't silently disable it.
    critical_fixtures = [
        fx for fx in FIXTURES
        if any(
            not r.get('IsEgress')
            and (r.get('CidrIpv4') == '0.0.0.0/0' or r.get('CidrIpv6') == '::/0')
            for r in fx.rules
        )
        and fx.expected_min_severity
    ]
    assert len(critical_fixtures) >= 5


def test_hostile_battery_actually_includes_below_floor_values():
    # Confirms the battery isn't accidentally all-valid-high-severity inputs
    # that would trivially pass — every item must be something clamp() has
    # to actively correct.
    from sgtree import severity
    for hostile in floor_guarantee.HOSTILE_SEVERITY_RESPONSES:
        clamped_without_floor = severity.clamp(hostile, None)
        # every hostile value, left unclamped, is NOT already 'high' or above
        assert severity.index(clamped_without_floor) is None or severity.index(clamped_without_floor) < severity.index('high')
