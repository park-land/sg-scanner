"""Runs the four deterministic checks against evals/fixtures.py and scores
precision/recall per check. Pure offline computation — no AWS, no Claude —
so this is part of the normal pytest suite (tests/test_evals_deterministic.py)
and runs on every PR. Since the checks are rules, not judgment, this should
score 100% on well-formed fixtures; its real job is catching a regression
that silently changes what a check fires on.
"""
from collections import defaultdict

from sgtree import checks


def run_checks_on_fixture(fixture):
    """Returns the set of (check_id, resource_id) pairs the deterministic
    checks produce for one fixture — the same shape as Fixture.expected_findings."""
    found = set()
    sg_name = fixture.sg_name

    for rule in fixture.rules:
        rule_id = rule.get('SecurityGroupRuleId', 'r?')

        hit = checks.check_allowall(rule, sg_name)
        if hit:
            found.add((hit[0], rule_id))

        hit = checks.check_rule_label(rule, sg_name)
        if hit:
            found.add((hit[0], rule_id))

        if rule.get('ReferencedGroupInfo'):
            hit = checks.check_stale_rule(rule, sg_name, rule.get('_referenced_exists', True))
            if hit:
                found.add((hit[0], rule_id))

    hit = checks.check_unused_sg('SG', sg_name, fixture.is_default, fixture.attachments)
    if hit:
        found.add((hit[0], 'SG'))

    return found


def score(fixtures):
    """Returns (per_check_stats, totals, mismatches).

    per_check_stats: {check_id: {'tp', 'fp', 'fn', 'precision', 'recall'}}
    totals: same shape, aggregated across all checks.
    mismatches: [(fixture_name, kind, check_id, resource_id)] for every
    false positive/negative, kind in ('fp', 'fn') — the detail behind the
    numbers, so a regression is debuggable, not just a dropped percentage.
    """
    stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0})
    mismatches = []

    for fixture in fixtures:
        actual = run_checks_on_fixture(fixture)
        expected = fixture.expected_findings

        for item in actual & expected:
            stats[item[0]]['tp'] += 1
        for item in actual - expected:
            stats[item[0]]['fp'] += 1
            mismatches.append((fixture.name, 'fp', item[0], item[1]))
        for item in expected - actual:
            stats[item[0]]['fn'] += 1
            mismatches.append((fixture.name, 'fn', item[0], item[1]))

    def _finalize(s):
        tp, fp, fn = s['tp'], s['fp'], s['fn']
        s['precision'] = tp / (tp + fp) if (tp + fp) else 1.0
        s['recall'] = tp / (tp + fn) if (tp + fn) else 1.0
        return s

    per_check = {check: _finalize(dict(s)) for check, s in stats.items()}
    totals = _finalize({
        'tp': sum(s['tp'] for s in stats.values()),
        'fp': sum(s['fp'] for s in stats.values()),
        'fn': sum(s['fn'] for s in stats.values()),
    })

    return per_check, totals, mismatches
