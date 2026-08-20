"""Live AI-severity eval — replays evals/fixtures.py through the real
sgtree.tree machinery (BFS collection is bypassed; this drives
assess_severity_and_posture directly against each fixture's rules/
attachments/public IPs, exactly like a real report would) and scores the
result against each fixture's expected_min_severity. Needs
ANTHROPIC_API_KEY; not part of normal CI — see run_live_evals.py and
.github/workflows/evals.yml.

expected_min_severity is "the least severe rating a competent reviewer would
accept as correct" — not a single exact target, since real judgment can
reasonably escalate (e.g. 'high' vs 'critical' for an exposed DB) based on
context a fixture's static labels don't fully capture. Three views on the
same data, from strictest to most permissive:
  - exact_match: final severity == expected_min_severity exactly.
  - within_one_level: |index(final) - index(expected_min)| <= 1.
  - meets_or_exceeds: index(final) >= index(expected_min) — accepts a
    defensible escalation as correct, only flags an actual undersell.

floor_violations should always be 0 — evals/floor_guarantee.py already
proves this exhaustively offline against a hostile-response battery; this
count is the live-model version of the same check (did the *real* model
response, once clamped, ever need clamping upward on one of these fixtures —
informative, not a pass/fail gate the way the offline eval is).

baseline_delta measures the actual point of the feature: how often does the
AI's contextual severity differ from the flat/uniform baseline
(severity.baseline_for_finding, the pre-AI world where every sg_allows_all
finding on a given port class gets the same rating regardless of exposure),
and in those cases, does the AI's answer land closer to expected_min than
the baseline does. That "closer and different" count is the number that
argues the AI severity pass earns its place over the flat baseline.
"""
from collections import Counter

from sgtree import claude_helper, exposure, severity
from sgtree.tree import SGEdge, SGNode


def _node_from_fixture(fixture):
    node = SGNode(sg_id='sg-eval', depth=0, status='found', name=fixture.sg_name,
                  description=fixture.sg_description, is_default=fixture.is_default)
    node.rules = fixture.rules
    node.attachments = fixture.attachments
    return node


def _run_posture(fixture, model):
    """Mirrors sgtree.tree.assess_severity_and_posture for one fixture,
    without needing a full BFS-collected graph (fixtures are single-SG)."""
    from sgtree import checks

    node = _node_from_fixture(fixture)
    rule_by_id = {r.get('SecurityGroupRuleId'): r for r in node.rules}

    for rule in node.rules:
        rid = rule.get('SecurityGroupRuleId', 'r?')
        hit = checks.check_allowall(rule, fixture.sg_name)
        if hit:
            node.findings.append({'sg_id': node.sg_id, 'check': hit[0], 'detail': hit[1],
                                   'resource_type': 'security_group_rule', 'resource_id': rid})
        hit = checks.check_rule_label(rule, fixture.sg_name)
        if hit:
            node.findings.append({'sg_id': node.sg_id, 'check': hit[0], 'detail': hit[1],
                                   'resource_type': 'security_group_rule', 'resource_id': rid})

    hit_unused = checks.check_unused_sg('sg-eval', fixture.sg_name, fixture.is_default, node.attachments)
    if hit_unused:
        node.findings.append({'sg_id': node.sg_id, 'check': hit_unused[0], 'detail': hit_unused[1],
                               'resource_type': 'security_group', 'resource_id': 'SG'})

    for f in node.findings:
        rule = rule_by_id.get(f['resource_id'])
        f['_finding_key'] = f"{f['check']}:{f['resource_id']}"
        f['severity'] = severity.baseline_for_finding(
            f['check'], rule.get('FromPort') if rule else None, rule.get('ToPort') if rule else None)

    signals = exposure.compute_signals(node, fixture.public_ips)
    det_verdict, _ = exposure.deterministic_verdict(signals)

    from sgtree.tree import build_posture_context
    context = build_posture_context(node, {node.sg_id: node}, [], signals, det_verdict)
    posture = claude_helper.analyze_security_posture(context, model=model) or {}

    ai_severities = posture.get('severities', {})
    for f in node.findings:
        rule = rule_by_id.get(f['resource_id'])
        floor = None
        if f['check'] == 'sg_allows_all' and rule is not None:
            floor = severity.floor_for_port_range(rule.get('FromPort'), rule.get('ToPort'))
        ai = ai_severities.get(f['_finding_key'])
        if ai:
            pre_clamp = ai['severity']
            f['severity'] = severity.clamp(pre_clamp, floor)
            f['severity_source'] = 'ai'
            f['severity_explanation'] = ai['explanation']
            f['_floor_violation'] = floor is not None and severity.index(pre_clamp) is not None \
                and severity.index(pre_clamp) < severity.index(floor)
        else:
            f['severity_source'] = 'baseline'
            f['_floor_violation'] = False

    return node.findings


def run(fixtures, model=None):
    model = model or claude_helper.DEFAULT_MODEL
    results = []  # per-finding-key eval rows
    confusion = Counter()
    floor_violations = 0
    baseline_delta_total = 0
    baseline_delta_improved = 0

    for fixture in fixtures:
        findings = _run_posture(fixture, model)
        for f in findings:
            key = (f['check'], f['resource_id'])
            if key not in fixture.expected_min_severity:
                continue
            expected = fixture.expected_min_severity[key]
            actual = f['severity']
            e_idx, a_idx = severity.index(expected), severity.index(actual)

            if f.get('_floor_violation'):
                floor_violations += 1

            rule = next((r for r in fixture.rules if r.get('SecurityGroupRuleId') == f['resource_id']), None)
            baseline = severity.baseline_for_finding(
                f['check'], rule.get('FromPort') if rule else None, rule.get('ToPort') if rule else None)
            if f['severity_source'] == 'ai' and baseline != actual:
                baseline_delta_total += 1
                b_idx = severity.index(baseline)
                if b_idx is not None and e_idx is not None and a_idx is not None:
                    if abs(a_idx - e_idx) < abs(b_idx - e_idx):
                        baseline_delta_improved += 1

            confusion[(expected, actual)] += 1
            results.append({
                'fixture': fixture.name, 'finding_key': f['_finding_key'],
                'expected_min_severity': expected, 'actual_severity': actual,
                'severity_explanation': f.get('severity_explanation'),
                'exact_match': actual == expected,
                'within_one_level': e_idx is not None and a_idx is not None and abs(a_idx - e_idx) <= 1,
                'meets_or_exceeds': e_idx is not None and a_idx is not None and a_idx >= e_idx,
            })

    n = len(results) or 1
    return {
        'n':                       len(results),
        'exact_match_accuracy':    sum(r['exact_match'] for r in results) / n,
        'within_one_level_accuracy': sum(r['within_one_level'] for r in results) / n,
        'meets_or_exceeds_accuracy': sum(r['meets_or_exceeds'] for r in results) / n,
        'floor_violations':        floor_violations,
        'baseline_delta_total':    baseline_delta_total,
        'baseline_delta_improved': baseline_delta_improved,
        'confusion':               dict(confusion),
        'results':                 results,
    }
