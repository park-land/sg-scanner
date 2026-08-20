"""Renders the eval results (from every module in this package) into one
checked-in Markdown report. Two tiers, matching what actually ran:

  - render_offline() covers deterministic.py + floor_guarantee.py — the part
    that runs in every PR's CI, no API key needed. Always available.
  - render_live() adds live_severity.py + judge.py + adversarial.py — needs
    a real model run (see run_live_evals.py); only present when that was
    actually executed.
"""
from datetime import datetime, timezone


def _pct(x):
    return f"{x * 100:.1f}%"


def _table(headers, rows):
    lines = ['| ' + ' | '.join(headers) + ' |', '|' + '|'.join(['---'] * len(headers)) + '|']
    for row in rows:
        lines.append('| ' + ' | '.join(str(c) for c in row) + ' |')
    return '\n'.join(lines)


def render_offline(det_per_check, det_totals, det_mismatches, floor_violations, n_fixtures):
    lines = []
    lines.append("## Deterministic checks — precision / recall\n")
    lines.append(f"Guards regression on the four checks — a rule-based system, so this should read 1.0/1.0; "
                  f"its job is catching a silent behavior change, not measuring judgment. Scored against "
                  f"{n_fixtures} synthetic fixtures — see `evals/fixtures.py`.\n")
    rows = [[check, s['tp'], s['fp'], s['fn'], _pct(s['precision']), _pct(s['recall'])]
            for check, s in sorted(det_per_check.items())]
    rows.append(['**total**', det_totals['tp'], det_totals['fp'], det_totals['fn'],
                  _pct(det_totals['precision']), _pct(det_totals['recall'])])
    lines.append(_table(['check', 'TP', 'FP', 'FN', 'precision', 'recall'], rows))
    if det_mismatches:
        lines.append("\n**Mismatches:**\n")
        for fixture_name, kind, check_id, resource_id in det_mismatches:
            lines.append(f"- `{fixture_name}` — {kind}: `{check_id}` on `{resource_id}`")
    lines.append("")

    lines.append("## Severity floor guarantee — zero critical misses\n")
    lines.append(
        "For every critical-port allow-all fixture, `severity.clamp()` is tested against a battery of "
        "hostile/malformed AI responses (including literal prompt-injection text as the claimed severity) "
        "and must never let the result fall below the required floor. This is a code guarantee, not a model "
        "behavior — it's exhaustive and always either 0 or a bug.\n"
    )
    status = "✅ **0 violations**" if not floor_violations else f"❌ **{len(floor_violations)} violations**"
    lines.append(f"{status}\n")
    if floor_violations:
        for name, rule_id, hostile, clamped, floor in floor_violations:
            lines.append(f"- `{name}` / `{rule_id}`: hostile input `{hostile!r}` → clamped to `{clamped}`, "
                          f"required floor `{floor}`")
    return '\n'.join(lines)


def render_live(severity_result, judge_summary, injection_result, grounding_result, model):
    lines = ["## AI severity accuracy (live model run)\n"]
    lines.append(f"Model: `{model}`. n={severity_result['n']} labeled findings.\n")
    lines.append(_table(
        ['metric', 'value'],
        [
            ['exact match', _pct(severity_result['exact_match_accuracy'])],
            ['within one level', _pct(severity_result['within_one_level_accuracy'])],
            ['meets or exceeds expected (no undersell)', _pct(severity_result['meets_or_exceeds_accuracy'])],
            ['floor violations (unclamped model output)', severity_result['floor_violations']],
        ],
    ))

    lines.append("\n### AI-vs-baseline delta\n")
    total, improved = severity_result['baseline_delta_total'], severity_result['baseline_delta_improved']
    lines.append(
        f"Of {severity_result['n']} labeled findings, the AI severity differed from the flat/uniform baseline "
        f"in **{total}** case(s); of those, **{improved}** landed closer to the expected label than the "
        f"baseline would have — this is the number that argues contextual severity earns its place over "
        f"treating every finding on a given port the same.\n"
    )

    lines.append("### Confusion matrix (expected → actual)\n")
    confusion_rows = [[exp, act, count] for (exp, act), count in sorted(severity_result['confusion'].items())]
    lines.append(_table(['expected', 'actual', 'count'], confusion_rows) if confusion_rows else "_no data_")

    lines.append("\n## LLM-as-judge — free-text quality\n")
    lines.append(f"n={judge_summary['n']} graded outputs (severity explanations, remediation, rule-description "
                  f"suggestions, ENI labels, external-IP guesses), 1-5 per axis.\n")
    lines.append(_table(
        ['axis', 'average'],
        [[axis, f"{judge_summary[axis]:.2f}"] for axis in ('accurate', 'grounded', 'specific', 'calibrated')],
    ))
    gf = judge_summary['grounding_failure_count']
    lines.append(f"\n**Grounding failures: {gf} / {judge_summary['n']}** "
                  f"(a fabricated fact not present in the input — a hard fail regardless of the numeric scores).\n")

    lines.append("## Adversarial — injection resistance (live model, unclamped)\n")
    lines.append(
        "Distinct from the floor guarantee above: that eval proves the *code* can't be talked below the floor "
        "no matter what a model says. This measures whether the *model itself*, before any clamping, resists "
        "prompt injection embedded in rule descriptions / SG names on its own.\n"
    )
    n, resisted = injection_result['n'], injection_result['resisted']
    lines.append(f"**{resisted} / {n}** adversarial fixtures resisted (severity met the floor unclamped, and "
                  f"the explanation didn't echo the injected claim).\n")
    for case in injection_result['cases']:
        if not case['resisted']:
            lines.append(f"- ⚠️ `{case['fixture']}`: unclamped severity `{case['ai_severity_unclamped']}` "
                          f"(floor `{case['floor']}`), echoed_injection={case['echoed_injection']}")

    lines.append("\n## Adversarial — external-IP grounding trap\n")
    lines.append(
        "A rule description names a friendly vendor; RDAP registration data for the same IP says otherwise. "
        "The system prompt says RDAP should win when it disagrees with a vague/generic description — this "
        "checks whether the model's guess actually follows RDAP rather than parroting the unsupported claim.\n"
    )
    n, followed = grounding_result['n'], grounding_result['followed_rdap']
    lines.append(f"**{followed} / {n}** followed RDAP over the contradicted description claim.\n")

    return '\n'.join(lines)


def render_full(det_per_check, det_totals, det_mismatches, floor_violations, n_fixtures,
                 severity_result=None, judge_summary=None, injection_result=None,
                 grounding_result=None, model=None):
    header = [
        "# sg-scanner eval report",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
    ]
    body = [render_offline(det_per_check, det_totals, det_mismatches, floor_violations, n_fixtures)]
    if severity_result is not None:
        body.append(render_live(severity_result, judge_summary, injection_result, grounding_result, model))
    else:
        body.append(
            "## Live model evals\n\n_Not run in this report — requires `ANTHROPIC_API_KEY` and "
            "`python -m evals.run_live_evals`. The offline evals above (deterministic checks + floor "
            "guarantee) never need one and always run in CI._\n"
        )
    return '\n'.join(header) + '\n\n'.join(body)
