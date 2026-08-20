#!/usr/bin/env python3
"""Runs the full eval suite and writes evals/EVAL_REPORT.md.

    python -m evals.run_live_evals                  # full run, needs ANTHROPIC_API_KEY
    python -m evals.run_live_evals --offline-only    # deterministic + floor guarantee only, no API key
    python -m evals.run_live_evals --model claude-opus-5
    python -m evals.run_live_evals --out evals/EVAL_REPORT.md

The offline part (deterministic checks precision/recall, the severity-floor
guarantee) always runs and needs no credentials — it's also what
tests/test_evals_deterministic.py and tests/test_evals_floor_guarantee.py
run on every PR. This script adds the live model evals (AI severity
accuracy, LLM-as-judge, adversarial injection resistance) on top and writes
the combined result to disk, since those need a real ANTHROPIC_API_KEY and
cost real money — they're not run automatically on every PR (see
.github/workflows/evals.yml, which is workflow_dispatch-gated for exactly
that reason).
"""
import argparse
import sys

from evals import adversarial, deterministic, floor_guarantee, judge, live_severity, report
from evals.fixtures import FIXTURES
from sgtree import claude_helper


def _collect_judge_items(severity_result):
    """Judge items from the live severity run's own explanations — grading
    the actual free text this eval suite produced, not a hand-picked sample."""
    items = []
    for row in severity_result['results']:
        if not row.get('severity_explanation'):
            continue
        items.append({
            'id': f"severity:{row['fixture']}:{row['finding_key']}",
            'kind': 'severity_explanation',
            'input_facts': {'finding_key': row['finding_key'], 'assigned_severity': row['actual_severity']},
            'output_text': row['severity_explanation'],
        })
    return items


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--offline-only', action='store_true',
                         help='Skip the live model evals (severity accuracy, judge, adversarial). '
                              'No ANTHROPIC_API_KEY needed.')
    parser.add_argument('--model', default=claude_helper.DEFAULT_MODEL,
                         help=f'Model for the live evals (default: {claude_helper.DEFAULT_MODEL}).')
    parser.add_argument('--out', default='evals/EVAL_REPORT.md', help='Where to write the report.')
    args = parser.parse_args()

    print("Running offline evals (deterministic checks, severity floor guarantee)...", file=sys.stderr)
    det_per_check, det_totals, det_mismatches = deterministic.score(FIXTURES)
    floor_violations = floor_guarantee.check(FIXTURES)
    print(f"  deterministic: precision={det_totals['precision']:.3f} recall={det_totals['recall']:.3f}",
          file=sys.stderr)
    print(f"  floor guarantee violations: {len(floor_violations)}", file=sys.stderr)

    severity_result = judge_summary = injection_result = grounding_result = None

    if not args.offline_only:
        print(f"\nRunning live model evals against {args.model} (this calls the real API)...", file=sys.stderr)

        print("  AI severity accuracy...", file=sys.stderr)
        severity_result = live_severity.run(FIXTURES, model=args.model)
        print(f"    exact_match={severity_result['exact_match_accuracy']:.3f} "
              f"within_one_level={severity_result['within_one_level_accuracy']:.3f} "
              f"floor_violations(unclamped)={severity_result['floor_violations']}", file=sys.stderr)

        print("  LLM-as-judge on severity explanations...", file=sys.stderr)
        judge_items = _collect_judge_items(severity_result)
        scored = judge.judge_batch(judge_items, model=args.model)
        judge_summary = judge.summarize(scored)
        print(f"    n={judge_summary['n']} grounding_failures={judge_summary['grounding_failure_count']}",
              file=sys.stderr)

        print("  Adversarial: injection resistance...", file=sys.stderr)
        injection_result = adversarial.run_injection_resistance(model=args.model)
        print(f"    resisted={injection_result['resisted']}/{injection_result['n']}", file=sys.stderr)

        print("  Adversarial: external-IP grounding trap...", file=sys.stderr)
        grounding_result = adversarial.run_grounding_trap(model=args.model)
        print(f"    followed_rdap={grounding_result['followed_rdap']}/{grounding_result['n']}", file=sys.stderr)

    md = report.render_full(
        det_per_check, det_totals, det_mismatches, floor_violations, len(FIXTURES),
        severity_result=severity_result, judge_summary=judge_summary,
        injection_result=injection_result, grounding_result=grounding_result, model=args.model,
    )
    with open(args.out, 'w') as f:
        f.write(md)
    print(f"\nWrote {args.out}", file=sys.stderr)

    if floor_violations:
        print("\nFAIL: severity floor guarantee was violated — see report.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
