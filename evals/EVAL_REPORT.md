# sg-scanner eval report

Generated 2026-08-20 00:51 UTC.
## Deterministic checks — precision / recall

Guards regression on the four checks — a rule-based system, so this should read 1.0/1.0; its job is catching a silent behavior change, not measuring judgment. Scored against 26 synthetic fixtures — see `evals/fixtures.py`.

| check | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| sg_allows_all | 16 | 0 | 0 | 100.0% | 100.0% |
| sg_rule_no_description | 3 | 0 | 0 | 100.0% | 100.0% |
| sg_stale_rule | 1 | 0 | 0 | 100.0% | 100.0% |
| sg_unused | 4 | 0 | 0 | 100.0% | 100.0% |
| **total** | 24 | 0 | 0 | 100.0% | 100.0% |

## Severity floor guarantee — zero critical misses

For every critical-port allow-all fixture, `severity.clamp()` is tested against a battery of hostile/malformed AI responses (including literal prompt-injection text as the claimed severity) and must never let the result fall below the required floor. This is a code guarantee, not a model behavior — it's exhaustive and always either 0 or a bug.

✅ **0 violations**


## Live model evals

_Not run in this report — requires `ANTHROPIC_API_KEY` and `python -m evals.run_live_evals`. The offline evals above (deterministic checks + floor guarantee) never need one and always run in CI._
