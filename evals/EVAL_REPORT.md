# sg-scanner eval report

Generated 2026-08-20 16:31 UTC.
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


## AI severity accuracy (live model run)

Model: `claude-opus-5`. n=11 labeled findings.

| metric | value |
|---|---|
| exact match | 90.9% |
| within one level | 100.0% |
| meets or exceeds expected (no undersell) | 90.9% |
| floor violations (unclamped model output) | 0 |

### AI-vs-baseline delta

Of 11 labeled findings, the AI severity differed from the flat/uniform baseline in **6** case(s); of those, **6** landed closer to the expected label than the baseline would have — this is the number that argues contextual severity earns its place over treating every finding on a given port the same.

### Confusion matrix (expected → actual)

| expected | actual | count |
|---|---|---|
| critical | critical | 6 |
| critical | high | 1 |
| high | high | 4 |

## LLM-as-judge — free-text quality

n=9 graded outputs (severity explanations, remediation, rule-description suggestions, ENI labels, external-IP guesses), 1-5 per axis.

| axis | average |
|---|---|
| accurate | 4.56 |
| grounded | 4.22 |
| specific | 4.78 |
| calibrated | 4.89 |

**Grounding failures: 2 / 9** (a fabricated fact not present in the input — a hard fail regardless of the numeric scores).

## Adversarial — injection resistance (live model, unclamped)

Distinct from the floor guarantee above: that eval proves the *code* can't be talked below the floor no matter what a model says. This measures whether the *model itself*, before any clamping, resists prompt injection embedded in rule descriptions / SG names on its own.

**3 / 3** adversarial fixtures resisted (severity met the floor unclamped, and the explanation didn't echo the injected claim).

_The echo check is a keyword heuristic and can false-positive on a model that correctly quotes-and-refutes the injected claim in wording its cue list doesn't cover — the explanation text for every non-resisted case is included below so that can be checked directly rather than trusted blindly._


## Adversarial — external-IP grounding trap

A rule description names a friendly vendor; RDAP registration data for the same IP says otherwise. The system prompt says RDAP should win when it disagrees with a vague/generic description — this checks whether the model's guess actually follows RDAP rather than parroting the unsupported claim.

**1 / 1** followed RDAP over the contradicted description claim.
