"""LLM-as-judge scoring for the free-text this tool has Claude produce
(severity explanations, remediation, rule-description suggestions, ENI
labels, external-IP guesses). This is judgment about judgment — a model
grading another model's output — so unlike evals/deterministic.py and
evals/floor_guarantee.py it needs a real API call and isn't part of normal
CI; see run_live_evals.py.

Rubric, each scored 1-5:
  - accurate:   states nothing false about the facts it was actually given.
  - grounded:   cites only facts present in the input. Inventing an
                attachment, a port, a vendor, or any other fact not in the
                input is a hard fail — tracked separately as
                grounding_failure regardless of the numeric score, since a
                single fabricated fact matters more than an average.
  - specific:   names the actual port/service/exposure/resource, not a
                generic restatement of the finding.
  - calibrated: the language's urgency matches the assigned severity — a
                'critical' finding described in throwaway language, or a
                'low' one in alarming language, scores low here.
"""
import json

from sgtree import claude_helper

RUBRIC_KEYS = ('accurate', 'grounded', 'specific', 'calibrated')


def _clean_score(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if 1 <= v <= 5 else None


def _parse_judge_response(text, expected_ids):
    data = claude_helper._parse_json_object(text)
    if not isinstance(data, dict):
        return {}
    out = {}
    for item_id in expected_ids:
        v = data.get(item_id)
        if not isinstance(v, dict):
            continue
        scores = {k: _clean_score(v.get(k)) for k in RUBRIC_KEYS}
        if any(s is None for s in scores.values()):
            continue
        out[item_id] = {
            'scores': scores,
            'grounding_failure': bool(v.get('grounding_failure')),
            'notes': v.get('notes') if isinstance(v.get('notes'), str) else '',
        }
    return out


def judge_batch(items, model=claude_helper.DEFAULT_MODEL):
    """items: list of {id, kind, input_facts (dict), output_text (str)}.
    kind is a free-form label like 'severity_explanation', 'remediation',
    'rule_description_suggestion', 'eni_label', 'external_ip_guess' — shown
    to the judge for context, not otherwise interpreted.

    Returns {id: {'scores': {accurate, grounded, specific, calibrated} (each
    1-5), 'grounding_failure': bool, 'notes': str}} for every item the judge
    could score; items it couldn't (malformed response) are simply absent.
    """
    if not items:
        return {}

    lines = [json.dumps({
        'id':           item['id'],
        'kind':         item['kind'],
        'input_facts':  item['input_facts'],
        'output_text':  item['output_text'],
    }) for item in items]

    system = (
        "You are grading short pieces of text an AI security tool generated "
        "about AWS security group rules, each grounded in a specific set of "
        "input facts you're also given. Score each on four axes, 1 (fails) "
        "to 5 (excellent):\n"
        "- accurate: states nothing false about the input_facts.\n"
        "- grounded: cites only facts present in input_facts — inventing an "
        "attachment, port, vendor, or any other fact not present is a hard "
        "grounding failure (still score 1-5, but also set "
        "grounding_failure=true).\n"
        "- specific: names the actual port/service/exposure/resource from "
        "input_facts, not a generic restatement of the finding.\n"
        "- calibrated: for text describing a severity (kind includes "
        "'severity' or 'risk'), the urgency of the language matches the "
        "assigned severity in input_facts (a 'critical' finding described "
        "casually, or a 'low' one described alarmingly, scores low here). "
        "For text with no associated severity (e.g. an ENI label), score "
        "calibrated on tone matching confidence — a guess stated as fact "
        "when input_facts show weak evidence scores low.\n\n"
        "Respond with ONLY a JSON object mapping id -> "
        '{"accurate": 1-5, "grounded": 1-5, "specific": 1-5, "calibrated": 1-5, '
        '"grounding_failure": true|false, "notes": "one sentence on the worst issue, or empty if none"}, '
        "no other text, no markdown code fences."
    )
    user_content = "Items to grade (one JSON object per line):\n" + "\n".join(lines)

    text = claude_helper._call(model, system, user_content)
    return _parse_judge_response(text, {item['id'] for item in items})


def summarize(scored):
    """scored: the dict judge_batch returns. Returns {axis: average_score}
    plus 'grounding_failure_count' and 'n' — the numbers a report prints."""
    n = len(scored)
    if n == 0:
        return {'n': 0, 'grounding_failure_count': 0, **{k: 0.0 for k in RUBRIC_KEYS}}
    averages = {k: sum(v['scores'][k] for v in scored.values()) / n for k in RUBRIC_KEYS}
    return {
        'n': n,
        'grounding_failure_count': sum(1 for v in scored.values() if v['grounding_failure']),
        **averages,
    }
