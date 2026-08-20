"""Optional Claude-assisted enrichment.

Three things fall back to Claude, each batched into a single API call per
tree run to keep cost/latency down:
  - classify_enis: guess the owning AWS resource for an ENI whose
    Description didn't match any of the deterministic patterns in aws.py.
  - suggest_rule_descriptions: propose a description for undocumented rules
    on the root SG (only the root SG gets checks run against it at all).
  - guess_external_sources: for a root-SG rule whose CIDR is external and
    doesn't match anything in this account, guess what it might be (a known
    vendor's published IP range, a CDN, etc.) from the rule's own
    description — the account has no visibility into who owns an external
    IP, so this is only ever a guess grounded in text the rule's author left.

All three degrade silently to "unavailable" (empty dict) if the anthropic
package isn't installed or no credentials are configured — this tool must
still work fully without Claude, just with fewer resolved labels/suggestions.
"""
import json
import sys

DEFAULT_MODEL = 'claude-opus-5'

_client = None
_client_checked = False


def _get_client():
    global _client, _client_checked
    if _client_checked:
        return _client
    _client_checked = True
    try:
        import anthropic
    except ImportError:
        print("note: 'anthropic' package not installed — skipping Claude-assisted "
              "enrichment (pip install anthropic to enable).", file=sys.stderr)
        return None
    try:
        _client = anthropic.Anthropic()
    except Exception as e:
        print(f"note: could not initialize Claude client ({e}) — skipping "
              f"Claude-assisted enrichment.", file=sys.stderr)
        _client = None
    return _client


def _call(model, system, user_content):
    """One Claude call, tolerant of any failure. Returns the response text or None."""
    client = _get_client()
    if client is None:
        return None
    import anthropic
    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system,
            messages=[{'role': 'user', 'content': user_content}],
        )
    except anthropic.AuthenticationError:
        print("note: Claude API authentication failed — skipping Claude-assisted "
              "enrichment for the rest of this run.", file=sys.stderr)
        global _client
        _client = None
        return None
    except Exception as e:
        print(f"note: Claude API call failed ({type(e).__name__}: {e}) — "
              f"continuing without it.", file=sys.stderr)
        return None
    for block in response.content:
        if block.type == 'text':
            return block.text
    return None


def _parse_json_object(text):
    if not text:
        return {}
    text = text.strip()
    # Tolerate a fenced code block even though we ask for bare JSON.
    if text.startswith('```'):
        text = text.strip('`')
        if text.startswith('json'):
            text = text[4:]
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}


def classify_enis(enis, model=DEFAULT_MODEL):
    """enis: list of dicts with eni_id, description, interface_type,
    requester_id. Returns {eni_id: short guess string} for entries Claude
    could make a reasonable guess about; omits ones it can't."""
    if not enis:
        return {}

    lines = []
    for e in enis:
        lines.append(json.dumps({
            'eni_id':         e['eni_id'],
            'description':    e.get('description') or '',
            'interface_type': e.get('interface_type') or '',
            'requester_id':   e.get('requester_id') or '',
        }))

    system = (
        "You are helping an AWS security auditor identify what AWS resource or "
        "service owns each given Elastic Network Interface (ENI), based on its "
        "raw metadata. AWS's managed services often stamp identifying text into "
        "the ENI's Description or leave clues in RequesterId/InterfaceType. "
        "For each ENI, give your single best short guess (max ~8 words) at the "
        "owning resource/service, e.g. 'RDS Proxy', 'ElastiCache Redis node', "
        "'AWS Transfer Family server', 'QuickSight VPC connection'. "
        "If you genuinely cannot infer anything beyond 'unknown', omit that "
        "eni_id from your output rather than guessing wildly. "
        "Respond with ONLY a JSON object mapping eni_id -> guess string, no "
        "other text, no markdown code fences."
    )
    user_content = "ENIs to classify (one JSON object per line):\n" + "\n".join(lines)

    text = _call(model, system, user_content)
    result = _parse_json_object(text)
    return {k: v for k, v in result.items() if isinstance(v, str) and v.strip()}


def guess_external_sources(rules, model=DEFAULT_MODEL):
    """rules: list of dicts with rule_id, cidr, description, direction,
    protocol, from_port, to_port — root-SG rules whose CIDR resolved
    'external' with no match against this account's own public IPs. Returns
    {rule_id: guess string} for entries Claude could make a reasonable guess
    about from the rule's description text; omits ones it can't."""
    if not rules:
        return {}

    lines = []
    for r in rules:
        lines.append(json.dumps({
            'rule_id':     r['rule_id'],
            'cidr':        r.get('cidr') or '',
            'description': r.get('description') or '',
            'direction':   r.get('direction') or '',
            'protocol':    r.get('protocol') or '',
            'from_port':   r.get('from_port'),
            'to_port':     r.get('to_port'),
        }))

    system = (
        "You are helping an AWS security auditor understand security group rules "
        "whose source/destination is a public IP range outside this AWS account "
        "(not one of the account's own resources). For each rule, use its "
        "description text — and, if you happen to recognize the CIDR itself as a "
        "published range for a well-known provider, that too — to guess what the "
        "range likely belongs to, e.g. 'Datadog monitoring agent', 'GitHub Actions "
        "runner range (per description)', 'corporate office VPN egress (per "
        "description)', 'Cloudflare edge network'. Ground the guess in the "
        "description whenever one is given — do not invent a vendor the "
        "description doesn't support. If the description is empty or unhelpful "
        "and the CIDR isn't a range you recognize, omit that rule_id from your "
        "output rather than guessing wildly. Respond with ONLY a JSON object "
        "mapping rule_id -> guess string, no other text, no markdown code fences."
    )
    user_content = "External rules to guess at (one JSON object per line):\n" + "\n".join(lines)

    text = _call(model, system, user_content)
    result = _parse_json_object(text)
    return {k: v for k, v in result.items() if isinstance(v, str) and v.strip()}


def suggest_rule_descriptions(rules, model=DEFAULT_MODEL):
    """rules: list of dicts with rule_id, sg_name, direction, protocol,
    from_port, to_port, cidr, referenced_sg_name. Returns
    {rule_id: suggested description string}."""
    if not rules:
        return {}

    lines = []
    for r in rules:
        lines.append(json.dumps({
            'rule_id':             r['rule_id'],
            'sg_name':             r.get('sg_name') or '',
            'direction':           r.get('direction') or '',
            'protocol':            r.get('protocol') or '',
            'from_port':           r.get('from_port'),
            'to_port':             r.get('to_port'),
            'cidr':                r.get('cidr') or '',
            'referenced_sg_name':  r.get('referenced_sg_name') or '',
        }))

    system = (
        "You are helping an AWS security auditor fill in missing descriptions "
        "on security group rules, based on the rule's protocol/ports/source. "
        "For each rule, propose a short (max ~10 words), specific description "
        "of what the rule is likely for, e.g. 'HTTPS from internet', "
        "'Postgres from app tier', 'SSH from bastion SG'. Infer intent from "
        "well-known ports (22=SSH, 443=HTTPS, 5432=Postgres, etc.) where "
        "possible; otherwise describe it plainly (e.g. 'TCP 8080 from 10.0.0.0/8'). "
        "Respond with ONLY a JSON object mapping rule_id -> suggested "
        "description string, no other text, no markdown code fences."
    )
    user_content = "Rules needing descriptions (one JSON object per line):\n" + "\n".join(lines)

    text = _call(model, system, user_content)
    result = _parse_json_object(text)
    return {k: v for k, v in result.items() if isinstance(v, str) and v.strip()}
