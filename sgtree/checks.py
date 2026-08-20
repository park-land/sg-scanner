"""The same four checks sg_checks.py runs account-wide, applied per-node as
the tree is traversed. Signatures are adapted (no pre-fetched existing_ids
set — a referenced SG's existence is established by actually trying to fetch
it during traversal) but the pass/fail logic is unchanged.
"""

SAFE_PORTS = {80, 443}

SG_RULE_CHECK_IDS = frozenset({'sg_allows_all', 'sg_rule_no_description', 'sg_stale_rule'})
SG_CHECK_IDS      = frozenset({'sg_unused'})
ALL_CHECK_IDS     = SG_RULE_CHECK_IDS | SG_CHECK_IDS


def check_allowall(rule, sg_name):
    if rule.get('IsEgress'):
        return None
    allows_all = rule.get('CidrIpv4') == '0.0.0.0/0' or rule.get('CidrIpv6') == '::/0'
    if not allows_all:
        return None
    from_port = rule.get('FromPort', 0)
    to_port   = rule.get('ToPort', 65535)
    if any(from_port <= p <= to_port for p in SAFE_PORTS):
        return None
    port_str = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
    return 'sg_allows_all', f'{sg_name} allows all ingress on {port_str}'


def check_rule_label(rule, sg_name):
    if not rule.get('Description'):
        direction = 'egress' if rule.get('IsEgress') else 'ingress'
        return 'sg_rule_no_description', f'{sg_name} has a {direction} rule with no description'
    return None


def check_stale_rule(rule, sg_name, referenced_sg_exists):
    """referenced_sg_exists: True/False/None (None = same-account reference we
    haven't resolved, e.g. cross-region/cross-account or lookup error)."""
    ref = rule.get('ReferencedGroupInfo', {})
    ref_id = ref.get('GroupId') if ref else None
    if ref_id and referenced_sg_exists is False:
        return 'sg_stale_rule', f'{sg_name} references non-existent SG {ref_id}'
    return None


def check_unused_sg(sg_id, sg_name, is_default, attachments):
    if is_default:
        return None
    if not attachments:
        return 'sg_unused', f'{sg_name} ({sg_id}) is not referenced by any resource or service configuration'
    return None
