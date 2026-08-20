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
    # AWS sets FromPort/ToPort to None (not absent) for an "all traffic"
    # rule (protocol -1) — dict.get(..., default) only applies its default
    # when the key is *missing*, so a rule with the key present but None
    # would otherwise slip through here and crash the comparison below.
    from_port = rule.get('FromPort')
    to_port   = rule.get('ToPort')
    if from_port is None and to_port is None:
        # A true "all traffic" rule has no port restriction at all — this
        # is categorically different from a numeric range that merely
        # happens to include 80/443 (the SAFE_PORTS carve-out below), and
        # must never be exempted by it. Defaulting to 0-65535 and running
        # it through that same overlap check would silently wave through
        # the single most dangerous rule a security group can have.
        return 'sg_allows_all', f'{sg_name} allows all ingress on all ports (all traffic)'
    from_port = 0 if from_port is None else from_port
    to_port   = 65535 if to_port is None else to_port
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
