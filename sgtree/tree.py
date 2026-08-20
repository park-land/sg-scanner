"""Builds the SG reference graph starting from one root SG id, then runs the
same checks sg_checks.py runs account-wide — but only against the root SG.
Downstream SGs discovered while walking the tree are identified and their
attachments resolved, but don't get findings of their own; this tool answers
"is *this* SG OK", using the tree as context, not "audit every SG it touches".

Two phases, deliberately separate:
  1. collect() - BFS outward from the root, fetching each SG and its rules,
     following ReferencedGroupInfo on every rule to discover more SGs.
  2. analyze() - once the whole reachable graph is known, run the checks.
     This has to happen after collection finishes because check_stale_rule
     needs to know whether a *referenced* SG turned out to exist, which
     isn't settled until that node has been (attempted to be) fetched.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import aws, checks, ipres


@dataclass
class SGNode:
    sg_id: str
    depth: int
    status: str = 'pending'       # 'found' | 'not_found' | 'error' | 'external'
    name: Optional[str] = None
    description: Optional[str] = None
    vpc_id: Optional[str] = None
    owner_id: Optional[str] = None
    is_default: bool = False
    rules: List[dict] = field(default_factory=list)
    attachments: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    cidr_rules: List[dict] = field(default_factory=list)   # root SG only — see resolve_cidr_rules
    error: Optional[str] = None


@dataclass
class SGEdge:
    from_sg: str
    to_sg: str
    rule_id: str
    direction: str          # 'ingress' | 'egress'
    protocol: Optional[str]
    from_port: Optional[int]
    to_port: Optional[int]
    cross_account: bool = False
    referenced_owner_id: Optional[str] = None


@dataclass
class TreeResult:
    root_sg_id: str
    region: str
    account_id: Optional[str]
    nodes: Dict[str, SGNode]
    edges: List[SGEdge]
    findings: List[dict]
    errors: List[dict]


def collect(session, region, root_sg_id, max_depth=None, own_account_id=None):
    nodes: Dict[str, SGNode] = {}
    edges: List[SGEdge] = []
    errors: List[dict] = []

    queue = [(root_sg_id, 0)]
    queued = {root_sg_id}

    while queue:
        sg_id, depth = queue.pop(0)
        node = SGNode(sg_id=sg_id, depth=depth)
        nodes[sg_id] = node

        sg, status = aws.get_security_group(session, region, sg_id)
        node.status = status
        if status == 'error':
            errors.append({'sg_id': sg_id, 'stage': 'describe_security_groups'})
            continue
        if status == 'not_found':
            continue

        node.name        = sg.get('GroupName', sg_id)
        node.description = sg.get('Description')
        node.vpc_id      = sg.get('VpcId')
        node.owner_id    = sg.get('OwnerId')
        node.is_default  = sg.get('GroupName') == 'default'

        try:
            node.rules = aws.get_security_group_rules(session, region, sg_id)
        except Exception as e:
            errors.append({'sg_id': sg_id, 'stage': 'describe_security_group_rules', 'error': str(e)})
            node.rules = []

        if max_depth is not None and depth >= max_depth:
            continue

        for rule in node.rules:
            ref = rule.get('ReferencedGroupInfo') or {}
            ref_id = ref.get('GroupId')
            if not ref_id:
                continue

            ref_owner = ref.get('UserId')
            cross_account = bool(own_account_id and ref_owner and ref_owner != own_account_id)

            edges.append(SGEdge(
                from_sg=sg_id,
                to_sg=ref_id,
                rule_id=rule.get('SecurityGroupRuleId', ''),
                direction='egress' if rule.get('IsEgress') else 'ingress',
                protocol=rule.get('IpProtocol'),
                from_port=rule.get('FromPort'),
                to_port=rule.get('ToPort'),
                cross_account=cross_account,
                referenced_owner_id=ref_owner,
            ))

            if cross_account:
                if ref_id not in nodes and ref_id not in queued:
                    nodes[ref_id] = SGNode(sg_id=ref_id, depth=depth + 1, status='external', owner_id=ref_owner)
                    queued.add(ref_id)
                continue

            if ref_id not in queued:
                queued.add(ref_id)
                queue.append((ref_id, depth + 1))

    return nodes, edges, errors


def resolve_cidr_rules(node: SGNode, ip_data, include_claude: bool = False, claude_model: Optional[str] = None):
    """Populate node.cidr_rules: every rule whose source/destination is a
    CIDR or managed prefix list (not an SG reference) is included, resolved
    to a VPC/subnet (internal), one of this account's own public IPs
    (external), or left untraced (0.0.0.0/0 / ::/0 — see ipres.resolve_cidr).
    Root SG only — downstream SGs are identified, not analyzed, same as the
    check gating.

    External CIDRs that don't match anything we own get one more pass: if
    include_claude is set, any that also have a rule description get batched
    into a single Claude call asking it to guess what the range might be from
    that description (and the CIDR itself, if Claude happens to recognize a
    published range) — this account has no way to look an external IP up
    directly, so it's only ever a guess grounded in what the rule's author
    wrote down.
    """
    vpc_blocks, subnet_blocks, account_public_ips, prefix_list_names = ip_data
    for rule in node.rules:
        if rule.get('ReferencedGroupInfo'):
            continue
        cidr = rule.get('CidrIpv4') or rule.get('CidrIpv6')
        pl_id = rule.get('PrefixListId')
        if cidr:
            resolution = ipres.resolve_cidr(cidr, vpc_blocks, subnet_blocks, account_public_ips)
        elif pl_id:
            resolution = ipres.resolve_prefix_list(pl_id, prefix_list_names)
        else:
            continue
        node.cidr_rules.append({
            'rule_id':    rule.get('SecurityGroupRuleId', node.sg_id),
            'direction':  'egress' if rule.get('IsEgress') else 'ingress',
            'protocol':   rule.get('IpProtocol'),
            'from_port':  rule.get('FromPort'),
            'to_port':    rule.get('ToPort'),
            'description': rule.get('Description'),
            'resolution': resolution,
        })

    if not include_claude:
        return

    unmatched = [
        r for r in node.cidr_rules
        if r['resolution'].get('kind') == 'external'
        and not r['resolution'].get('account_matches')
        and r.get('description')
    ]
    if not unmatched:
        return

    from . import claude_helper
    model = claude_model or claude_helper.DEFAULT_MODEL
    batch = [{
        'rule_id':     r['rule_id'],
        'cidr':        r['resolution'].get('cidr'),
        'description': r['description'],
        'direction':   r['direction'],
        'protocol':    r['protocol'],
        'from_port':   r['from_port'],
        'to_port':     r['to_port'],
    } for r in unmatched]
    guesses = claude_helper.guess_external_sources(batch, model=model)
    for r in unmatched:
        guess = guesses.get(r['rule_id'])
        if guess:
            r['resolution']['claude_guess'] = guess


def analyze(nodes: Dict[str, SGNode], edges: List[SGEdge], attach_map: Optional[dict],
            root_sg_id: str, include_claude: bool = False, claude_model: Optional[str] = None,
            ip_data=None):
    """Run the four sg_checks.py checks — but only against the root SG.
    Downstream SGs discovered in the tree are identified and their
    attachments are resolved and shown, but no findings are generated for
    them; findings stay focused on the SG you actually asked about.

    Mutates each node's .findings in place and also returns a flat findings
    list. Missing-description findings on the root get a Claude-suggested
    description attached when include_claude is set.
    """
    flat_findings: List[dict] = []

    def record(node: SGNode, check_id, detail, resource_type, resource_id):
        f = {
            'sg_id':         node.sg_id,
            'check':         check_id,
            'detail':        detail,
            'resource_type': resource_type,
            'resource_id':   resource_id,
        }
        node.findings.append(f)
        flat_findings.append(f)
        return f

    # Attachments are shown for every SG in the tree, not just the root —
    # this is "what is it attached to", independent of whether checks run.
    if attach_map is not None:
        for node in nodes.values():
            if node.status == 'found':
                node.attachments = attach_map.get(node.sg_id, [])

    root_node = nodes.get(root_sg_id)
    if root_node is None or root_node.status != 'found':
        return flat_findings

    if ip_data is not None:
        resolve_cidr_rules(root_node, ip_data, include_claude=include_claude, claude_model=claude_model)

    sg_name = root_node.name or root_node.sg_id
    no_desc_findings = []  # (finding_dict, rule) pairs, for the Claude suggestion pass

    for rule in root_node.rules:
        rule_id = rule.get('SecurityGroupRuleId', root_node.sg_id)

        hit = checks.check_allowall(rule, sg_name)
        if hit:
            record(root_node, hit[0], hit[1], 'security_group_rule', rule_id)

        hit = checks.check_rule_label(rule, sg_name)
        if hit:
            f = record(root_node, hit[0], hit[1], 'security_group_rule', rule_id)
            no_desc_findings.append((f, rule))

        ref = rule.get('ReferencedGroupInfo') or {}
        ref_id = ref.get('GroupId')
        if ref_id:
            ref_node = nodes.get(ref_id)
            if ref_node is None:
                referenced_exists = None
            elif ref_node.status == 'not_found':
                referenced_exists = False
            elif ref_node.status == 'found':
                referenced_exists = True
            else:  # 'error' or 'external' - can't prove it's gone
                referenced_exists = None
            hit = checks.check_stale_rule(rule, sg_name, referenced_exists)
            if hit:
                record(root_node, hit[0], hit[1], 'security_group_rule', rule_id)

    if attach_map is not None:
        hit = checks.check_unused_sg(root_node.sg_id, sg_name, root_node.is_default, root_node.attachments)
        if hit:
            record(root_node, hit[0], hit[1], 'security_group', root_node.sg_id)

    if no_desc_findings and include_claude:
        from . import claude_helper
        model = claude_model or claude_helper.DEFAULT_MODEL
        batch = []
        for f, rule in no_desc_findings:
            ref = rule.get('ReferencedGroupInfo') or {}
            ref_node = nodes.get(ref.get('GroupId')) if ref.get('GroupId') else None
            batch.append({
                'rule_id':            f['resource_id'],
                'sg_name':            sg_name,
                'direction':          'egress' if rule.get('IsEgress') else 'ingress',
                'protocol':           rule.get('IpProtocol'),
                'from_port':          rule.get('FromPort'),
                'to_port':            rule.get('ToPort'),
                'cidr':               rule.get('CidrIpv4') or rule.get('CidrIpv6') or '',
                'referenced_sg_name': (ref_node.name if ref_node else None) or '',
            })
        suggestions = claude_helper.suggest_rule_descriptions(batch, model=model)
        for f, rule in no_desc_findings:
            suggestion = suggestions.get(f['resource_id'])
            if suggestion:
                f['suggestion'] = suggestion

    return flat_findings


def build(session, region, root_sg_id, max_depth=None, include_attachments=True,
          include_claude=False, claude_model=None, include_ip_resolution=True):
    try:
        own_account_id = aws.get_account_id(session)
    except Exception:
        own_account_id = None

    nodes, edges, errors = collect(session, region, root_sg_id, max_depth=max_depth, own_account_id=own_account_id)

    attach_map = None
    if include_attachments:
        try:
            attach_map = aws.get_attachment_map(session, region, errors=errors,
                                                 include_claude=include_claude, claude_model=claude_model)
        except Exception as e:
            errors.append({'sg_id': None, 'stage': 'get_attachment_map', 'error': str(e)})
            attach_map = {}

    ip_data = None
    if include_ip_resolution:
        try:
            ip_data = (
                aws.get_vpc_cidr_blocks(session, region),
                aws.get_subnet_cidr_blocks(session, region),
                aws.get_account_public_ips(session, region, include_claude=include_claude, claude_model=claude_model),
                aws.get_prefix_list_names(session, region),
            )
        except Exception as e:
            errors.append({'sg_id': None, 'stage': 'ip_resolution', 'error': str(e)})
            ip_data = None

    findings = analyze(nodes, edges, attach_map, root_sg_id,
                        include_claude=include_claude, claude_model=claude_model,
                        ip_data=ip_data)

    return TreeResult(
        root_sg_id=root_sg_id,
        region=region,
        account_id=own_account_id,
        nodes=nodes,
        edges=edges,
        findings=findings,
        errors=errors,
    )
