"""Rendering: an indented tree of the SG reference graph, a findings summary
grouped by check (mirrors sg_checks.py's print_findings), and a JSON dump.
"""
import dataclasses
import json

STATUS_LABEL = {
    'found':     '',
    'not_found': '  [NOT FOUND]',
    'error':     '  [LOOKUP ERROR]',
    'external':  '  [EXTERNAL / CROSS-ACCOUNT — not traversed]',
}


def _node_line(node):
    label = node.name or node.sg_id
    suffix = STATUS_LABEL.get(node.status, '')
    bits = [f'{node.sg_id}']
    if node.name and node.name != node.sg_id:
        bits.append(f'"{node.name}"')
    if node.vpc_id:
        bits.append(f'vpc={node.vpc_id}')
    if node.status == 'external' and node.owner_id:
        bits.append(f'owner={node.owner_id}')
    line = '  '.join(bits) + suffix
    if node.findings:
        line += f'  ({len(node.findings)} finding{"s" if len(node.findings) != 1 else ""})'
    return line


def _attachment_line(a):
    tag = '  (Claude-inferred)' if a.get('inferred') else ''
    name = f' ({a["resource_name"]})' if a['resource_name'] != a['resource_id'] else ''
    return f"[{a['service']}] {a['resource_type']} {a['resource_id']}{name}{tag}"


def _port_str_generic(protocol, from_port, to_port):
    if from_port is None or to_port is None:
        return f'{protocol or "?"}/all'
    if from_port == to_port:
        return f'{protocol}/{from_port}'
    return f'{protocol}/{from_port}-{to_port}'


def _resolution_summary(resolution):
    kind = resolution.get('kind')
    if kind == 'universal':
        return 'all addresses — not traced (see sg_allows_all if flagged)'
    if kind == 'internal':
        vpc_str = '; '.join(
            f"VPC {v['vpc_id']}" + (f' ("{v["name"]}")' if v['name'] else '') + f" [{v['cidr']}]"
            for v in resolution.get('vpc_matches', [])
        )
        subnets = resolution.get('subnet_matches', [])
        if subnets:
            subnet_str = '; '.join(
                f"subnet {s['subnet_id']}" + (f' ("{s["name"]}")' if s['name'] else '')
                + (f' {s["az"]}' if s['az'] else '') + f" [{s['cidr']}]"
                for s in subnets
            )
            return f"internal — {vpc_str}; matches subnet(s): {subnet_str}"
        return f"internal — {vpc_str}"
    if kind == 'external':
        matches = resolution.get('account_matches', [])
        if matches:
            parts = '; '.join(
                f"{m['resource_name']} ({m['ip']})" + ('  (Claude-inferred)' if m.get('inferred') else '')
                for m in matches
            )
            return f"external — matches account resource(s): {parts}"
        guess = resolution.get('claude_guess')
        if guess:
            return f'external — no match in this account; Claude guess (from rule description): "{guess}"'
        return "external — no match in this account"
    if kind == 'prefix_list':
        name = resolution.get('name')
        pl_id = resolution.get('prefix_list_id')
        return f'managed prefix list {pl_id} ("{name}")' if name and name != pl_id else f'managed prefix list {pl_id}'
    if kind == 'unparseable':
        return 'could not parse CIDR'
    return kind or 'unknown'


def _cidr_rule_line(entry):
    # Direction is conveyed by the Ingress/Egress group header instead of
    # repeated on every line — see _print_node_detail.
    port = _port_str_generic(entry['protocol'], entry['from_port'], entry['to_port'])
    resolution = entry['resolution']
    source = resolution.get('cidr') or resolution.get('prefix_list_id') or '?'
    return f"[{port}] {source} → {_resolution_summary(resolution)}"


def _print_node_detail(node, prefix):
    """Attachments, and (root only) resolved CIDR/prefix-list rules —
    findings themselves already show in print_findings — indented under
    this node's tree line. Ingress and egress rules print as separate
    groups so the two directions don't have to be mentally sorted apart."""
    if node.status != 'found':
        return
    if node.attachments:
        for a in node.attachments:
            print(f"{prefix}      • attached to: {_attachment_line(a)}")
    else:
        print(f"{prefix}      • attached to: nothing found (may be unused)")

    ingress = [r for r in node.cidr_rules if r['direction'] == 'ingress']
    egress = [r for r in node.cidr_rules if r['direction'] == 'egress']
    for label, group in (('ingress rules', ingress), ('egress rules', egress)):
        if not group:
            continue
        print(f"{prefix}      • {label}:")
        for r in group:
            print(f"{prefix}          - {_cidr_rule_line(r)}")


def print_tree(result):
    nodes, edges = result.nodes, result.edges
    children = {}
    for e in edges:
        children.setdefault(e.from_sg, []).append(e)

    print(f"Account: {result.account_id or 'unknown'}   Region: {result.region}")
    print(f"Root SG: {result.root_sg_id}")
    print("(Checks — allow-all, missing descriptions, stale/unused — run on the root SG only;")
    print(" downstream SGs below are identified and their attachments resolved, not audited.)\n")

    printed = set()

    def walk(sg_id, prefix, is_last, ancestors):
        node = nodes.get(sg_id)
        connector = '└── ' if is_last else '├── '
        if node is None:
            print(f"{prefix}{connector}{sg_id}  [unresolved]")
            return
        if sg_id in ancestors:
            print(f"{prefix}{connector}{_node_line(node)}  (cycle, already shown above)")
            return
        print(f"{prefix}{connector}{_node_line(node)}")

        if sg_id in printed:
            kids = children.get(sg_id, [])
            if kids:
                nxt = prefix + ('    ' if is_last else '│   ')
                print(f"{nxt}└── (children already expanded above)")
            return
        printed.add(sg_id)
        nxt_prefix = prefix + ('    ' if is_last else '│   ')
        _print_node_detail(node, nxt_prefix)
        _print_child_edges(children.get(sg_id, []), nxt_prefix, sg_id, ancestors, walk)

    root_node = nodes.get(result.root_sg_id)
    if root_node is None:
        print(f"{result.root_sg_id}  [unresolved]")
    else:
        print(_node_line(root_node))
        printed.add(result.root_sg_id)
        _print_node_detail(root_node, '')
        _print_child_edges(children.get(result.root_sg_id, []), '', result.root_sg_id,
                            {result.root_sg_id}, walk)


def _grouped_edge_items(kids):
    """Ingress edges first, then egress, each preceded by a header — so the
    two directions don't have to be mentally sorted apart while scanning.
    Yields ('header', label) or ('edge', edge, is_last), where is_last is
    computed against the combined ingress+egress order (it controls the
    '│' vs blank continuation for that edge's own subtree, so it must stay
    correct across the whole list, not just within one direction's group)."""
    ingress = [e for e in kids if e.direction == 'ingress']
    egress = [e for e in kids if e.direction == 'egress']
    ordered = ingress + egress
    pos = 0
    for label, group in (('Ingress', ingress), ('Egress', egress)):
        if not group:
            continue
        yield ('header', label)
        for edge in group:
            yield ('edge', edge, pos == len(ordered) - 1)
            pos += 1


def _print_child_edges(kids, nxt_prefix, sg_id, ancestors, walk):
    for item in _grouped_edge_items(kids):
        if item[0] == 'header':
            # Same depth as the connector glyphs on the edge lines below it.
            print(f"{nxt_prefix}    {item[1]}:")
            continue
        _, edge, last = item
        print(f"{nxt_prefix}{'    ' if last else '│   '}{_edge_label(edge)}")
        walk(edge.to_sg, nxt_prefix, last, ancestors | {sg_id})


def _port_str(edge):
    return _port_str_generic(edge.protocol, edge.from_port, edge.to_port)


def _edge_label(edge):
    # Direction is conveyed by the Ingress/Egress group header instead of
    # repeated on every line — see _grouped_edge_items.
    tag = '(cross-account)' if edge.cross_account else ''
    return f'[{_port_str(edge)}] {tag}'.rstrip()


def print_findings(findings):
    if not findings:
        print("\nNo findings.")
        return

    by_check = {}
    for f in findings:
        by_check.setdefault(f['check'], []).append(f)

    print(f"\n{'=' * 60}")
    print(f"  {len(findings)} finding(s) across {len(by_check)} check(s)")
    print(f"{'=' * 60}\n")

    for check, items in sorted(by_check.items()):
        print(f"{check.upper().replace('_', ' ')}  ({len(items)})")
        print('-' * 40)
        for f in items:
            print(f"  [{f['sg_id']}] {f['detail']}")
            if f.get('suggestion'):
                print(f"      → Claude-suggested description: \"{f['suggestion']}\"")
        print()


def print_errors(errors):
    if not errors:
        return
    print(f"\n{len(errors)} lookup error(s) (results may be incomplete):")
    for e in errors:
        sg = e.get('sg_id') or '-'
        print(f"  [{sg}] {e.get('stage', e.get('source', '?'))}: {e.get('error', '')}")


def to_json(result):
    def node_dict(n):
        d = dataclasses.asdict(n)
        return d

    def edge_dict(e):
        return dataclasses.asdict(e)

    return json.dumps({
        'root_sg_id': result.root_sg_id,
        'region':     result.region,
        'account_id': result.account_id,
        'nodes':      {sg_id: node_dict(n) for sg_id, n in result.nodes.items()},
        'edges':      [edge_dict(e) for e in result.edges],
        'findings':   result.findings,
        'errors':     result.errors,
    }, indent=2, default=str)
