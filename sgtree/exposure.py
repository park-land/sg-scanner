"""Deterministic exposure signals for the root SG — the facts an AI
reachability verdict is built from, computed with no AI involved so the
verdict has a checkable factual basis rather than being the model's own
read of the raw tree.

This deliberately stays honest about what we can and can't verify: we know
whether a resource attached to the root SG holds a public IP (from the same
account-public-IP resolution used elsewhere), and we know the *type* of
anything load-balancer-shaped attached to it, but we don't call the ELB API
to check a load balancer's Scheme (internet-facing vs internal) — that's a
real gap, so a load-balancer attachment is surfaced as "unverified" rather
than asserted either way.
"""
from dataclasses import dataclass, field
from typing import List

_LOAD_BALANCER_TYPES = {
    'load_balancer', 'network_load_balancer',
    'gateway_load_balancer', 'gateway_load_balancer_endpoint',
}
_UNIVERSAL_CIDRS = {'0.0.0.0/0', '::/0'}


@dataclass
class ExposureSignals:
    is_unused: bool
    has_universal_ingress: bool
    universal_ingress_ports: List[tuple]           # [(from_port, to_port), ...]
    directly_public_attachments: List[dict]         # attachments whose own resource_id has a known public IP
    load_balancer_attachments: List[dict]           # attachment dicts of LB-shaped types (unverified scheme)
    nat_gateway_attachments: List[dict]
    other_attachment_count: int                     # attachments not covered by the categories above


def compute_signals(root_node, account_public_ips) -> ExposureSignals:
    attachments = root_node.attachments or []
    public_ip_resource_ids = {e['resource_id'] for e in (account_public_ips or [])}

    directly_public = [a for a in attachments if a['resource_id'] in public_ip_resource_ids]
    load_balancers = [a for a in attachments if a['resource_type'] in _LOAD_BALANCER_TYPES]
    nat_gateways = [a for a in attachments if a['resource_type'] == 'nat_gateway']
    categorized_ids = {a['resource_id'] for a in directly_public + load_balancers + nat_gateways}
    other_count = len([a for a in attachments if a['resource_id'] not in categorized_ids])

    universal_ports = []
    for rule in root_node.rules:
        if rule.get('IsEgress'):
            continue
        if rule.get('CidrIpv4') in _UNIVERSAL_CIDRS or rule.get('CidrIpv6') in _UNIVERSAL_CIDRS:
            universal_ports.append((rule.get('FromPort'), rule.get('ToPort')))

    return ExposureSignals(
        is_unused=not attachments,
        has_universal_ingress=bool(universal_ports),
        universal_ingress_ports=universal_ports,
        directly_public_attachments=directly_public,
        load_balancer_attachments=load_balancers,
        nat_gateway_attachments=nat_gateways,
        other_attachment_count=other_count,
    )


def deterministic_verdict(signals: ExposureSignals):
    """The exposure verdict we can assert without any AI involvement, or
    None if it genuinely needs interpretation (that's where Claude's read of
    the full tree — not just this node's own attachments — adds value: an
    unverified load balancer, or a rule that's wide open but the SG's
    attachments alone don't prove or disprove reachability)."""
    if signals.is_unused:
        return 'unused', 'SG has no attachments — the rule can\'t be reached through this SG at all.'
    if not signals.has_universal_ingress:
        return 'internal-only', 'No ingress rule is open to the internet.'
    if signals.directly_public_attachments:
        ids = ', '.join(a['resource_id'] for a in signals.directly_public_attachments)
        return 'internet-exposed', f'Ingress is open to the internet and a directly public resource is attached ({ids}).'
    return None, None
