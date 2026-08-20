"""Resolves a rule's CIDR source/destination to something meaningful instead
of a bare address block:

  - universal (0.0.0.0/0 or ::/0) is left untraced — "everything" isn't a
    location, and check_allowall already flags the rule if it's actually
    wide open. The rule itself still shows up in the report, just without a
    VPC/subnet/public-IP resolution attempt.
  - internal (overlaps one of this account's VPC CIDRs in this region) maps
    back to the owning VPC, and the owning subnet(s) if narrow enough to tell.
  - external (no overlap with any of our VPCs) is checked against this
    account's own public IPs (Elastic IPs, ENI public IPs, NAT Gateway IPs)
    to catch the case where a rule is scoped to our own infrastructure by its
    public address rather than an SG reference.
"""
import ipaddress

UNIVERSAL_CIDRS = {'0.0.0.0/0', '::/0'}


def resolve_cidr(cidr_str, vpc_blocks, subnet_blocks, account_public_ips):
    if cidr_str in UNIVERSAL_CIDRS:
        return {'cidr': cidr_str, 'kind': 'universal'}

    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return {'cidr': cidr_str, 'kind': 'unparseable'}

    vpc_matches = [b for b in vpc_blocks if b['network'].version == net.version and b['network'].overlaps(net)]
    if vpc_matches:
        subnet_matches = [b for b in subnet_blocks if b['network'].version == net.version and b['network'].overlaps(net)]
        return {
            'cidr': cidr_str,
            'kind': 'internal',
            'vpc_matches': [{'vpc_id': b['vpc_id'], 'name': b['name'], 'cidr': b['cidr']} for b in vpc_matches],
            'subnet_matches': [{'subnet_id': b['subnet_id'], 'vpc_id': b['vpc_id'], 'az': b['az'],
                                 'name': b['name'], 'cidr': b['cidr']} for b in subnet_matches],
        }

    account_matches = []
    for entry in account_public_ips:
        try:
            ip = ipaddress.ip_address(entry['ip'])
        except ValueError:
            continue
        if ip.version == net.version and ip in net:
            account_matches.append(entry)

    return {
        'cidr': cidr_str,
        'kind': 'external',
        'account_matches': account_matches,
    }


def resolve_prefix_list(pl_id, prefix_list_names):
    return {
        'kind': 'prefix_list',
        'prefix_list_id': pl_id,
        'name': prefix_list_names.get(pl_id, pl_id),
    }
