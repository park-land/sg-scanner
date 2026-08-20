"""Unit tests for sgtree/ipres.py — CIDR/prefix-list resolution."""
import ipaddress

from sgtree import ipres


def _vpc(vpc_id, name, cidr):
    return {'vpc_id': vpc_id, 'name': name, 'cidr': cidr, 'network': ipaddress.ip_network(cidr)}


def _subnet(subnet_id, vpc_id, az, name, cidr):
    return {'subnet_id': subnet_id, 'vpc_id': vpc_id, 'az': az, 'name': name,
            'cidr': cidr, 'network': ipaddress.ip_network(cidr)}


class TestResolveCidrUniversal:
    def test_ipv4_universal_is_untraced(self):
        result = ipres.resolve_cidr('0.0.0.0/0', vpc_blocks=[], subnet_blocks=[], account_public_ips=[])
        assert result == {'cidr': '0.0.0.0/0', 'kind': 'universal'}

    def test_ipv6_universal_is_untraced(self):
        result = ipres.resolve_cidr('::/0', vpc_blocks=[], subnet_blocks=[], account_public_ips=[])
        assert result == {'cidr': '::/0', 'kind': 'universal'}

    def test_universal_short_circuits_before_touching_vpc_data(self):
        # A non-empty vpc_blocks that would (incorrectly) "match" everything
        # must not change the outcome — universal is never traced.
        vpcs = [_vpc('vpc-1', 'prod', '10.0.0.0/8')]
        result = ipres.resolve_cidr('0.0.0.0/0', vpc_blocks=vpcs, subnet_blocks=[], account_public_ips=[])
        assert result['kind'] == 'universal'


class TestResolveCidrInternal:
    def test_matches_owning_vpc(self):
        vpcs = [_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16')]
        result = ipres.resolve_cidr('10.0.1.0/24', vpc_blocks=vpcs, subnet_blocks=[], account_public_ips=[])
        assert result['kind'] == 'internal'
        assert result['vpc_matches'][0]['vpc_id'] == 'vpc-1'

    def test_narrows_to_matching_subnet(self):
        vpcs = [_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16')]
        subnets = [
            _subnet('subnet-a', 'vpc-1', 'us-east-1a', 'app-a', '10.0.1.0/24'),
            _subnet('subnet-b', 'vpc-1', 'us-east-1b', 'app-b', '10.0.2.0/24'),
        ]
        result = ipres.resolve_cidr('10.0.1.0/24', vpc_blocks=vpcs, subnet_blocks=subnets, account_public_ips=[])
        assert [s['subnet_id'] for s in result['subnet_matches']] == ['subnet-a']

    def test_broader_rule_cidr_still_matches_vpc(self):
        # A rule allowing 10.0.0.0/8 should still resolve internal against a /16 VPC
        vpcs = [_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16')]
        result = ipres.resolve_cidr('10.0.0.0/8', vpc_blocks=vpcs, subnet_blocks=[], account_public_ips=[])
        assert result['kind'] == 'internal'


class TestResolveCidrExternal:
    def test_no_overlap_with_any_vpc_is_external(self):
        vpcs = [_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16')]
        result = ipres.resolve_cidr('198.51.100.0/24', vpc_blocks=vpcs, subnet_blocks=[], account_public_ips=[])
        assert result['kind'] == 'external'
        assert result['account_matches'] == []

    def test_matches_an_account_owned_public_ip(self):
        public_ips = [{'ip': '203.0.113.5', 'service': 'ec2', 'resource_type': 'nat_gateway',
                       'resource_id': 'nat-1', 'resource_name': 'nat-1'}]
        result = ipres.resolve_cidr('203.0.113.5/32', vpc_blocks=[], subnet_blocks=[], account_public_ips=public_ips)
        assert result['kind'] == 'external'
        assert result['account_matches'][0]['resource_id'] == 'nat-1'

    def test_ipv4_ip_never_matches_ipv6_rule(self):
        public_ips = [{'ip': '203.0.113.5', 'service': 'ec2', 'resource_type': 'nat_gateway',
                       'resource_id': 'nat-1', 'resource_name': 'nat-1'}]
        result = ipres.resolve_cidr('2001:db8::/32', vpc_blocks=[], subnet_blocks=[], account_public_ips=public_ips)
        assert result['account_matches'] == []

    def test_unparseable_cidr(self):
        result = ipres.resolve_cidr('not-a-cidr', vpc_blocks=[], subnet_blocks=[], account_public_ips=[])
        assert result['kind'] == 'unparseable'


class TestResolvePrefixList:
    def test_known_name(self):
        result = ipres.resolve_prefix_list('pl-abc', {'pl-abc': 'com.amazonaws.us-east-1.s3'})
        assert result == {'kind': 'prefix_list', 'prefix_list_id': 'pl-abc', 'name': 'com.amazonaws.us-east-1.s3'}

    def test_unknown_falls_back_to_id(self):
        result = ipres.resolve_prefix_list('pl-xyz', {})
        assert result['name'] == 'pl-xyz'
