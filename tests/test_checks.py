"""Unit tests for sgtree/checks.py — the four checks ported from sg_checks.py.
All pure functions, no AWS/mocking needed.
"""
from sgtree import checks


class TestCheckAllowall:
    def test_flags_ingress_open_to_world_on_unsafe_port(self):
        rule = {'IsEgress': False, 'CidrIpv4': '0.0.0.0/0', 'FromPort': 22, 'ToPort': 22}
        hit = checks.check_allowall(rule, 'my-sg')
        assert hit is not None
        check_id, detail = hit
        assert check_id == 'sg_allows_all'
        assert 'my-sg' in detail and 'port 22' in detail

    def test_flags_ipv6_open_to_world(self):
        rule = {'IsEgress': False, 'CidrIpv6': '::/0', 'FromPort': 3389, 'ToPort': 3389}
        assert checks.check_allowall(rule, 'my-sg') is not None

    def test_allows_safe_ports_80_and_443(self):
        for port in (80, 443):
            rule = {'IsEgress': False, 'CidrIpv4': '0.0.0.0/0', 'FromPort': port, 'ToPort': port}
            assert checks.check_allowall(rule, 'my-sg') is None

    def test_allows_range_spanning_a_safe_port(self):
        rule = {'IsEgress': False, 'CidrIpv4': '0.0.0.0/0', 'FromPort': 1, 'ToPort': 1000}
        assert checks.check_allowall(rule, 'my-sg') is None

    def test_ignores_egress(self):
        rule = {'IsEgress': True, 'CidrIpv4': '0.0.0.0/0', 'FromPort': 22, 'ToPort': 22}
        assert checks.check_allowall(rule, 'my-sg') is None

    def test_all_traffic_rule_with_none_ports_does_not_crash(self):
        # AWS sets FromPort/ToPort to None (present, not absent) for an
        # "all traffic" rule (protocol -1) — this must be treated as the
        # full 0-65535 range, not crash comparing None <= port.
        rule = {'IsEgress': False, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0', 'FromPort': None, 'ToPort': None}
        hit = checks.check_allowall(rule, 'my-sg')
        assert hit is not None
        assert hit[0] == 'sg_allows_all'

    def test_all_traffic_rule_is_never_exempted_by_the_safe_port_carve_out(self):
        # 0.0.0.0/0 spans 80/443 too, but "all traffic, no port restriction"
        # must never get the SAFE_PORTS pass a merely-broad numeric range
        # (e.g. 1-1000) can get — it's the single most dangerous rule shape.
        rule = {'IsEgress': False, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0', 'FromPort': None, 'ToPort': None}
        hit = checks.check_allowall(rule, 'my-sg')
        assert hit is not None
        assert 'all ports' in hit[1]

    def test_ignores_non_universal_cidr(self):
        rule = {'IsEgress': False, 'CidrIpv4': '10.0.0.0/8', 'FromPort': 22, 'ToPort': 22}
        assert checks.check_allowall(rule, 'my-sg') is None

    def test_port_range_message_format(self):
        rule = {'IsEgress': False, 'CidrIpv4': '0.0.0.0/0', 'FromPort': 8000, 'ToPort': 8010}
        _, detail = checks.check_allowall(rule, 'my-sg')
        assert 'ports 8000-8010' in detail


class TestCheckRuleLabel:
    def test_flags_missing_description(self):
        hit = checks.check_rule_label({'IsEgress': False, 'Description': None}, 'my-sg')
        assert hit is not None
        assert hit[0] == 'sg_rule_no_description'
        assert 'ingress' in hit[1]

    def test_flags_empty_string_description(self):
        assert checks.check_rule_label({'IsEgress': False, 'Description': ''}, 'my-sg') is not None

    def test_egress_direction_in_message(self):
        _, detail = checks.check_rule_label({'IsEgress': True, 'Description': None}, 'my-sg')
        assert 'egress' in detail

    def test_passes_when_described(self):
        assert checks.check_rule_label({'IsEgress': False, 'Description': 'SSH from bastion'}, 'my-sg') is None


class TestCheckStaleRule:
    def test_flags_reference_to_nonexistent_sg(self):
        rule = {'ReferencedGroupInfo': {'GroupId': 'sg-gone'}}
        hit = checks.check_stale_rule(rule, 'my-sg', referenced_sg_exists=False)
        assert hit is not None
        assert hit[0] == 'sg_stale_rule'
        assert 'sg-gone' in hit[1]

    def test_passes_when_reference_exists(self):
        rule = {'ReferencedGroupInfo': {'GroupId': 'sg-there'}}
        assert checks.check_stale_rule(rule, 'my-sg', referenced_sg_exists=True) is None

    def test_passes_when_existence_unknown(self):
        # cross-account / lookup-error references must never be flagged as proof of staleness
        rule = {'ReferencedGroupInfo': {'GroupId': 'sg-unknown'}}
        assert checks.check_stale_rule(rule, 'my-sg', referenced_sg_exists=None) is None

    def test_passes_when_no_reference(self):
        assert checks.check_stale_rule({'CidrIpv4': '10.0.0.0/8'}, 'my-sg', referenced_sg_exists=False) is None


class TestCheckUnusedSg:
    def test_flags_unattached_non_default_sg(self):
        hit = checks.check_unused_sg('sg-123', 'my-sg', is_default=False, attachments=[])
        assert hit is not None
        assert hit[0] == 'sg_unused'

    def test_ignores_default_sg_even_if_unattached(self):
        assert checks.check_unused_sg('sg-123', 'default', is_default=True, attachments=[]) is None

    def test_passes_when_attached(self):
        attachments = [{'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1', 'resource_name': 'i-1'}]
        assert checks.check_unused_sg('sg-123', 'my-sg', is_default=False, attachments=attachments) is None
