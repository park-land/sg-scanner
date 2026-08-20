"""Unit tests for sgtree/exposure.py — pure functions, no AWS/Claude
involved, so these run purely against constructed SGNode fixtures."""
from sgtree.exposure import compute_signals, deterministic_verdict
from sgtree.tree import SGNode


def _node(rules=None, attachments=None):
    return SGNode(sg_id='sg-root', depth=0, status='found', name='root-sg',
                  rules=rules or [], attachments=attachments or [])


def _rule(is_egress=False, cidr4=None, cidr6=None, from_port=443, to_port=443):
    r = {'IsEgress': is_egress, 'FromPort': from_port, 'ToPort': to_port}
    if cidr4:
        r['CidrIpv4'] = cidr4
    if cidr6:
        r['CidrIpv6'] = cidr6
    return r


class TestComputeSignals:
    def test_unused_sg_flagged(self):
        signals = compute_signals(_node(), account_public_ips=[])
        assert signals.is_unused is True

    def test_universal_ingress_detected(self):
        node = _node(rules=[_rule(cidr4='0.0.0.0/0', from_port=22, to_port=22)])
        signals = compute_signals(node, account_public_ips=[])
        assert signals.has_universal_ingress is True
        assert signals.universal_ingress_ports == [(22, 22)]

    def test_universal_egress_is_not_ingress_exposure(self):
        node = _node(rules=[_rule(is_egress=True, cidr4='0.0.0.0/0', from_port=443, to_port=443)])
        signals = compute_signals(node, account_public_ips=[])
        assert signals.has_universal_ingress is False

    def test_ipv6_universal_ingress_detected(self):
        node = _node(rules=[_rule(cidr6='::/0', from_port=443, to_port=443)])
        signals = compute_signals(node, account_public_ips=[])
        assert signals.has_universal_ingress is True

    def test_scoped_cidr_is_not_universal(self):
        node = _node(rules=[_rule(cidr4='10.0.0.0/8', from_port=443, to_port=443)])
        signals = compute_signals(node, account_public_ips=[])
        assert signals.has_universal_ingress is False

    def test_directly_public_attachment_detected(self):
        node = _node(attachments=[
            {'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1', 'resource_name': 'i-1'},
        ])
        public_ips = [{'ip': '203.0.113.5', 'resource_id': 'i-1'}]
        signals = compute_signals(node, account_public_ips=public_ips)
        assert len(signals.directly_public_attachments) == 1
        assert signals.directly_public_attachments[0]['resource_id'] == 'i-1'

    def test_load_balancer_attachment_categorized_separately(self):
        node = _node(attachments=[
            {'service': 'ec2', 'resource_type': 'network_load_balancer', 'resource_id': 'eni-lb', 'resource_name': 'NLB'},
        ])
        signals = compute_signals(node, account_public_ips=[])
        assert len(signals.load_balancer_attachments) == 1
        assert signals.directly_public_attachments == []

    def test_nat_gateway_attachment_categorized_separately(self):
        node = _node(attachments=[
            {'service': 'ec2', 'resource_type': 'nat_gateway', 'resource_id': 'nat-1', 'resource_name': 'nat-1'},
        ])
        signals = compute_signals(node, account_public_ips=[])
        assert len(signals.nat_gateway_attachments) == 1

    def test_other_attachment_counted_and_not_miscategorized(self):
        node = _node(attachments=[
            {'service': 'rds', 'resource_type': 'db_instance', 'resource_id': 'db-1', 'resource_name': 'db-1'},
        ])
        signals = compute_signals(node, account_public_ips=[])
        assert signals.other_attachment_count == 1
        assert signals.directly_public_attachments == []
        assert signals.load_balancer_attachments == []


class TestDeterministicVerdict:
    def test_unused_sg_is_unused_verdict(self):
        signals = compute_signals(_node(), account_public_ips=[])
        verdict, _ = deterministic_verdict(signals)
        assert verdict == 'unused'

    def test_no_universal_ingress_is_internal_only(self):
        node = _node(rules=[_rule(cidr4='10.0.0.0/8')], attachments=[
            {'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1', 'resource_name': 'i-1'},
        ])
        signals = compute_signals(node, account_public_ips=[])
        verdict, _ = deterministic_verdict(signals)
        assert verdict == 'internal-only'

    def test_universal_ingress_plus_public_attachment_is_internet_exposed(self):
        node = _node(
            rules=[_rule(cidr4='0.0.0.0/0', from_port=22, to_port=22)],
            attachments=[{'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1', 'resource_name': 'i-1'}],
        )
        signals = compute_signals(node, account_public_ips=[{'ip': '203.0.113.5', 'resource_id': 'i-1'}])
        verdict, explanation = deterministic_verdict(signals)
        assert verdict == 'internet-exposed'
        assert 'i-1' in explanation

    def test_universal_ingress_with_only_a_load_balancer_is_left_unverified(self):
        # This is the case an AI reachability read is actually for — we
        # can't prove or disprove it from attachments alone.
        node = _node(
            rules=[_rule(cidr4='0.0.0.0/0', from_port=443, to_port=443)],
            attachments=[{'service': 'ec2', 'resource_type': 'load_balancer', 'resource_id': 'eni-lb', 'resource_name': 'ELB'}],
        )
        signals = compute_signals(node, account_public_ips=[])
        verdict, explanation = deterministic_verdict(signals)
        assert verdict is None
        assert explanation is None
