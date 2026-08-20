"""Unit tests for the deterministic ENI-resolution logic in sgtree/aws.py —
_classify_eni_deterministic and resolve_enis, plus get_account_public_ips'
use of it to trace a public IP to its main resource.
"""
from sgtree import aws


class TestClassifyEniDeterministic:
    def test_nat_gateway_by_interface_type_and_description(self):
        eni = {'InterfaceType': 'nat_gateway', 'Description': 'Interface for NAT Gateway nat-0123456789abcdef0'}
        assert aws._classify_eni_deterministic(eni) == 'NAT Gateway (nat-0123456789abcdef0)'

    def test_vpc_endpoint(self):
        eni = {'InterfaceType': 'vpc_endpoint', 'Description': 'VPC Endpoint Interface vpce-0123456789abcdef0'}
        assert aws._classify_eni_deterministic(eni) == 'VPC Endpoint (vpce-0123456789abcdef0)'

    def test_lambda_by_description_pattern(self):
        eni = {'InterfaceType': 'interface', 'Description': 'AWS Lambda VPC ENI-abcdef'}
        assert aws._classify_eni_deterministic(eni) == 'Lambda-managed network interface'

    def test_elb_application_load_balancer(self):
        eni = {'InterfaceType': 'interface', 'Description': 'ELB app/my-alb/1234567890abcdef'}
        assert aws._classify_eni_deterministic(eni) == "Application Load Balancer 'my-alb'"

    def test_elb_network_load_balancer(self):
        eni = {'InterfaceType': 'interface', 'Description': 'ELB net/my-nlb/abcdef1234567890'}
        assert aws._classify_eni_deterministic(eni) == "Network Load Balancer 'my-nlb'"

    def test_rds_network_interface(self):
        eni = {'InterfaceType': 'interface', 'Description': 'RDSNetworkInterface'}
        assert aws._classify_eni_deterministic(eni) == 'RDS-managed network interface'

    def test_elasticache(self):
        eni = {'InterfaceType': 'interface', 'Description': 'ElastiCache node-0001'}
        assert aws._classify_eni_deterministic(eni) == 'ElastiCache-managed network interface'

    def test_unrecognized_description_returns_none(self):
        eni = {'InterfaceType': 'interface', 'Description': 'some totally unrecognized custom description'}
        assert aws._classify_eni_deterministic(eni) is None

    def test_empty_description_returns_none(self):
        assert aws._classify_eni_deterministic({'InterfaceType': 'interface', 'Description': ''}) is None


class TestResolveEnis:
    def test_instance_attached_eni_resolves_to_instance(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda session, region, ids: {'i-0abc': 'i-0abc (web-1)'})
        enis = [{'NetworkInterfaceId': 'eni-1', 'InterfaceType': 'interface',
                 'Attachment': {'InstanceId': 'i-0abc'}, 'Description': 'primary'}]
        result = aws.resolve_enis(session=None, region='us-east-1', enis=enis, include_claude=False)
        assert result['eni-1'] == {'resource_type': 'instance', 'resource_id': 'i-0abc',
                                    'label': 'i-0abc (web-1)', 'inferred': False, 'reasoning': None}

    def test_pattern_matched_eni_resolves_without_claude(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda *a, **k: {})
        enis = [{'NetworkInterfaceId': 'eni-alb', 'InterfaceType': 'interface',
                 'Description': 'ELB app/my-alb/1234567890abcdef'}]
        result = aws.resolve_enis(session=None, region='us-east-1', enis=enis, include_claude=False)
        assert result['eni-alb']['resource_type'] == 'network_interface'
        assert result['eni-alb']['label'] == "Application Load Balancer 'my-alb'"
        assert result['eni-alb']['inferred'] is False
        assert result['eni-alb']['reasoning'] is None

    def test_unresolved_eni_without_claude_falls_back_to_raw_description(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda *a, **k: {})
        enis = [{'NetworkInterfaceId': 'eni-x', 'InterfaceType': 'interface', 'Description': 'mystery thing'}]
        result = aws.resolve_enis(session=None, region='us-east-1', enis=enis, include_claude=False)
        assert result['eni-x'] == {'resource_type': 'network_interface', 'resource_id': 'eni-x',
                                    'label': 'mystery thing', 'inferred': False, 'reasoning': None}

    def test_unresolved_eni_uses_claude_when_enabled(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda *a, **k: {})
        from sgtree import claude_helper
        monkeypatch.setattr(claude_helper, 'classify_enis', lambda enis, model=None: {
            'eni-x': {'label': 'Transfer Family server', 'reasoning': 'Description mentions an SFTP endpoint.'},
        })
        enis = [{'NetworkInterfaceId': 'eni-x', 'InterfaceType': 'interface', 'Description': 'mystery thing'}]
        result = aws.resolve_enis(session=None, region='us-east-1', enis=enis, include_claude=True)
        assert result['eni-x']['label'] == 'Transfer Family server'
        assert result['eni-x']['inferred'] is True
        assert result['eni-x']['reasoning'] == 'Description mentions an SFTP endpoint.'


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class _FakeEC2:
    def __init__(self, enis, addresses):
        self._enis = enis
        self._addresses = addresses

    def get_paginator(self, name):
        if name == 'describe_network_interfaces':
            return _FakePaginator([{'NetworkInterfaces': self._enis}])
        if name == 'describe_nat_gateways':
            return _FakePaginator([{'NatGateways': []}])
        raise AssertionError(f'unexpected paginator {name}')

    def describe_addresses(self):
        return {'Addresses': self._addresses}


class _FakeSession:
    def __init__(self, enis, addresses):
        self._ec2 = _FakeEC2(enis, addresses)

    def client(self, name, region_name=None):
        assert name == 'ec2'
        return self._ec2


class TestGetAccountPublicIpsTracesMainResource:
    def test_eip_on_albs_eni_resolves_to_the_alb_not_the_eni(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda *a, **k: {})
        enis = [{'NetworkInterfaceId': 'eni-alb', 'InterfaceType': 'interface',
                 'Description': "ELB app/my-alb/1234567890abcdef"}]
        addresses = [{'PublicIp': '198.51.100.20', 'NetworkInterfaceId': 'eni-alb',
                      'Tags': [{'Key': 'Name', 'Value': 'prod-eip'}]}]
        session = _FakeSession(enis, addresses)

        result = aws.get_account_public_ips(session, 'us-east-1', include_claude=False)

        entry = next(e for e in result if e['ip'] == '198.51.100.20')
        assert entry['resource_type'] == 'network_interface'
        assert "Application Load Balancer 'my-alb'" in entry['resource_name']
        assert 'prod-eip' in entry['resource_name']

    def test_unassociated_eip_is_labeled_as_such(self, monkeypatch):
        monkeypatch.setattr(aws, '_resolve_instance_labels', lambda *a, **k: {})
        addresses = [{'PublicIp': '198.51.100.30', 'AllocationId': 'eipalloc-1', 'Tags': []}]
        session = _FakeSession([], addresses)

        result = aws.get_account_public_ips(session, 'us-east-1', include_claude=False)

        entry = next(e for e in result if e['ip'] == '198.51.100.30')
        assert entry['resource_type'] == 'elastic_ip'
        assert 'Unassociated' in entry['resource_name']
