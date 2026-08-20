"""Integration tests for sgtree/tree.py — the BFS traversal, root-only check
gating, and CIDR/prefix-list resolution — against a mocked sgtree.aws module.
No real AWS or Claude calls; everything is monkeypatched.
"""
import ipaddress

import pytest

from sgtree import aws, tree


def _vpc(vpc_id, name, cidr):
    return {'vpc_id': vpc_id, 'name': name, 'cidr': cidr, 'network': ipaddress.ip_network(cidr)}


def _subnet(subnet_id, vpc_id, az, name, cidr):
    return {'subnet_id': subnet_id, 'vpc_id': vpc_id, 'az': az, 'name': name,
            'cidr': cidr, 'network': ipaddress.ip_network(cidr)}


@pytest.fixture
def mock_aws(monkeypatch):
    """Wires up sgtree.aws with in-memory fakes driven by module-level dicts
    the test sets before calling tree.build(). Returns the dicts to populate."""
    sgs = {}
    rules = {}
    attach_map = {}
    vpc_blocks = []
    subnet_blocks = []
    public_ips = []
    prefix_list_names = {}

    def fake_get_security_group(session, region, sg_id):
        return (sgs[sg_id], 'found') if sg_id in sgs else (None, 'not_found')

    def fake_get_security_group_rules(session, region, sg_id):
        return rules.get(sg_id, [])

    def fake_get_attachment_map(session, region, errors=None, include_claude=False, claude_model=None):
        return attach_map

    def fake_get_vpc_cidr_blocks(session, region):
        return vpc_blocks

    def fake_get_subnet_cidr_blocks(session, region):
        return subnet_blocks

    def fake_get_account_public_ips(session, region, include_claude=False, claude_model=None):
        return public_ips

    def fake_get_prefix_list_names(session, region):
        return prefix_list_names

    monkeypatch.setattr(aws, 'get_security_group', fake_get_security_group)
    monkeypatch.setattr(aws, 'get_security_group_rules', fake_get_security_group_rules)
    monkeypatch.setattr(aws, 'get_attachment_map', fake_get_attachment_map)
    monkeypatch.setattr(aws, 'get_account_id', lambda session: '111111111111')
    monkeypatch.setattr(aws, 'get_vpc_cidr_blocks', fake_get_vpc_cidr_blocks)
    monkeypatch.setattr(aws, 'get_subnet_cidr_blocks', fake_get_subnet_cidr_blocks)
    monkeypatch.setattr(aws, 'get_account_public_ips', fake_get_account_public_ips)
    monkeypatch.setattr(aws, 'get_prefix_list_names', fake_get_prefix_list_names)

    return {
        'sgs': sgs, 'rules': rules, 'attach_map': attach_map,
        'vpc_blocks': vpc_blocks, 'subnet_blocks': subnet_blocks,
        'public_ips': public_ips, 'prefix_list_names': prefix_list_names,
    }


def _sg(sg_id, name, vpc_id='vpc-1'):
    return {'GroupId': sg_id, 'GroupName': name, 'Description': name, 'VpcId': vpc_id, 'OwnerId': '111111111111'}


def _rule(rule_id, sg_id, is_egress=False, protocol='tcp', from_port=443, to_port=443, **kwargs):
    r = {'SecurityGroupRuleId': rule_id, 'GroupId': sg_id, 'IsEgress': is_egress,
         'IpProtocol': protocol, 'FromPort': from_port, 'ToPort': to_port, 'Description': 'ok'}
    r.update(kwargs)
    return r


class TestChecksRunOnRootOnly:
    def test_downstream_sg_findings_are_suppressed(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['sgs']['sg-child'] = _sg('sg-child', 'child-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-child', 'UserId': '111111111111'}),
        ]
        # Child has its own allow-all + undocumented rule — must NOT produce findings.
        mock_aws['rules']['sg-child'] = [
            _rule('sgr-2', 'sg-child', from_port=0, to_port=65535, CidrIpv4='0.0.0.0/0', Description=None),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        assert result.findings == []
        assert result.nodes['sg-child'].findings == []

    def test_root_findings_are_produced(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', from_port=22, to_port=22, CidrIpv4='0.0.0.0/0', Description=None),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        check_ids = {f['check'] for f in result.findings}
        assert check_ids == {'sg_allows_all', 'sg_rule_no_description'}
        assert all(f['sg_id'] == 'sg-root' for f in result.findings)


class TestAttachmentsShownForEveryNode:
    def test_downstream_sg_gets_attachments_but_no_unused_finding(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['sgs']['sg-child'] = _sg('sg-child', 'child-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-child', 'UserId': '111111111111'}),
        ]
        mock_aws['rules']['sg-child'] = []
        mock_aws['attach_map'].update({
            'sg-root': [],  # unused -> should be flagged, it's the root
            'sg-child': [{'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1',
                          'resource_name': 'i-1', 'inferred': False}],
        })

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=True, include_claude=False, include_ip_resolution=False)

        assert result.nodes['sg-child'].attachments  # identified, shown
        assert result.nodes['sg-child'].findings == []  # but not audited
        assert any(f['check'] == 'sg_unused' and f['sg_id'] == 'sg-root' for f in result.findings)


class TestGraphTraversal:
    def test_cycle_does_not_infinite_loop(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['sgs']['sg-child'] = _sg('sg-child', 'child-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-child', 'UserId': '111111111111'}),
        ]
        mock_aws['rules']['sg-child'] = [
            _rule('sgr-2', 'sg-child', is_egress=True,
                  ReferencedGroupInfo={'GroupId': 'sg-root', 'UserId': '111111111111'}),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        assert set(result.nodes) == {'sg-root', 'sg-child'}
        assert len(result.edges) == 2

    def test_reference_to_missing_sg_is_not_found_not_error(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-gone', 'UserId': '111111111111'}),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        assert result.nodes['sg-gone'].status == 'not_found'
        assert any(f['check'] == 'sg_stale_rule' for f in result.findings)

    def test_cross_account_reference_is_external_and_not_traversed(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-other-acct', 'UserId': '222222222222'}),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        assert result.nodes['sg-other-acct'].status == 'external'
        # Not proof of staleness — no finding should fire for an unresolved cross-account ref.
        assert not any(f['check'] == 'sg_stale_rule' for f in result.findings)

    def test_max_depth_limits_traversal(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['sgs']['sg-mid'] = _sg('sg-mid', 'mid-sg')
        mock_aws['sgs']['sg-leaf'] = _sg('sg-leaf', 'leaf-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-mid', 'UserId': '111111111111'}),
        ]
        mock_aws['rules']['sg-mid'] = [
            _rule('sgr-2', 'sg-mid', ReferencedGroupInfo={'GroupId': 'sg-leaf', 'UserId': '111111111111'}),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root', max_depth=1,
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        assert 'sg-mid' in result.nodes
        assert 'sg-leaf' not in result.nodes


class TestCidrResolution:
    def test_universal_cidrs_are_listed_but_untraced(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['vpc_blocks'].append(_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16'))
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', CidrIpv4='0.0.0.0/0'),
            _rule('sgr-2', 'sg-root', CidrIpv6='::/0'),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=True)

        root = result.nodes['sg-root']
        assert {r['rule_id'] for r in root.cidr_rules} == {'sgr-1', 'sgr-2'}
        for r in root.cidr_rules:
            assert r['resolution']['kind'] == 'universal'

    def test_internal_and_external_cidrs_resolved(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['vpc_blocks'].append(_vpc('vpc-1', 'prod-vpc', '10.0.0.0/16'))
        mock_aws['subnet_blocks'].append(_subnet('subnet-a', 'vpc-1', 'us-east-1a', 'app-a', '10.0.1.0/24'))
        mock_aws['public_ips'].append({'ip': '203.0.113.5', 'service': 'ec2', 'resource_type': 'nat_gateway',
                                        'resource_id': 'nat-1', 'resource_name': 'nat-1', 'inferred': False})
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', from_port=5432, to_port=5432, CidrIpv4='10.0.1.0/24'),
            _rule('sgr-2', 'sg-root', CidrIpv4='203.0.113.5/32'),
            _rule('sgr-3', 'sg-root', CidrIpv4='198.51.100.9/32'),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=True)

        by_id = {r['rule_id']: r for r in result.nodes['sg-root'].cidr_rules}
        assert by_id['sgr-1']['resolution']['kind'] == 'internal'
        assert by_id['sgr-1']['resolution']['subnet_matches'][0]['subnet_id'] == 'subnet-a'
        assert by_id['sgr-2']['resolution']['kind'] == 'external'
        assert by_id['sgr-2']['resolution']['account_matches'][0]['resource_id'] == 'nat-1'
        assert by_id['sgr-3']['resolution']['kind'] == 'external'
        assert by_id['sgr-3']['resolution']['account_matches'] == []

    def test_sg_referenced_rules_are_not_treated_as_cidr_rules(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['sgs']['sg-child'] = _sg('sg-child', 'child-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', ReferencedGroupInfo={'GroupId': 'sg-child', 'UserId': '111111111111'}),
        ]
        mock_aws['rules']['sg-child'] = []

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=True)

        assert result.nodes['sg-root'].cidr_rules == []

    def test_prefix_list_resolved(self, mock_aws):
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['prefix_list_names']['pl-abc'] = 'com.amazonaws.us-east-1.s3'
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', is_egress=True, protocol='-1', from_port=None, to_port=None,
                  PrefixListId='pl-abc'),
        ]

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=True)

        r = result.nodes['sg-root'].cidr_rules[0]
        assert r['resolution'] == {'kind': 'prefix_list', 'prefix_list_id': 'pl-abc', 'name': 'com.amazonaws.us-east-1.s3'}


class TestExternalIpClaudeGuess:
    def test_unmatched_external_cidr_with_description_gets_a_guess(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', CidrIpv4='198.51.100.9/32', Description='Datadog agent per vendor docs'),
        ]
        captured = {}

        def fake_guess(rules, model=None):
            captured['rules'] = rules
            return {'sgr-1': 'Datadog monitoring agent'}

        monkeypatch.setattr(claude_helper, 'guess_external_sources', fake_guess)

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=True, include_ip_resolution=True)

        r = result.nodes['sg-root'].cidr_rules[0]
        assert r['resolution']['claude_guess'] == 'Datadog monitoring agent'
        assert captured['rules'][0]['description'] == 'Datadog agent per vendor docs'

    def test_unmatched_external_cidr_without_description_is_not_sent_to_claude(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', CidrIpv4='198.51.100.9/32', Description=None),
        ]

        def boom(*a, **k):
            raise AssertionError('must not call Claude for a rule with no description')

        monkeypatch.setattr(claude_helper, 'guess_external_sources', boom)

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=True, include_ip_resolution=True)

        r = result.nodes['sg-root'].cidr_rules[0]
        assert 'claude_guess' not in r['resolution']

    def test_matched_account_ip_is_not_sent_to_claude(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['public_ips'].append({'ip': '203.0.113.5', 'service': 'ec2', 'resource_type': 'nat_gateway',
                                        'resource_id': 'nat-1', 'resource_name': 'nat-1', 'inferred': False})
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', CidrIpv4='203.0.113.5/32', Description='our own NAT gateway'),
        ]

        def boom(*a, **k):
            raise AssertionError('must not call Claude when the IP already resolved to an account resource')

        monkeypatch.setattr(claude_helper, 'guess_external_sources', boom)

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=True, include_ip_resolution=True)

        r = result.nodes['sg-root'].cidr_rules[0]
        assert 'claude_guess' not in r['resolution']

    def test_disabled_when_include_claude_false(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', CidrIpv4='198.51.100.9/32', Description='some vendor range'),
        ]

        def boom(*a, **k):
            raise AssertionError('must not call Claude when include_claude=False')

        monkeypatch.setattr(claude_helper, 'guess_external_sources', boom)

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=True)

        r = result.nodes['sg-root'].cidr_rules[0]
        assert 'claude_guess' not in r['resolution']


class TestClaudeSuggestions:
    def test_suggestion_attached_to_no_description_finding(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', from_port=22, to_port=22, Description=None),
        ]
        monkeypatch.setattr(claude_helper, 'suggest_rule_descriptions',
                             lambda rules, model=None: {'sgr-1': 'SSH from bastion'})

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=True, include_ip_resolution=False)

        f = next(f for f in result.findings if f['check'] == 'sg_rule_no_description')
        assert f['suggestion'] == 'SSH from bastion'

    def test_no_suggestion_call_when_claude_disabled(self, mock_aws, monkeypatch):
        from sgtree import claude_helper
        mock_aws['sgs']['sg-root'] = _sg('sg-root', 'root-sg')
        mock_aws['rules']['sg-root'] = [
            _rule('sgr-1', 'sg-root', from_port=22, to_port=22, Description=None),
        ]

        def boom(*a, **k):
            raise AssertionError('should not be called when include_claude=False')

        monkeypatch.setattr(claude_helper, 'suggest_rule_descriptions', boom)

        result = tree.build(session=None, region='us-east-1', root_sg_id='sg-root',
                             include_attachments=False, include_claude=False, include_ip_resolution=False)

        f = next(f for f in result.findings if f['check'] == 'sg_rule_no_description')
        assert 'suggestion' not in f
