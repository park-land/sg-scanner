"""Tests for sgtree/report.py's tree rendering — specifically that ingress
and egress print as separate, clearly labeled groups (both for CIDR rule
bullets and for SG-reference subtree branches), and that the Claude guess
on an unmatched external IP surfaces in the printed line.
"""
from sgtree import report
from sgtree.tree import SGEdge, SGNode, TreeResult


def _node(sg_id, name='sg', status='found', cidr_rules=None):
    return SGNode(sg_id=sg_id, depth=0, status=status, name=name, vpc_id='vpc-1',
                  cidr_rules=cidr_rules or [])


def _cidr_rule(rule_id, direction, resolution, protocol='tcp', from_port=443, to_port=443):
    return {'rule_id': rule_id, 'direction': direction, 'protocol': protocol,
            'from_port': from_port, 'to_port': to_port, 'description': None, 'resolution': resolution}


class TestCidrRulesGroupedByDirection:
    def test_ingress_and_egress_print_under_separate_headers(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {'kind': 'universal', 'cidr': '0.0.0.0/0'}),
            _cidr_rule('sgr-2', 'egress', {'kind': 'universal', 'cidr': '0.0.0.0/0'}),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'ingress rules:' in out
        assert 'egress rules:' in out
        # ingress header must appear before the egress header
        assert out.index('ingress rules:') < out.index('egress rules:')

    def test_only_present_direction_gets_a_header(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {'kind': 'universal', 'cidr': '0.0.0.0/0'}),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'ingress rules:' in out
        assert 'egress rules:' not in out

    def test_rule_line_no_longer_repeats_direction(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {'kind': 'universal', 'cidr': '0.0.0.0/0'}),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert '[ingress' not in out  # direction now lives only in the group header
        assert '[tcp/443]' in out


class TestSgReferenceEdgesGroupedByDirection:
    def test_ingress_and_egress_children_print_under_separate_headers(self, capsys):
        root = _node('sg-root')
        child_a = _node('sg-child-a')
        child_b = _node('sg-child-b')
        edges = [
            SGEdge(from_sg='sg-root', to_sg='sg-child-a', rule_id='sgr-1', direction='ingress',
                   protocol='tcp', from_port=443, to_port=443),
            SGEdge(from_sg='sg-root', to_sg='sg-child-b', rule_id='sgr-2', direction='egress',
                   protocol='tcp', from_port=5432, to_port=5432),
        ]
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root, 'sg-child-a': child_a, 'sg-child-b': child_b},
                             edges=edges, findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'Ingress:' in out
        assert 'Egress:' in out
        assert out.index('Ingress:') < out.index('sg-child-a')
        assert out.index('sg-child-a') < out.index('Egress:')
        assert out.index('Egress:') < out.index('sg-child-b')


class TestExternalIpClaudeGuessRendering:
    def test_claude_guess_shown_when_present(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {
                'kind': 'external', 'cidr': '198.51.100.9/32', 'account_matches': [],
                'claude_guess': 'Datadog monitoring agent',
            }),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'Datadog monitoring agent' in out
        assert 'Claude guess' in out

    def test_no_guess_line_when_absent(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {
                'kind': 'external', 'cidr': '198.51.100.9/32', 'account_matches': [],
            }),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'Claude guess' not in out
        assert 'no match in this account' in out
