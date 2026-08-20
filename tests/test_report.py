"""Tests for sgtree/report.py's tree rendering — specifically that ingress
and egress print as separate, clearly labeled groups (both for CIDR rule
bullets and for SG-reference subtree branches), and that the Claude guess
on an unmatched external IP surfaces in the printed line.
"""
from sgtree import report
from sgtree.tree import SGEdge, SGNode, TreeResult


def _node(sg_id, name='sg', status='found', cidr_rules=None, attachments=None, findings=None):
    return SGNode(sg_id=sg_id, depth=0, status=status, name=name, vpc_id='vpc-1',
                  cidr_rules=cidr_rules or [], attachments=attachments or [], findings=findings or [])


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

    def test_rdap_data_without_a_claude_guess_does_not_lengthen_the_line(self, capsys):
        # RDAP data alone (no Claude guess) stays out of the inline line —
        # it still feeds the Claude reasoning section, just not printed here.
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {
                'kind': 'external', 'cidr': '198.51.100.9/32', 'account_matches': [],
                'rdap': {'org': 'Cloudflare, Inc.', 'network_name': 'CLOUDFLARENET', 'country': 'US'},
            }),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'registered to' not in out
        assert 'Cloudflare' not in out
        assert 'no match in this account' in out
        assert 'Claude guess' not in out

    def test_claude_guess_shown_without_rdap_details_alongside_it(self, capsys):
        # Even with RDAP data present, the inline line shows only the short
        # Claude guess — not the RDAP org/country/network name too.
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {
                'kind': 'external', 'cidr': '198.51.100.9/32', 'account_matches': [],
                'rdap': {'org': 'Cloudflare, Inc.', 'network_name': None, 'country': 'US'},
                'claude_guess': 'Cloudflare edge network',
            }),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_tree(result)
        out = capsys.readouterr().out

        assert 'Claude guess: "Cloudflare edge network"' in out
        assert 'registered to' not in out


class TestClaudeReasoningSection:
    def test_inferred_attachment_reasoning_is_listed(self, capsys):
        root = _node('sg-root', attachments=[
            {'service': 'ec2', 'resource_type': 'network_interface', 'resource_id': 'eni-x',
             'resource_name': 'Transfer Family server', 'inferred': True,
             'reasoning': "Description mentions an SFTP endpoint."},
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_claude_reasoning(result)
        out = capsys.readouterr().out

        assert 'eni-x' in out
        assert 'Transfer Family server' in out
        assert 'Description mentions an SFTP endpoint.' in out

    def test_deterministic_attachment_is_not_listed(self, capsys):
        root = _node('sg-root', attachments=[
            {'service': 'ec2', 'resource_type': 'instance', 'resource_id': 'i-1',
             'resource_name': 'i-1 (web-1)', 'inferred': False, 'reasoning': None},
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_claude_reasoning(result)
        out = capsys.readouterr().out

        assert out == ''

    def test_rule_description_suggestion_reasoning_is_listed(self, capsys):
        root = _node('sg-root')
        findings = [{
            'sg_id': 'sg-root', 'check': 'sg_rule_no_description', 'detail': 'root-sg has no description',
            'resource_type': 'security_group_rule', 'resource_id': 'sgr-1',
            'suggestion': 'SSH from bastion', 'suggestion_reasoning': 'Port 22 is the well-known SSH port.',
        }]
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=findings, errors=[])

        report.print_claude_reasoning(result)
        out = capsys.readouterr().out

        assert 'sgr-1' in out
        assert 'SSH from bastion' in out
        assert 'Port 22 is the well-known SSH port.' in out

    def test_external_ip_guess_reasoning_is_listed(self, capsys):
        root = _node('sg-root', cidr_rules=[
            _cidr_rule('sgr-1', 'ingress', {
                'kind': 'external', 'cidr': '198.51.100.9/32', 'account_matches': [],
                'claude_guess': 'home access for Alice Chen',
                'claude_reasoning': "Description reads \"Alice's home IP\".",
            }),
        ])
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_claude_reasoning(result)
        out = capsys.readouterr().out

        assert 'home access for Alice Chen' in out
        assert "Alice's home IP" in out

    def test_nothing_printed_when_no_claude_derived_items(self, capsys):
        root = _node('sg-root')
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])

        report.print_claude_reasoning(result)
        out = capsys.readouterr().out

        assert out == ''


class TestSeverityInFindings:
    def test_severity_tag_and_explanation_printed(self, capsys):
        root = _node('sg-root')
        findings = [{
            'sg_id': 'sg-root', 'check': 'sg_allows_all', 'detail': 'root-sg allows all ingress on port 5432',
            'resource_type': 'security_group_rule', 'resource_id': 'sgr-1',
            'severity': 'critical', 'severity_source': 'ai', 'severity_explanation': 'Public ALB attached.',
        }]
        report.print_findings(findings)
        out = capsys.readouterr().out

        assert '[CRITICAL]' in out
        assert 'Public ALB attached.' in out

    def test_findings_within_a_check_sorted_most_severe_first(self, capsys):
        findings = [
            {'sg_id': 'sg-root', 'check': 'sg_allows_all', 'detail': 'low one',
             'resource_type': 'security_group_rule', 'resource_id': 'sgr-1', 'severity': 'low'},
            {'sg_id': 'sg-root', 'check': 'sg_allows_all', 'detail': 'critical one',
             'resource_type': 'security_group_rule', 'resource_id': 'sgr-2', 'severity': 'critical'},
        ]
        report.print_findings(findings)
        out = capsys.readouterr().out

        assert out.index('critical one') < out.index('low one')

    def test_missing_severity_shows_unknown_tag_without_crashing(self, capsys):
        findings = [{'sg_id': 'sg-root', 'check': 'sg_unused', 'detail': 'unused',
                     'resource_type': 'security_group', 'resource_id': 'sg-root'}]
        report.print_findings(findings)
        out = capsys.readouterr().out
        assert '[?]' in out


class TestPrintPosture:
    def test_reachability_printed_with_source_tag(self, capsys):
        root = _node('sg-root')
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[],
                             reachability={'verdict': 'internet-exposed', 'explanation': 'Public instance attached.',
                                           'source': 'deterministic'})
        report.print_posture(result)
        out = capsys.readouterr().out

        assert 'INTERNET-EXPOSED' in out
        assert 'proven from attachments' in out
        assert 'Public instance attached.' in out

    def test_remediation_printed(self, capsys):
        root = _node('sg-root')
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[],
                             remediation={'top_fix': 'Restrict port 5432.', 'summary': 'Overall picture.'})
        report.print_posture(result)
        out = capsys.readouterr().out

        assert 'Restrict port 5432.' in out
        assert 'Overall picture.' in out

    def test_additional_risks_printed_and_labeled_non_deterministic(self, capsys):
        root = _node('sg-root')
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[],
                             additional_risks=[{'rule_id': 'sgr-1', 'concern': 'Broad internal CIDR.',
                                                 'severity': 'medium', 'reasoning': 'Covers 10.0.0.0/8.'}])
        report.print_posture(result)
        out = capsys.readouterr().out

        assert 'not deterministic findings' in out
        assert 'Broad internal CIDR.' in out
        assert '[MEDIUM]' in out

    def test_nothing_printed_when_all_absent(self, capsys):
        root = _node('sg-root')
        result = TreeResult(root_sg_id='sg-root', region='us-east-1', account_id='111111111111',
                             nodes={'sg-root': root}, edges=[], findings=[], errors=[])
        report.print_posture(result)
        out = capsys.readouterr().out
        assert out == ''
