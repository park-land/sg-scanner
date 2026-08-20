#!/usr/bin/env python3
"""CLI entrypoint: audit a single security group and map everything it
transitively references, applying the same checks as the account-wide
sg_checks.py scanner (allow-all ingress, undocumented rules, stale SG
references, unused SGs) to the root SG only. Downstream SGs found while
walking the reference tree are identified and their attachments resolved,
but not audited themselves. The root SG's CIDR/prefix-list rules are also
resolved: internal CIDRs map back to a VPC/subnet, external CIDRs are
checked against this account's own public IPs.

Claude-assisted enrichment (on by default, needs AWS_... plus Claude
credentials — see README):
  - ENI attachments that don't match a known AWS pattern get a best-guess
    owning resource from Claude instead of a raw description.
  - Root-SG rules with no description get a Claude-suggested one.
  - Root-SG rules whose CIDR is external and unmatched in this account get a
    Claude guess at what the range is, grounded in the rule's description and
    an RDAP registration lookup (who the range is registered to, and where).
All of these degrade silently (falls back to raw AWS/RDAP data, or nothing)
if Claude is unavailable.

Usage:
    ./sg_tree.py sg-0123456789abcdef0
    ./sg_tree.py sg-0123456789abcdef0 --region us-east-1
    ./sg_tree.py sg-0123456789abcdef0 --profile my-profile --json
    ./sg_tree.py sg-0123456789abcdef0 --no-attachments      # skip the ~21-service usage scan
    ./sg_tree.py sg-0123456789abcdef0 --no-claude           # skip Claude-assisted enrichment
    ./sg_tree.py sg-0123456789abcdef0 --no-ip-resolution    # skip CIDR -> VPC/subnet/public-IP mapping
    ./sg_tree.py sg-0123456789abcdef0 --no-rdap             # skip RDAP lookups for external IPs
    ./sg_tree.py sg-0123456789abcdef0 --max-depth 2
"""
import argparse
import sys

from sgtree import aws, claude_helper, report, tree


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sg_id', help='Security group id to audit, e.g. sg-0123456789abcdef0')
    parser.add_argument('--region', help='Region the SG lives in. If omitted, all enabled regions are probed.')
    parser.add_argument('--profile', help='AWS profile to use (defaults to the standard boto3 credential chain).')
    parser.add_argument('--max-depth', type=int, default=None,
                         help='Limit how many hops of SG-to-SG references to follow (default: unlimited).')
    parser.add_argument('--no-attachments', action='store_true',
                         help='Skip the resource-attachment scan (ENIs, Lambda, RDS, ECS, etc.) '
                              'and the sg_unused check. Much faster.')
    parser.add_argument('--no-claude', action='store_true',
                         help='Skip Claude-assisted enrichment (ENI resource guesses, rule-description '
                              'suggestions). Falls back to raw AWS data only.')
    parser.add_argument('--no-ip-resolution', action='store_true',
                         help="Skip resolving the root SG's CIDR/prefix-list rules to VPCs/subnets "
                              '(internal) or account-owned public IPs (external).')
    parser.add_argument('--no-rdap', action='store_true',
                         help='Skip RDAP registration lookups for external, unmatched CIDRs '
                              '(no outbound calls to third-party RDAP servers). Claude guesses at '
                              'those rules from their description alone, if any.')
    parser.add_argument('--claude-model', default=claude_helper.DEFAULT_MODEL,
                         help=f'Model to use for Claude-assisted enrichment (default: {claude_helper.DEFAULT_MODEL}).')
    parser.add_argument('--json', action='store_true', help='Emit machine-readable JSON instead of the tree view.')
    args = parser.parse_args()

    session = aws.get_session(args.profile)

    region = args.region
    if not region:
        if not args.json:
            print(f"No --region given; searching enabled regions for {args.sg_id} ...", file=sys.stderr)
        region = aws.find_sg_region(session, args.sg_id)
        if not region:
            print(f"Could not find {args.sg_id} in any enabled region for this account/profile.", file=sys.stderr)
            sys.exit(1)

    result = tree.build(
        session, region, args.sg_id,
        max_depth=args.max_depth,
        include_attachments=not args.no_attachments,
        include_claude=not args.no_claude,
        claude_model=args.claude_model,
        include_ip_resolution=not args.no_ip_resolution,
        include_rdap=not args.no_rdap,
    )

    if args.json:
        print(report.to_json(result))
        return

    report.print_tree(result)
    report.print_findings(result.findings)
    report.print_posture(result)
    report.print_claude_reasoning(result)
    report.print_errors(result.errors)


if __name__ == '__main__':
    main()
