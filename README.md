# sg-scanner

Audits a single AWS security group and maps its full reference tree on demand.

Takes one SG id, fetches its rules, and for every rule whose source/destination
is another security group, recursively fetches *that* SG and its rules too —
walking the whole reference graph reachable from the root. It ports the same
four checks an account-wide scanner would run against every SG, applied
**only to the root SG**:

| Check | Meaning |
|---|---|
| `sg_allows_all` | Ingress rule open to `0.0.0.0/0` / `::/0` on ports other than 80/443 |
| `sg_rule_no_description` | Rule has no description (Claude suggests one — see below) |
| `sg_stale_rule` | Rule references a security group that no longer exists |
| `sg_unused` | SG isn't attached to any resource or service config (EC2, Lambda, RDS, ECS, EKS, and ~15 more) |

Downstream SGs discovered while walking the tree are **identified and their
attachments resolved, but not audited** — this tool answers "is *this* SG OK,
and what does it lead to", not "audit every SG it touches".

Standalone CLI — no DB, no tenant/suppressions pipeline, no persisted state.
Prints a report (or `--json`). Ingress and egress always print as separate,
headed groups — both the root SG's CIDR/prefix-list rules and its SG-reference
subtrees — so the two directions don't have to be mentally sorted apart while
reading.

## What Claude does here

On by default (`--no-claude` to turn it off), used for three things — all
optional, all degrade to plain AWS data if Claude isn't reachable (see
[Claude-assisted enrichment](#claude-assisted-enrichment) below for the full
detail):

1. **Names unrecognized ENI attachments.** ~14 AWS-documented patterns resolve
   most ENIs deterministically (NAT Gateway, ALB, RDS Proxy, Lambda, …); Claude
   guesses at whatever's left, tagged `(Claude-inferred)`.
2. **Suggests descriptions** for root-SG rules that don't have one.
3. **Guesses what an unmatched external IP might be**, from the rule's own
   description text — only when a description exists to ground the guess in.

Nothing else in the tool depends on Claude — the checks, the tree traversal,
and the VPC/subnet CIDR resolution are all plain AWS API calls.

## Usage

```bash
pip install -r requirements.txt

./sg_tree.py sg-0123456789abcdef0
./sg_tree.py sg-0123456789abcdef0 --region us-east-1 --profile my-profile
./sg_tree.py sg-0123456789abcdef0 --json > report.json
./sg_tree.py sg-0123456789abcdef0 --no-attachments      # skip the slow usage scan
./sg_tree.py sg-0123456789abcdef0 --no-claude           # skip Claude-assisted enrichment
./sg_tree.py sg-0123456789abcdef0 --no-ip-resolution    # skip CIDR -> VPC/subnet/public-IP mapping
./sg_tree.py sg-0123456789abcdef0 --max-depth 2         # limit reference hops
```

If `--region` is omitted, the credentials' own default region (profile/env/
`AWS_DEFAULT_REGION`) is tried first, then every other enabled region.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

Tests are fully mocked (`sgtree.aws` and `sgtree.claude_helper` are patched
via `pytest`'s `monkeypatch`) — no AWS credentials or network access needed.
They run on every PR to `main` via [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Claude-assisted enrichment

On by default (`--no-claude` to disable), using the standard Anthropic
credential resolution (`ANTHROPIC_API_KEY`, `ant auth login`, etc. — see the
`anthropic` SDK docs). Falls back silently to raw AWS data if unavailable, so
the tool works fully without it. Three things use it, each batched into a
single API call per run:

- **Attachment resolution.** Every SG in the tree shows what it's attached
  to. When an attachment is an ENI, it's resolved to the actual owning
  resource rather than left as a bare `eni-xxxx`: a direct EC2 instance
  attachment and ~14 AWS-documented ENI description/InterfaceType patterns
  (NAT Gateway, VPC Endpoint, ELB, RDS Proxy, Lambda, ElastiCache, EFS,
  Directory Service, Transit Gateway, DAX, CloudHSM, Redshift, …) are
  resolved deterministically; anything left over is sent to Claude for a
  best-guess label, shown tagged `(Claude-inferred)`.
- **Rule description suggestions.** Every root-SG rule missing a description
  gets a Claude-suggested one printed alongside the `sg_rule_no_description`
  finding, inferred from the rule's protocol/ports/source.
- **External IP guesses.** A root-SG rule whose CIDR is external and doesn't
  match anything in this account has no further trail to follow through
  AWS — so if the rule has a description, Claude is asked to guess what the
  range might be from that description text (and the CIDR itself, if it
  happens to recognize a published range), shown as
  `Claude guess (from rule description): "..."`. A rule with no description
  is left as a plain "no match in this account" — there's nothing to ground
  a guess in, and undocumented rules already surface via
  `sg_rule_no_description`.

Model defaults to `claude-opus-5`; override with `--claude-model`.

## IP/CIDR resolution

On by default (`--no-ip-resolution` to disable). Every root-SG rule whose
source/destination is a CIDR or a managed prefix list — not an SG reference —
is resolved, **except `0.0.0.0/0` and `::/0`**, which are left alone (that's
"everything", not a location to trace — `check_allowall` already flags the
rule if it's actually wide open):

- **Internal** (the CIDR overlaps one of this account's VPC CIDR blocks in
  this region): mapped back to the owning VPC, and to the specific subnet(s)
  if the rule's CIDR is narrow enough to land inside one.
- **External** (no overlap with any of our VPCs): checked against this
  account's own public IPs — Elastic IPs, ENI auto-assigned public IPs, and
  NAT Gateway IPs — so a rule scoped to "the internet" that's actually just
  scoped to our own infrastructure doesn't get missed. Each matched IP is
  traced through to its **main resource**, not left as a bare ENI id — the
  same ENI resolution used for the attachment scan (an Elastic IP on an ALB's
  ENI shows `Application Load Balancer 'my-alb'`, on an instance's primary
  ENI shows the instance's Name tag, on an unrecognized ENI falls back to
  Claude same as attachments do). No match means it's genuinely external
  (public internet, on-prem, a partner network, …).
- **Managed prefix list** sources are resolved to the prefix list's name
  (e.g. `pl-xxxx` → `com.amazonaws.us-east-1.s3`).

CIDR-overlap classification is pure `ipaddress`-module arithmetic against
`describe_vpcs`/`describe_subnets`; public-IP main-resource tracing reuses
the same `describe_addresses`/`describe_network_interfaces`/
`describe_nat_gateways` + ENI-resolution logic (deterministic patterns, with
Claude as the fallback) as the attachment scan.

## Notes on traversal

- SG-to-SG references (`ReferencedGroupInfo`) are only ever valid within the
  same region, so the whole tree is resolved in a single region once the root
  SG's region is known.
- Already-visited SGs aren't re-fetched (cycles are common — two SGs that
  reference each other — and are handled without looping).
- A reference to a security group owned by a *different* AWS account (VPC
  peering) is reported as an external leaf and not traversed, since it can't
  generally be resolved with this account's credentials.
- `sg_unused` (root SG only) re-runs the same ~21-service scan the
  account-wide scanner uses (ENIs, launch templates/configs, Lambda, ECS,
  CodeBuild, RDS, ElastiCache, Glue, SageMaker, Batch, MSK, App Runner,
  Directory Service, EKS, Redshift, Step Functions, CloudFormation, SSM,
  Service Catalog, Elastic Beanstalk, VPC endpoints), but every SG in the
  tree gets its attachments listed regardless of the check — pass
  `--no-attachments` to skip that scan entirely for a much faster rules-only
  pass.

## IAM permissions

Read-only `Describe*`/`List*`/`Get*` across EC2, STS, Lambda, ECS, CodeBuild,
RDS, ElastiCache, Glue, SageMaker, Batch, Kafka (MSK), App Runner, Directory
Service, EKS, Redshift, Step Functions, CloudFormation, SSM, Service Catalog,
Elastic Beanstalk, and Auto Scaling. `AWS managed ReadOnlyAccess` policy
covers all of it; a tighter custom policy can be scoped down service by
service if needed.
