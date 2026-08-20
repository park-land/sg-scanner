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

These four checks are the **floor**: pure rule-based logic, no AI, and they
alone decide whether something *is* a finding at all. AI is layered strictly
on top to decide *how bad* and *why* — see
[AI-assessed severity, reachability & remediation](#ai-assessed-severity-reachability--remediation)
below — and is never allowed to make a finding disappear or rate a critical
one as anything less. [Evals](#evals) prove that guarantee holds, including
under prompt injection.

Downstream SGs discovered while walking the tree are **identified and their
attachments resolved, but not audited** — this tool answers "is *this* SG OK,
and what does it lead to", not "audit every SG it touches".

Standalone CLI — no DB, no tenant/suppressions pipeline, no persisted state.
Prints a report (or `--json`). Ingress and egress always print as separate,
headed groups — both the root SG's CIDR/prefix-list rules and its SG-reference
subtrees — so the two directions don't have to be mentally sorted apart while
reading.

## What Claude does here

On by default (`--no-claude` to turn it off), used for four things — all
optional, all degrade to plain deterministic behavior if Claude isn't
reachable:

1. **Rates severity, reads reachability, and prioritizes a fix** — the
   contextual layer on top of the four checks above, using the tree/
   attachments/exposure data this tool already computes. Also flags rules
   that look risky even though no check fired (a broad internal CIDR on an
   admin port, a description saying "temporary — remove"), strictly
   additive to the checks above. See
   [AI-assessed severity, reachability & remediation](#ai-assessed-severity-reachability--remediation).
2. **Names unrecognized ENI attachments.** ~14 AWS-documented patterns resolve
   most ENIs deterministically (NAT Gateway, ALB, RDS Proxy, Lambda, …); Claude
   guesses at whatever's left, tagged `(Claude-inferred)`.
3. **Suggests descriptions** for root-SG rules that don't have one.
4. **Guesses what an unmatched external IP might be**, as a short summary
   (e.g. `home access for Alice Chen`) from an RDAP registration lookup (who
   the range is registered to, and where — see
   [IP/CIDR resolution](#ipcidr-resolution)) and the rule's own description,
   combining whichever of those two is actually available.

Every one of these prints short inline; the full reasoning behind each — what
Claude actually based it on — lands separately in a **Claude reasoning**
section at the end of the report.

Nothing else in the tool depends on Claude — the checks, the tree traversal,
the RDAP lookup itself, and the VPC/subnet CIDR resolution are all plain
API calls with no Claude involved.

## Usage

```bash
pip install -r requirements.txt

./sg_tree.py sg-0123456789abcdef0
./sg_tree.py sg-0123456789abcdef0 --region us-east-1 --profile my-profile
./sg_tree.py sg-0123456789abcdef0 --json > report.json
./sg_tree.py sg-0123456789abcdef0 --no-attachments      # skip the slow usage scan
./sg_tree.py sg-0123456789abcdef0 --no-claude           # skip Claude-assisted enrichment
./sg_tree.py sg-0123456789abcdef0 --no-ip-resolution    # skip CIDR -> VPC/subnet/public-IP mapping
./sg_tree.py sg-0123456789abcdef0 --no-rdap             # skip RDAP lookups for external IPs
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

## Evals

Two tiers, in [`evals/`](evals/) — the combination is the point: hard metrics
prove the safety guarantee, judge-based scoring covers the free text a metric
can't grade, and neither substitutes for the other.

**Offline — no API key, part of every PR** (`tests/test_evals_deterministic.py`,
`tests/test_evals_floor_guarantee.py`, plus harness-logic tests for every
live eval module below):

- **Deterministic precision/recall.** The four checks against
  [`evals/fixtures.py`](evals/fixtures.py) (~26 synthetic scenarios spanning
  critical/app/safe ports, every exposure shape, hygiene checks, and
  adversarial variants). Should read 1.0/1.0 — it's a regression guard on
  rule-based logic, not a judgment measurement — and building it caught two
  real bugs already fixed: `check_allowall` crashed on an "all traffic"
  (protocol `-1`) rule instead of flagging it, and once fixed, a second bug
  surfaced where such a rule was being silently *exempted* by the safe-port
  carve-out meant for a narrow range like `1-1000` that happens to include
  443 — the single most dangerous SG rule shape was invisible to the tool.
  Both are fixed in `sgtree/checks.py`, with regression tests locking in
  the correct behavior.
- **The severity floor guarantee — the headline number.** For every
  critical-port fixture, `severity.clamp()` is run against a battery of
  hostile/malformed responses — including literal prompt-injection text as
  the claimed severity, wrong types, case variants — and the result must
  never fall below the required floor. **Zero violations, always** — this is
  a property of the code (`clamp()` can't be talked out of it), not of model
  behavior, so it's exhaustive and belongs in every PR, not just a live run.

**Live — needs `ANTHROPIC_API_KEY`, run manually** (`python -m
evals.run_live_evals`, or the `evals` GitHub Actions workflow via
`workflow_dispatch`; not run on every PR since it calls the real API and
costs money):

- **AI severity accuracy** (`evals/live_severity.py`) — exact-match,
  within-one-level, and "meets-or-exceeds-expected" accuracy against each
  fixture's expected severity, a confusion matrix, and the **AI-vs-baseline
  delta**: how often the contextual severity actually differs from the flat/
  uniform baseline every `sg_allows_all` finding used to get, and how often
  that difference lands closer to the expected label — the number that
  argues the AI pass earns its place over the old flat treatment.
- **LLM-as-judge** (`evals/judge.py`) — scores every piece of free text this
  tool has Claude write (severity explanations, remediation, rule-description
  suggestions, ENI labels, external-IP guesses) 1-5 on accurate / grounded /
  specific / calibrated, and separately flags a **grounding failure** — a
  fact stated that isn't in the input — as a hard fail regardless of the
  numeric scores.
- **Adversarial, against the real model** (`evals/adversarial.py`) —
  measures (not just asserts) whether Claude *itself*, unclamped, resists
  prompt injection embedded in rule descriptions and SG names, and whether
  an external-IP guess follows RDAP registration data over a rule
  description that names a contradicting, unsupported vendor. Distinct from
  the floor guarantee: that eval proves the code is safe regardless of model
  behavior; this one measures the model behavior itself, which is useful
  signal on prompt quality but never the safety guarantee.

A run writes [`evals/EVAL_REPORT.md`](evals/EVAL_REPORT.md), checked in — the
version in this repo reflects the last offline-only run (real numbers, not
fabricated) and notes that the live sections need `ANTHROPIC_API_KEY` to
populate; run `python -m evals.run_live_evals` locally with a key to fill
them in and update the checked-in report.

## AI-assessed severity, reachability & remediation

The four checks above decide *whether* something is a finding — that never
changes based on AI. This layer, on top, decides *how bad* and *why*, using
context the checks themselves don't carry: what's attached to the SG, what
references it, the port's typical service, the rule's own description. One
`analyze_security_posture` Claude call per report (`--no-claude` to disable;
everything below then falls back to non-AI defaults rather than disappearing)
produces four things, all attached to the root SG only:

- **Contextual severity.** `sg_allows_all` on Postgres and on an obscure app
  port get identical weight from the check alone — a human doesn't read them
  as equal. Claude assigns `info`/`low`/`medium`/`high`/`critical` per
  finding from the tree/attachment context, with a one-sentence explanation.
  **Hard floor, enforced in code, not in the prompt:** an allow-all rule
  covering SSH (22), RDP (3389), or a database/cache port (MSSQL, Oracle,
  MySQL, PostgreSQL, Redis, Cassandra, Elasticsearch, Memcached, MongoDB,
  CouchDB, etcd) is clamped to at least `high` regardless of what the model
  returns — `sgtree/severity.py`'s `clamp()` runs on every AI severity
  unconditionally, so a wrong, malformed, or adversarially-influenced
  response literally cannot produce a below-floor result. Without Claude,
  every finding still gets this same floor-respecting baseline severity —
  just without the contextual nuance or explanation.
- **Reachability verdict.** `internet-exposed` / `internal-only` / `unused` /
  `uncertain`, from the same graph + attachment + public-IP data the rest of
  the tool already resolves. A deterministic read
  (`sgtree/exposure.py`) wins outright whenever the attachments prove it
  either way (no attachments = `unused`; no rule open to the world =
  `internal-only`; a rule open to the world *and* a directly-public resource
  attached = `internet-exposed`) — Claude's read only fills the gap where
  attachments alone are genuinely ambiguous (e.g. a load balancer whose
  public/internal Scheme this tool doesn't independently verify).
- **Prioritized remediation.** One top-priority fix plus a short overall
  summary, spanning everything found on the root SG.
- **Additive, intent-aware findings.** Rules that look risky from their own
  facts even though no check fired — an internal CIDR broad enough to cover
  an entire VPC supernet on an admin port, a description reading "temporary,
  remove before prod" that's still there. Shown in their own section, always
  tagged **not a deterministic finding** — this list can only add to what
  the checks found, never explain one away or replace it.

```
HIGH SEVERITY (from sg_allows_all)
  root-sg allows all ingress on port 5432
      severity: Postgres open to 0.0.0.0/0 on an SG fronting a public ALB — directly exploitable.

  Reachability
  INTERNET-EXPOSED  (proven from attachments)
      Ingress is open to the internet and a directly public resource is attached (i-0abc123).

  Remediation (Claude)
  Top fix: Restrict port 5432 ingress to the application tier's security group.

  Additional AI-flagged risks (1) — not deterministic findings
  [MEDIUM] rule sgr-9: 10.0.0.0/8 open on port 22 with no description covers the entire VPC.
```

See [Evals](#evals) for the eval suite that proves the floor holds — including
under prompt injection embedded in a rule description — and quantifies how
often the contextual severity actually beats the flat baseline.

## Claude-assisted enrichment

On by default (`--no-claude` to disable), using the standard Anthropic
credential resolution (`ANTHROPIC_API_KEY`, `ant auth login`, etc. — see the
`anthropic` SDK docs). Falls back silently to raw AWS data if unavailable, so
the tool works fully without it. Three more things use it (in addition to
the severity/reachability/remediation layer above), each batched into a
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
  match anything in this account has no AWS trail to follow — so it gets an
  [RDAP registration lookup](#ipcidr-resolution) (who the range is actually
  registered to, and where), and if either that or the rule's own
  description has anything to go on, Claude is asked to synthesize a terse
  (~6 words) plain-language guess from whichever is available, in "purpose
  for subject" phrasing where the rule supports it — e.g. `Claude guess:
  "home access for Alice Chen"`, `Claude guess: "Cloudflare edge network"`.
  Claude only ever uses a name/team/vendor that's actually written in the
  rule's description or returned by RDAP — it's told explicitly not to
  invent one. A rule with neither a description nor resolvable RDAP data is
  left as a plain "no match in this account" — there's nothing to ground a
  guess in.

Every guess/suggestion above is deliberately short for the inline view. The
full reasoning behind each one — what in the description, RDAP data, or ENI
metadata Claude actually based it on — prints separately in a **Claude
reasoning** section after the findings, so nothing gets taken on faith:

```
============================================================
  Claude reasoning (2)
============================================================

  [sg-0123...] rule sgr-2 (198.51.100.9/32) → guess "home access for Alice Chen"
      because: Description reads "Alice's home IP for VPN access".
  [sg-0123...] attachment eni-0abc → "Transfer Family server"
      because: InterfaceType and description both point to AWS Transfer Family.
```

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

An external CIDR with no account match also gets an **RDAP registration
lookup** (on by default regardless of `--no-claude`; `--no-rdap` to disable)
— a direct query to whichever regional registry (ARIN/RIPE/APNIC/LACNIC/
AFRINIC) actually holds that range, via the public `rdap.org` bootstrap
redirector (no API key, no third-party service account). It surfaces who
the range is registered to, the registry's network name, and the
registration country — not printed inline (that line stays short), but it's
the input that grounds the Claude guess described above, and shows up in
full in the [Claude reasoning](#claude-assisted-enrichment) section when it
does. This does send the external IPs found in your rules to a third-party
RDAP server; pass `--no-rdap` if you don't want that outbound lookup
happening at all.

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
