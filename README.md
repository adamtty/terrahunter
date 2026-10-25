<div align="center">

<img src="docs/assets/terrahunter-logo.png" alt="terrahunter" width="560">

### Point it at your Terraform. See your infrastructure, and how an attacker would move through it.

[![CI](https://github.com/adamtty/terrahunter/actions/workflows/ci.yml/badge.svg)](https://github.com/adamtty/terrahunter/actions/workflows/ci.yml)
[![CodeQL](https://github.com/adamtty/terrahunter/actions/workflows/codeql.yml/badge.svg)](https://github.com/adamtty/terrahunter/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/adamtty/terrahunter/badge)](https://scorecard.dev/viewer/?uri=github.com/adamtty/terrahunter)
![Python 3.11–3.14](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

</div>

> [!WARNING]
> **terrahunter is being rebuilt from the ground up.** This repository started again from scratch on
> 23 October 2026. All six stages of the pipeline below now run end to end (on AWS, Azure and Google Cloud), but
> it's early: expect rough edges, and check what it says against the code.

## The idea

Security scanners give you hundreds of findings, one resource at a time. What you actually want to know is the
question an attacker asks: **can the internet reach something, and where can it go from there?**

terrahunter answers that by drawing your infrastructure the way an architect would (accounts, VPCs, subnets,
services, the connections between them) and then walking you through each path an attacker could chain across it,
one hop at a time, with what's wrong at every step.

## How it works

1. **Point it at a folder.** Any repository checkout. terrahunter finds the Terraform root modules in it, wherever
   they sit.
2. **It tells you what's missing first.** Modules that haven't been downloaded, remote state, other repositories the
   connections run through. You fetch them, point at them, or skip them, and anything skipped is shown as unknown
   rather than silently left out.
3. **It maps the connections and draws the diagram.** An architecture diagram in the style of a cloud design tool,
   flat 2D or 3D isometric, with plumbing such as security groups and policy attachments folded into what they
   affect ("open to the internet on 22", "long-lived access key").
4. **It hunts for vulnerabilities.** trivy and checkov findings are attached to the resource they're about.
5. **It maps the attack paths.** Internet → a resource at the edge → resources inside: could an attacker chain these
   weaknesses together?
6. **It shows you the results.** Pick a path and walk through it: everything else fades, and each step zooms in on
   one hop and explains what's wrong there and what to fix.

## Status

| Stage | |
|---|---|
| 1. Folder in | **built**: `terrahunter <folder>` finds the root modules, says why each is one, and lets you pick (`--root`, `--all-roots`) |
| 2. What's missing | **built**: lists every module and remote state a root needs (followed through nested modules), matches remote state to the stack that writes it, offers to download modules, and takes other repositories with `--with` |
| 3. Connections and diagram | **built**: the connection graph (every resource in the root and its modules, every reference between them, through variables, locals and module outputs; `--graph-json`), and `terrahunter-diagram.html` on every run: an architecture diagram in 2D or 3D, plumbing folded into badges, unavailable modules drawn as dashed holes |
| 4. Vulnerabilities | **built**: runs [trivy](https://trivy.dev) and [checkov](https://www.checkov.io) (when installed; `--no-scan` skips them) on a contained copy of the root and every module it calls, and pins each finding to the resource it's about, in every instance of a module, so it shows on the diagram's components |
| 5. Attack paths | **built** (AWS, Azure, Google Cloud): finds what the internet reaches (load balancers and application gateways, VMs with a public IP behind an open security group, network security group or firewall rule, web apps, functions anyone may invoke, public databases, buckets and containers, long-lived access and service account keys), follows the traffic inwards, says how each workload could be taken over (SSH or RDP open, IMDSv1 behind a web port, the app itself), what it runs as (an IAM role, a managed identity, a service account, GCP's default compute service account), and which data stores that identity's policies, role assignments or IAM bindings reach, by service and scope; on the diagram, click a path and step through it hop by hop |
| 6. Results and walkthrough | **built**: in the diagram, click a path and step through it (everything else fades, each hop zooms in with what's wrong there); a fix list ranked by the paths each change breaks, with the file and line to change; `--report` writes it all as Markdown to share; `--fail-on` for CI |

## Usage

```sh
uv tool install git+https://github.com/adamtty/terrahunter
terrahunter path/to/terraform                 # pick a root, or --root envs/prod, or --all-roots
terrahunter map path/to/terraform             # just the map: connections and the diagram, no scanners
terrahunter . --root envs/prod --report terrahunter-report.md
terrahunter . --all-roots --fail-on critical  # in CI: exit 1 when a critical attack path exists
terrahunter . --as aws_iam_user.ci            # if these credentials leak: only from this identity
```

### If these credentials leak

Besides the paths from the internet, `terrahunter hunt` works out what each IAM user and role's credentials would
give an attacker who holds them: the data its own permissions reach, the roles it can assume, and the
privilege-escalation and lateral-movement techniques it has the permissions for (from the knowledge base:
PassRole into a new function or instance, rewriting its own policy, new code in an existing function, access keys
left in configuration it can read, …). Each identity that would give more is listed worst first, in the report and
the diagram, with every hop and the technique behind it. `--as ADDRESS` starts from named identities only;
`--no-credentials` skips it.

### Check by hand

Some of what a path rests on isn't in the Terraform, so terrahunter asks instead of guessing. Each question names the
resource and where to look, and lists the paths that depend on it:

- whether the application's code mishandles input, pointing at the code where it's in the folder;
- whether a key or password for an open SSH port exists elsewhere;
- whether a host keeps its containers from the metadata service;
- deploy-time scripts (provisioners, `null_resource`) and boot scripts that act on a resource on the path, with any
  credentials they carry;
- values the configuration doesn't settle;
- defaults the cloud adds (GCP's automatic Editor grant);
- the knowledge base's preconditions for each technique the path uses.

They're in the report, under each path, and on each step of the diagram's walkthrough.

### With a plan

Read from the code alone, terrahunter sees one node per resource block, and anything that depends on variables,
tfvars, conditionals or data sources stays an expression it can't judge. Give it a plan and it sees what will really
be deployed: every `count` and `for_each` instance (and none of a `count = 0` block), the resolved values (so a
security group opened by `var.public ? "0.0.0.0/0" : …` shows as open), and connections between instances.

```sh
terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
terrahunter . --root envs/prod --plan plan.json     # or: terrahunter map . --root envs/prod --plan plan.json
```

A state works too (`terraform show -json > state.json`). Making a plan needs the provider's credentials and the
backend, so it's optional: everything works without one. Values the plan marks sensitive are never used.

Each run prints what each root needs, the scanner findings, the attack paths and what to fix first, and writes
`terrahunter-diagram.html` (one self-contained page: open it in a browser). `terrahunter map` stops after the
connections and the diagram (stages 1 to 3): quick, and it needs neither trivy nor checkov. `terrahunter hunt` is the
full run, the same as plain `terrahunter`. Other options: `--with PATH` (another
repository the code reads from), `--fetch-modules`, `--graph-json PATH`, `--no-scan`, `--no-diagram`.

Variables are read the way Terraform reads them before talking to any cloud: defaults, `terraform.tfvars`,
`*.auto.tfvars`, then `--var-file PATH` and `--var NAME=VALUE`. What they evaluate to (and the locals and module
arguments built from them) replaces the expressions, so `cidr_blocks = [var.allowed]` is judged on its value, and a
block or module with `count = 0` (or an empty `for_each`) isn't on the map.

Exit codes: 0 done, 1 an attack path at or above `--fail-on`, 2 incomplete (something couldn't be read or scanned),
3 error.

## Where the knowledge comes from

What each resource type is, where it sits, what it connects to, when it's exposed and which settings are risky comes
from the terrahunter knowledge base, shipped as one file (`src/terrahunter/data/terrahunter-kb.json.gz`): 1,478
curated AWS, Azure and Google Cloud types with machine-readable conditions, the attack technique rules, AWS actions
and every AWS managed policy, and the Azure and Google Cloud roles. Its entries cite the providers' and the clouds'
own documentation; `src/terrahunter/data/NOTICE` lists the sources. `--kb PATH` (or `TERRAHUNTER_KB`) reads another
bundle, or a knowledge base checkout's `dist/`.

## Measuring it

`scripts/bench.py` scores the attack paths against the labelled benchmark in
[terrahunter-kb](https://github.com/adamtty/terrahunter-kb): deliberately vulnerable Terraform (TerraGoat, AWSGoat,
CloudGoat, IAM Vulnerable, CloudFoxable, sadcloud, AzureGoat, GCPGoat) with hand-written answer keys. It reports
recall (expected paths found, and how much of their data), precision (paths that match; those the key contradicts,
with its reason) and confidence side by side. Currently: recall 100% of the 72 internet paths (97% of the data they reach), precision 91%; and 97% of the 68 paths that start from credentials the project hands the attacker.

```sh
(cd ../terrahunter-kb && python scripts/bench/fetch.py)   # the projects, at their pinned commits
uv run python scripts/bench.py --kb ../terrahunter-kb --report bench.md
```

## Requirements

Python 3.11 or later. For stage 4, [trivy](https://trivy.dev/latest/getting-started/installation/) and
[checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html) on your `PATH`. Without them the rest still
runs, and the run says which scanner is missing (exit code 2: incomplete).

## Security

terrahunter is meant to run on Terraform you don't necessarily trust, such as a pull request from a stranger.
The scanners never see the folder itself. They get a copy holding only regular Terraform files, run from an empty
directory with a throwaway home, a minimal environment and no network. A module source that points outside the
folders under review stops the scan before it starts. See [SECURITY.md](SECURITY.md) for what that covers and how to
report a problem privately.

## License

[MIT](LICENSE). The knowledge base bundle's sources are listed in [its NOTICE](src/terrahunter/data/NOTICE).
