# FIP v2 — Installation and Operations

Forensic Isolation Program, version 2. Acquires forensic copies of potentially
compromised EC2 instances, isolates them, and lands the evidence in a dedicated
forensic account under your own key with a signed chain-of-custody manifest.

**How this manual is laid out.** §3 and §4 are the procedures: short, one `fip` command
per step, each linked to its entry in the [command reference](#6-command-reference)
(§6), which has every option, what success looks like and the details. §7 onward is
background, read when you need it. The appendices do the same work with `aws` and `cdk`
commands, for when `fip` is unavailable. Teardown lives in
[../cdk/RECOVERY.md](../cdk/RECOVERY.md).

> **Status.** Acquisition, containment, evidence copy and signed manifests are built and
> exercised against live instances (Linux and Windows, standalone and in Auto Scaling
> groups), as are incident cases (§5) and the evidence release path. Large fleet-scale
> runs and the isolated analysis workstation are built but have not yet been exercised
> against live instances. Memory capture, detonation and GuardDuty triggers are **not**
> built.
> See [What FIP does not do](#13-what-fip-does-not-do).

## Contents

- [1. What you get](#1-what-you-get)
  - [The commands](#the-commands)
- [2. Before you install](#2-before-you-install)
  - [Accounts](#accounts)
  - [Prerequisites](#prerequisites)
  - [Control Tower](#control-tower)
- [3. Install](#3-install)
  - [3.1 Configure](#31-configure)
  - [3.2 Test or production: decide before you deploy](#32-test-or-production-decide-before-you-deploy)
  - [3.3 Deploy](#33-deploy)
  - [3.4 Check the install](#34-check-the-install)
  - [3.5 Add a member account later](#35-add-a-member-account-later)
- [4. Responding to an incident](#4-responding-to-an-incident)
  - [4.1 Testing only: create a test instance](#41-testing-only-create-a-test-instance)
  - [4.2 Open or find the case](#42-open-or-find-the-case)
  - [4.3 Find the instance](#43-find-the-instance)
  - [4.4 Isolate it](#44-isolate-it)
  - [4.5 Check on it later](#45-check-on-it-later)
  - [4.6 Collect the evidence](#46-collect-the-evidence)
  - [4.7 Give an examiner access](#47-give-an-examiner-access)
  - [4.8 Restore the instances](#48-restore-the-instances)
  - [4.9 Close the case](#49-close-the-case)
  - [4.10 Testing only: clean up](#410-testing-only-clean-up)
- [5. Cases](#5-cases)
  - [5.1 Two ways to respond](#51-two-ways-to-respond)
  - [5.2 What a single isolation records](#52-what-a-single-isolation-records)
  - [5.3 fip case](#53-fip-case)
- [6. Command reference](#6-command-reference)
  - [6.1 fip configure](#61-fip-configure)
  - [6.2 fip deploy](#62-fip-deploy)
  - [6.3 fip doctor](#63-fip-doctor)
  - [6.4 fip instances](#64-fip-instances)
  - [6.5 fip test-instance](#65-fip-test-instance)
  - [6.6 fip isolate](#66-fip-isolate)
  - [6.7 fip status](#67-fip-status)
  - [6.8 fip evidence](#68-fip-evidence)
  - [6.9 fip verify](#69-fip-verify)
  - [6.10 fip signing-key](#610-fip-signing-key)
  - [6.11 fip release](#611-fip-release)
  - [6.12 fip restore](#612-fip-restore)
  - [6.13 fip cleanup](#613-fip-cleanup)
  - [6.14 fip version](#614-fip-version)
  - [6.15 fip case](#615-fip-case)
- [7. Reading a manifest](#7-reading-a-manifest)
  - [Integrity and origin](#integrity-and-origin)
  - [Integrity by hand](#integrity-by-hand)
  - [Reading a case log](#reading-a-case-log)
- [8. Production retention — a decision, not a default](#8-production-retention--a-decision-not-a-default)
- [9. Containment and Auto Scaling](#9-containment-and-auto-scaling)
  - [What happens, in order](#what-happens-in-order)
  - [Why a replacement is not launched by default](#why-a-replacement-is-not-launched-by-default)
  - [Undoing it after a restore](#undoing-it-after-a-restore)
- [10. Analysis access](#10-analysis-access)
  - [How an examiner gets in](#how-an-examiner-gets-in)
  - [Deploy](#deploy)
  - [Connect](#connect)
  - [Release the evidence to the analysis account](#release-the-evidence-to-the-analysis-account)
  - [Mount evidence read-only](#mount-evidence-read-only)
  - [Cost, and turning it off](#cost-and-turning-it-off)
- [11. Tags, and finding what FIP made](#11-tags-and-finding-what-fip-made)
- [12. Troubleshooting](#12-troubleshooting)
- [13. What FIP does not do](#13-what-fip-does-not-do)
- [14. Further reading](#14-further-reading)
- [Appendix A. Setup with shell commands](#appendix-a-setup-with-shell-commands)
  - [A.1 Set the account ids and profiles](#a1-set-the-account-ids-and-profiles)
  - [A.2 Set the retention posture](#a2-set-the-retention-posture)
  - [A.3 Bootstrap and deploy the two central stacks](#a3-bootstrap-and-deploy-the-two-central-stacks)
  - [A.4 Issue an external ID per member account](#a4-issue-an-external-id-per-member-account)
  - [A.5 Deploy the member stack](#a5-deploy-the-member-stack)
- [Appendix B. Isolation with shell commands](#appendix-b-isolation-with-shell-commands)
  - [B.1 Launch a test instance by hand](#b1-launch-a-test-instance-by-hand)
  - [B.2 Find the instance by hand](#b2-find-the-instance-by-hand)
  - [B.3 Start an isolation by hand](#b3-start-an-isolation-by-hand)
  - [B.4 Watch an isolation by hand](#b4-watch-an-isolation-by-hand)
  - [B.5 Collect and verify the evidence by hand](#b5-collect-and-verify-the-evidence-by-hand)
  - [B.6 Clean up a test by hand](#b6-clean-up-a-test-by-hand)
  - [B.7 Restore by hand](#b7-restore-by-hand)

---

## 1. What you get

| | |
|---|---|
| **Isolate** | Every network interface moved to a security group with no ingress and no egress rules |
| **Protect the fleet** | Instance detached from its Auto Scaling group, and the group is **prevented from launching a replacement** (§9) |
| **Acquire** | Crash-consistent multi-volume snapshot, tagged at creation |
| **Verify** | SHA-256 Merkle digest over the block stream, without attaching, mounting or booting anything |
| **Move** | Snapshot copied into the evidence account, re-encrypted under your forensic key |
| **Attest** | Manifest signed with an asymmetric key, written to an Object Lock bucket |
| **Optionally stop** | The instance, if you ask for it |
| **At fleet scale** | One run covers many instances across many accounts. A target that fails is recorded, not fatal to the run |
| **Keep an incident together** | An incident case gathers every run, ticket, comment, release and restore of one incident in a signed, chained log (§5) |

FIP never terminates an instance and never deletes a snapshot. Those permissions are
absent from its roles and denied by a permissions boundary. The one command that
removes anything, `fip cleanup --test`, runs with your own profiles, not FIP's roles. It
touches only what is tagged `fip:class=test` (§11).

### The commands

One executable, `fip`. Every subcommand takes `--help`; §6 is the full reference.

| Command | Does | Reference |
|---|---|---|
| `fip configure` | Collect and check the install configuration | [§6.1](#61-fip-configure) |
| `fip deploy` | Install or update every stack, in order, checking each | [§6.2](#62-fip-deploy) |
| `fip doctor` | Check the install can do its job | [§6.3](#63-fip-doctor) |
| `fip instances` | List instances in the member accounts, as targets | [§6.4](#64-fip-instances) |
| `fip test-instance` | Testing only: launch an instance to try FIP on | [§6.5](#65-fip-test-instance) |
| `fip isolate` | Contain and acquire one or more instances, as one isolation run | [§6.6](#66-fip-isolate) |
| `fip status` | Where a case or a run stands | [§6.7](#67-fip-status) |
| `fip evidence` | Download a case's or a run's signed records and verify them | [§6.8](#68-fip-evidence) |
| `fip verify` | Check one signed record | [§6.9](#69-fip-verify) |
| `fip signing-key` | Export the public signing key | [§6.10](#610-fip-signing-key) |
| `fip release` | Give, or withdraw, an analysis account access to a case's evidence | [§6.11](#611-fip-release) |
| `fip restore` | Put contained instances back on their original security groups | [§6.12](#612-fip-restore) |
| `fip cleanup` | List what FIP made, or remove what a test made | [§6.13](#613-fip-cleanup) |
| `fip version` | Which checkout `fip` runs from | [§6.14](#614-fip-version) |
| `fip case` | Incident cases: tickets, signed comments, the isolations of one incident, moves, merges, close and reopen | [§6.15](#615-fip-case) |

---

## 2. Before you install

### Accounts

FIP uses three roles, which may be three accounts or fewer:

| Role | Holds | Must be yours? |
|---|---|---|
| **Orchestrator** | State machine, Lambda, manifest signing key. No evidence | Yes |
| **Evidence** | Forensic CMK, Object Lock bucket, case table, evidence copies | Yes |
| **Analysis** | Where an examiner works. Optional, may be outside your organization | No |

**Member accounts** are the ones FIP covers: where the instances it isolates run.
Separating orchestrator from evidence is recommended; collapsing them is supported.

**You do not need AWS Organizations.** Where you have one, FIP adds
`aws:PrincipalOrgID` conditions as defense in depth; without one, trust rests on named
account principals plus an external ID.

### Prerequisites

- Node.js 20+ and `npm`
- `jq` and `openssl`
- AWS CLI v2, with credentials that can deploy CloudFormation in each account
- A region. FIP is single-region per deployment; deploy again per region

**One AWS CLI profile per account.** CDK does not switch accounts for you, and fails
with `IncorrectDefaultCredentials` when the credentials belong to another account, even
the management account. `fip configure` finds a profile you already have for each
account, or creates one.

### Control Tower

If you run Control Tower, vend accounts through **Account Factory**, not
`organizations:CreateAccount` — a raw-API account lands unenrolled and unbaselined.
Avoid OUs whose SCPs restrict bucket configuration to the Control Tower execution role;
CDK's deploy role is not that principal.

---

## 3. Install

By hand, with `aws` and `cdk`: [Appendix A](#appendix-a-setup-with-shell-commands).

### 3.1 Configure

From the folder where this repository is checked out:

```sh
cd cdk && npm ci && ./bin/fip configure
```

Answer its questions; Enter accepts the default shown. Answer `Yes` when it offers to put
`fip` on your PATH, so later steps can use plain `fip`. It changes nothing in AWS, and
ends with `All profiles check out.` Reference: [§6.1](#61-fip-configure).

### 3.2 Test or production: decide before you deploy

**Test** is the default: nothing is locked, so a test leaves nothing undeletable. For
**production**, you choose how long evidence is locked; FIP has no default:

```sh
fip configure --production --retention-days 365 --retention-mode GOVERNANCE
```

What that means and how to choose: [§8](#8-production-retention--a-decision-not-a-default).

### 3.3 Deploy

```sh
fip deploy --dry-run    # shows what it would run; changes nothing
fip deploy
```

Answer `y` when CDK asks to change IAM permissions. It ends with
`FIP is deployed and every check passed.` Rerun it to update. Reference:
[§6.2](#62-fip-deploy).

### 3.4 Check the install

```sh
fip doctor
```

Every line must read `ok`. Reference: [§6.3](#63-fip-doctor).

### 3.5 Add a member account later

```sh
fip configure            # add the account id to the member list
fip deploy --only members
```

---

## 4. Responding to an incident

Open or find the incident's case first, then isolate each host into it as you find it.
Every later step can then name the case, and acts on every host in it. When you know
exactly what to isolate and expect nothing more, the case is optional: skip §4.2 and
§4.9, drop `--case $CASE` from `fip isolate`, use the run id it prints in place of
`$CASE`, and restore each host with `fip restore $TARGET` (§5.1 says when).

The steps share three values:

| | Looks like | Comes from |
|---|---|---|
| `CASE` | `case-20261105T101500Z-3f9a1c` | `fip case open` prints it, or `fip case list` |
| `TARGET` | `444444444444:i-0123456789abcdef0` | `fip instances`, or `fip test-instance` |
| `RUN` | `fip-20261104T040328Z-62b079` | `fip isolate` prints it: one isolation run |

By hand, with `aws` commands: [Appendix B](#appendix-b-isolation-with-shell-commands).

### 4.1 Testing only: create a test instance

Skip in a real incident.

```sh
TARGET=$(fip test-instance --quiet)
```

Remove it afterwards with §4.10. Reference: [§6.5](#65-fip-test-instance).

### 4.2 Open or find the case

```sh
fip case list                                         # is one already open?
fip case open --ticket INC-1234 --comment "beaconing from web tier"
CASE=case-20261105T101500Z-3f9a1c                     # printed by open
```

The ticket is your own system's id, and optional; add one later with `fip case ticket`.
Reference: [§6.15](#615-fip-case).

### 4.3 Find the instance

```sh
fip instances --name 'web-*'
TARGET=444444444444:i-0cfa397d72897506e      # from the TARGET column
```

Reference: [§6.4](#64-fip-instances).

### 4.4 Isolate it

```sh
fip isolate --case $CASE $TARGET --dry-run     # every target must read OK
fip isolate --case $CASE $TARGET --watch       # asks to confirm, then follows the run
```

Several targets, in any accounts, go in one command; run it again for each host found
later. The run ends `ACQUIRED`; `PARTIAL` and `FAILED` are explained in
[§5.2](#52-what-a-single-isolation-records). Without `--case`, `fip isolate` lists any
open cases and proceeds without one; `fip case move` puts the run in a case afterwards.
Options, such as `--stop`: [§6.6](#66-fip-isolate).

### 4.5 Check on it later

```sh
fip status $CASE
```

Lists every host in the case: its acquisition, whether it is still contained, and who
its evidence is shared to. For one run's copy progress: `fip status $RUN --watch`.
Reference: [§6.7](#67-fip-status).

### 4.6 Collect the evidence

```sh
fip evidence $CASE
```

Every record must verify, and the case log must check as a chain. Reference:
[§6.8](#68-fip-evidence); what a manifest holds: [§7](#7-reading-a-manifest).

### 4.7 Give an examiner access

```sh
fip release --case $CASE --to 333333333333
```

Every host's evidence, under one grant. Reference: [§6.11](#611-fip-release); the
analysis account itself: [§10](#10-analysis-access).

### 4.8 Restore the instances

Only once you have decided each is fit to reconnect.

```sh
fip restore --case $CASE --dry-run     # "Originals from" must say the signed manifest
fip restore --case $CASE               # ends with "Restored." for each host
```

Name members after the case to restore only those. Auto Scaling capacity is not put back
for you; the output gives the command. Reference: [§6.12](#612-fip-restore).

### 4.9 Close the case

```sh
fip release --case $CASE --to 333333333333 --revoke    # once the examiner is done
fip case close $CASE --comment "contained; RCA in INC-1234"
```

Close is refused while any host is still contained or any evidence is still shared.
Closing deletes nothing. Reference: [§6.15](#615-fip-case).

### 4.10 Testing only: clean up

**Never in a real case**: it deletes the evidence.

```sh
fip cleanup --test --dry-run
fip cleanup --test
```

Reference: [§6.13](#613-fip-cleanup).

---

## 5. Cases

**Terms.**

| Term | Means |
|---|---|
| **Isolation run** | One `fip isolate` command, with any number of targets: id `fip-<UTC time>-<random>`. Older output and tags call it a case id (`fip:case-id`, `--case-id`) |
| **Incident case**, or **case** | One incident: id `case-<UTC time>-<random>`. Holds members, tickets, comments, and a state: open, closed, or merged |
| **Member** | One target of one run, recorded in a case: `<run id>/<instance id>`. A member is in at most one case |
| **Alias** | A case merged into another. Commands given its id act on the case it merged into |
| **Case log** | The case's signed, chained records, schema `fip.case/1` ([§7](#reading-a-case-log)) |

### 5.1 Two ways to respond

| You know | Use | Why |
|---|---|---|
| **Exactly what to isolate**, and expect nothing more | `fip isolate` alone (§4) | One run, one record. A case would only add bookkeeping |
| **There is an incident, but not yet every instance in it**, or more may turn up during assessment and containment | `fip case` (§5.3), then `fip isolate --case` for each host as you find it | Every isolation, release and restore is kept together under one incident, with its tickets and comments |

`fip isolate` will never open or join a case on its own. It joins one only when you name
it with `--case` or `--ticket`. If a case is open when you run it without either, it
says so and lists the open cases, then proceeds without one. Containment never waits on
case bookkeeping. A host isolated that way can be moved into the case afterwards with
`fip case move` (§5.3).

### 5.2 What a single isolation records

Each run of `fip isolate`, with any number of targets in any member accounts, has its
own id, `fip-<UTC time>-<random>`, which keys everything it made:

| Where | What |
|---|---|
| `fip-cases` table, evidence account | The row: state, targets, release history |
| Evidence bucket, `cases/<id>/<instance-id>/manifest.json` | One signed manifest per target |
| Evidence bucket, `cases/<id>/custody/` | Signed records of each release, revoke and restore |
| `fip:case-id` tag | On each instance, its volumes and interfaces, and every snapshot |
| `fip:case` tag | On every snapshot and evidence copy of a run made with `--case`: the incident case. A convenience for the console, not evidence; the case log is the record |

| State | Meaning |
|---|---|
| `IN_PROGRESS` | Targets still running |
| `ACQUIRED` | Every target succeeded |
| `PARTIAL` | Some succeeded, some failed. **The evidence from the successful targets is real and complete.** Rerun the failed targets with `--case-id` |
| `FAILED` | No target succeeded |

A run is not rolled back because one instance was unreachable. Its records stay for as
long as retention (§8) and your own policy say.

`fip isolate --case-id <id> <targets>` adds targets to an earlier run's id. Use it to
rerun failed targets. The state and counts describe every run under the id, and a later
run that succeeds clears an earlier run's failure. For a growing incident, use a case
(§5.3) rather than one ever-larger run. A run made with `--case` stays in that case:
re-running its id with a different `--case` is refused.

### 5.3 `fip case`

The verbs are in §6.15; `isolate`, `status`, `restore`, `release` and `evidence` accept
a case (§6.6, §6.7, §6.8, §6.11, §6.12).

A **case** is one incident. It holds the isolations made under it (each still a
`fip isolate` run, with its own id and records, unchanged), tickets from your own
systems, signed comments, and a state, open or closed.

A developing incident, start to finish:

```sh
fip case open --ticket INC-1234 --comment "beaconing from web tier"
CASE=case-20261105T101500Z-3f9a1c                # printed by open

fip isolate --case $CASE 111122223333:i-0abc    # the first host
fip isolate --case $CASE 444455556666:i-0def    # found an hour later
fip case move fip-20261105T094000Z-77aa01 --to $CASE \
    --comment "isolated before the case was opened"   # an earlier, standalone run
fip case show $CASE                              # everything, as a timeline
fip release --case $CASE --to 333333333333      # every host's evidence at once
fip case close $CASE --comment "contained; RCA in INC-1234"
```

| Command | Does |
|---|---|
| `fip case open [--ticket T]… [--comment C]` | Open an incident and print its id |
| `fip case list [--all] [--ticket T]` | List open cases; `--all` adds closed cases and every isolation run |
| `fip case show <case> [--verify]` | The case as a timeline, with its log verified |
| `fip case ticket <case> T [--comment C]` | Add a ticket. A case may carry several, from different systems |
| `fip case comment <case> C` | Add a signed, permanent comment |
| `fip isolate --case <case>` | Record an isolation run under the case |
| `fip case move <isolation or target>… --to <case> --comment C` | Move a whole isolation (`fip-…`), one target of it (`fip-…/i-…`) or every member of a case (`case-…`) into another case |
| `fip case merge <into> <from>… --comment C` | Fold whole cases into one. Each `<from>` becomes an alias of `<into>` |
| `fip case close <case> --comment C [--force]` | Close. Refused while any host is still contained or any evidence is still shared; `--force` overrides, and is recorded |
| `fip case reopen <case> --comment C` | Reopen a closed case |

Wherever a case id is accepted, `--ticket T` also works if exactly one case carries
that ticket; if several do, the command lists them and refuses to guess.

**What a move or merge changes.** Only which case lists an isolation. Evidence stays
where it was written and nothing signed is rewritten; each move is itself a signed
record in both cases' logs. A host's containment is never touched. Access already
released to an analysis account stays with the snapshots, so `fip case show` reports
release state per host.

**A merged case is an alias.** Any command given its id acts on the case it merged into
and says so. Its tickets are copied to that case, so `--ticket` finds the survivor.
There is no unmerge: a mistaken merge is corrected by moving the members back, which
leaves both moves in the record.

**Two responders at once.** Every move and merge is one database transaction,
conditioned on what the command read: the member is still where it was, and both cases
are still open. If someone else changed any of it first, the command is refused and
changes nothing, and the signed record it had already written is followed by a signed
`ABORTED` note. `show` marks such a record as withdrawn.

---

## 6. Command reference

Every command reads `~/.fip/install.env`, written by `fip configure`, for its accounts,
profiles and region, so nothing needs to be set in your shell. The commands that act in
AWS run as the orchestrator; an `AWS_PROFILE` you set yourself still wins. Every
command takes `--help` and `--region R`.

### 6.1 `fip configure`

```
fip configure [options]
fip configure --show
```

Asks for the region, the account ids, the role to sign in with, test or production, and
your own tags. Under AWS Organizations it lists your accounts to choose from. For each
account it uses a profile you already have that reaches it, or creates one named
`fip-orchestrator`, `fip-evidence` or `fip-member`, and never replaces one without
asking. It signs in with each to prove it lands in the right account. It saves to
`~/.fip/install.env` and changes nothing in AWS. Rerun it to change anything; what is
saved is offered as the default.

| Option | Meaning |
|---|---|
| `--region R` | Default `us-east-1` |
| `--orchestrator ID`, `--evidence ID` | The two central accounts. They may be the same |
| `--member ID[=PROFILE]` | An account FIP covers. Repeatable. `=PROFILE` names an existing profile for it |
| `--analysis ID` / `--no-analysis` | The optional account where examiners work (§10) |
| `--org-id ID` / `--no-org` | Your AWS Organizations id, or `--no-org` if you have none. Looked up if omitted; if the lookup fails, `fip deploy` stops until you give one of the two |
| `--admin-role NAME` | The role FIP's profiles assume in each account. Default `AWSControlTowerExecution`; accounts made by AWS Organizations usually have `OrganizationAccountAccessRole` |
| `--source-profile NAME` | Credentials those profiles start from. Default `default` |
| `--orchestrator-profile P`, `--evidence-profile P` | Use an existing profile rather than create one |
| `--responder Yes\|No` | Deploy the member role that contains and acquires. `No` installs only the read-only inventory role, for visibility before an engagement |
| `--allow-restore Yes\|No` | Let `fip restore` reconnect instances. Default `Yes`; §6.12 says what it permits |
| `--test` / `--production` | Test, the default, locks nothing. Production locks every signed record (§8) |
| `--retention-days N`, `--retention-mode M` | Production only. No default for days; mode `GOVERNANCE` (default) or `COMPLIANCE` (§8) |
| `--tag KEY=VALUE` / `--no-tags` | Your own tags, such as a cost center (§11). Repeatable; replaces the saved list |
| `--link` / `--no-link` | Put `fip` on your PATH as a link in `~/.local/bin`. Default: ask |
| `--overwrite-profiles` | Replace existing `fip-*` profiles without asking |
| `--yes` | Ask nothing; fail if something required is missing |
| `--show` | Print the saved configuration |

Without questions, for scripts:

```sh
fip configure --yes --region us-east-1 \
  --orchestrator 111111111111 --evidence 222222222222 --member 444444444444 \
  --test --tag cost-center=security
```

**Worked when** it prints `All profiles check out.`

By hand: [Appendix A.1](#a1-set-the-account-ids-and-profiles) and
[A.2](#a2-set-the-retention-posture).

### 6.2 `fip deploy`

```
fip deploy [--only core|orchestrator|members] [--member ID] [--yes] [--dry-run]
```

Installs or updates FIP from the saved configuration, in order, checking each step
before the next:

1. **Pre-flight**: each profile lands in its own account.
2. **CDK bootstrap** in the evidence and orchestrator accounts, where missing.
3. **`FipCoreStack`** (evidence), then checks Object Lock is enabled **with no default rule**.
4. **`FipOrchestratorStack`**, then checks the signing key. It must follow the core stack.
5. **Each member account**: issues its external ID, deploys `FipMemberStack`, then
   checks the trust path: the right external ID accepted, a wrong or missing one refused.

| Option | Meaning |
|---|---|
| `--only STEP` | Only `core`, `orchestrator` or `members`. Pre-flight always runs |
| `--member ID` | Only this member account. Repeatable; it must be configured |
| `--yes` | Do not stop for CDK's approval of IAM changes |
| `--dry-run` | Show every command it would run. Changes nothing |

**Worked when** it ends `FIP is deployed and every check passed.` Any `FAIL` stops it
there, with the reason.

**Safe to rerun**, and that is how to update: bootstrap is skipped where it exists, an
existing external ID is reused, never overwritten, and an unchanged stack is left alone.

**The external ID.** Each member account gets its own unpredictable identifier, issued
by you, not chosen by the account's owner, and stored in the orchestrator account. It
stops one member account inducing your orchestrator to act against another. It is not
a secret, but it must be unguessable and yours to assign.

**Bootstrap grants `AdministratorAccess` unless you say otherwise**, CDK's default for
the role CloudFormation deploys with. To narrow it, bootstrap by hand (Appendix A.3)
with `--cloudformation-execution-policies`; `fip deploy` then skips bootstrap. `iam:*`
must remain, because CDK cannot create roles without it.

**Member accounts you don't deploy to yourself.** The member template,
`cdk/synth/FipMemberStack.template.json`, needs no bootstrap and can be deployed as
a StackSet. Appendix A.5 gives its parameters.

**The organization is checked.** It stops before changing anything unless
`~/.fip/install.env` names an organization id or `none`. After deploying each member it
reads back every FIP role's trust policy and fails unless `aws:PrincipalOrgID` matches.
Installs configured before this check, with no organization recorded, stop once: rerun
`fip configure --org-id o-…` or `fip configure --no-org`, then `fip deploy`. Member
stacks deployed before then lack the organization condition even where one was
configured; `fip deploy --only members` adds it.

By hand: [Appendix A.3](#a3-bootstrap-and-deploy-the-two-central-stacks) to
[A.5](#a5-deploy-the-member-stack).

### 6.3 `fip doctor`

```
fip doctor [--member ID]
```

Checks, read-only, everything a case needs: the tools, the state machines, the signing
key, the evidence role and what it may and may not do, Object Lock, and for each member
account the external ID and the roles. `--member ID` checks just that account;
repeatable. Each check corresponds to something that has failed in practice.

**Worked when** every line reads `ok`. Run it after installing, and again before you
need FIP, not during an incident.

### 6.4 `fip instances`

```
fip instances [--member ID] [--name PATTERN] [--all]
```

Lists the instances in the member accounts. Changes nothing.

```
TARGET                               STATE      TYPE         NAME                         CASE
444444444444:i-0cfa397d72897506e     running    t3.micro     web-01                       -
```

`TARGET` is what `isolate` and `restore` take. `CASE` is the case FIP already opened on
the instance, if any.

| Option | Meaning |
|---|---|
| `--member ID` | Only this account |
| `--name PATTERN` | Only instances whose Name tag matches, such as `'web-*'` |
| `--all` | Include terminated and shutting-down instances |

It exits 1, with a hint, when nothing matches. By hand:
[Appendix B.2](#b2-find-the-instance-by-hand).

### 6.5 `fip test-instance`

```
fip test-instance [--member ID] [--type TYPE] [--subnet ID] [--quiet]
```

Testing only. Launches a small instance, waits until it runs, and prints it as a
target. It is tagged `fip:class=test`, so `fip cleanup --test` removes it and its
snapshots. It bills by the second until then.

| Option | Meaning |
|---|---|
| `--member ID` | Account to launch in. Default: the first configured |
| `--type TYPE` | Default `t3.micro` |
| `--subnet ID` | Needed when the account has no default VPC |
| `--quiet` | Print only the target, for `TARGET=$(fip test-instance --quiet)` |

If the account encrypts new volumes by default with the AWS-managed key `aws/ebs`,
`fip isolate` refuses the instance, rightly: that key cannot be shared, so the evidence
could never be copied. Use a key of your own. By hand:
[Appendix B.1](#b1-launch-a-test-instance-by-hand).

### 6.6 `fip isolate`

```
fip isolate [options] <account>:<instance> [<account>:<instance> …]
```

Contains and acquires each target, as one isolation run: moves every interface to a security
group with no rules, detaches the instance from its Auto Scaling group without a
replacement, snapshots and hashes the volumes, copies them to the evidence account,
and writes a signed manifest. The steps, in order: [§9](#9-containment-and-auto-scaling).
It confirms first and prints the run id near the top.

| Option | Meaning |
|---|---|
| `--dry-run` | Pre-flight only. Starts nothing; the run id it prints is thrown away |
| `--watch` | Then follow the run until it finishes, as `fip status --watch` |
| `--case-id ID` | Add the targets to an earlier run (§5.2). Default: a new id |
| `--case CASE` | Record this run under an open incident case (§5.3). Checked before anything is touched: a closed or unknown case stops the run in pre-flight |
| `--ticket T` | The same, naming the case by a ticket exactly one case carries |
| `--stop` | Stop each instance after containment. **Off** by default: it is service-affecting and loses instance-store data |
| `--allow-replacement` | Let an Auto Scaling group launch a replacement. **Off** by default; [§9](#why-a-replacement-is-not-launched-by-default) says why |
| `--yes` | Skip the confirmation |

**Every target is pre-flighted before any is touched.** A mistyped id, an account with
no external ID, or a stack never deployed fails in seconds and names the target. If any
target fails, **nothing** is started.

**How long.** It prints an expected duration per target and for the run, and when a
run still `IN_PROGRESS` is worth looking into. It is an order of magnitude, from
provisioned volume size: a small Linux instance takes about nine minutes, a 30 GiB
Windows volume about fifty. Targets run four at a time, so a large run goes in waves.

Ctrl-C stops `--watch`, not the run. By hand:
[Appendix B.3](#b3-start-an-isolation-by-hand).

### 6.7 `fip status`

```
fip status <run-id> [--watch] [--interval N]
fip status <case-id | --ticket T> [--watch]
```

**Given an incident case** (`case-…`), it lists every member: its account, how its
acquisition stands, whether its host is **still contained** (asked of the member
account: is any interface on an FIP isolation group; this changes nothing), and which analysis
accounts its evidence is **shared to**. Release state is per member: it follows the
evidence into whatever case holds it now, so a merged case can show some members
shared and some not. `--watch` refreshes while any member is still acquiring; for a
run's copy progress, `fip status <run id>`.

**Given an isolation run** (`fip-…`):

Prints the run's state (§5.2), each target's state, the custody events, and the
progress of the evidence copies: size, percent complete, throughput, ETA. `--watch`
refreshes until the run leaves `IN_PROGRESS`, every `--interval` seconds (default 20).

**Early on it shows almost nothing.** A target appears only once its acquisition
finishes, and reads `not yet recorded` until then, about eight minutes for a small
Linux instance.

**The ETA is an order of magnitude.** Size and percent are EC2's; throughput is
extrapolated. Sizes are provisioned, not used, so the ETA is pessimistic early. Hashing
follows the copy and is not in it. By hand: [Appendix B.4](#b4-watch-an-isolation-by-hand).

### 6.8 `fip evidence`

```
fip evidence <run-id | case-id | --ticket T> [--out DIR]
```

**Given an incident case**, it downloads the case's log and custody records into
`case/`, each member's manifest and its run's custody records into `members/<run>/`,
and the log and custody records of every case merged into it, however many merges
back, into `merged/<case>/`. A release made before a merge is recorded only in the
merged case, so those records belong to the evidence. It verifies every one, and checks
each case log as a **chain**: a record deleted, reordered or replaced fails even when
each remaining record verifies on its own.

**Given an isolation run**, it downloads the run's manifests and custody records into
`./<run-id>`, or `--out DIR`, and verifies each as `fip verify --ours` does. Either way
it changes nothing in AWS.

You get one `manifest.json` per instance, in a folder named for it, and a `custody/`
folder once evidence is released or an instance restored. **Worked when** the last
line reads `All N record(s) verified: unchanged, and signed by this installation.` A
`FAIL` means that record is not to be trusted (§7).

These are the records. The evidence itself is the snapshots in the evidence account,
and they stay there. By hand: [Appendix B.5](#b5-collect-and-verify-the-evidence-by-hand).

### 6.9 `fip verify`

```
fip verify <file> [--ours | --key-id ARN | --public-key FILE]
```

Checks one manifest or custody record, and answers two questions:

- **Integrity**: has it changed since it was signed? Always checked; needs only the file.
- **Origin**: was it signed by your key? Checked only with one of the options.

| Option | Compares the key in the file with | Needs |
|---|---|---|
| (none) | Nothing: origin reads `NOT CHECKED` | Only the file |
| `--ours` | This installation's signing key | Orchestrator credentials |
| `--key-id ARN` | A signing key in KMS | Credentials that can read it |
| `--public-key FILE` | A key file from `fip signing-key` | Nothing in AWS |

**Worked when** the last two lines read `Integrity ... VERIFIED` and
`Origin ...... VERIFIED`. `NOT CHECKED` is not a failure, but integrity alone proves
little: anyone can sign a forged record with a key of their own. Why, and checking by
hand with `openssl`: [§7](#7-reading-a-manifest).

### 6.10 `fip signing-key`

```
fip signing-key [--out FILE]
```

Writes this installation's public signing key to `fip-signing-key.pem`, or `--out
FILE`, and prints its fingerprint. It is a public key: safe to share, and it cannot
sign. Give it to anyone outside your accounts who must check a record's origin, and
send the fingerprint **by a different channel**, so one intercepted channel cannot
substitute both. They run `fip verify <file> --public-key fip-signing-key.pem`.

### 6.11 `fip release`

```
fip release (--case <run-id | case-id> | --ticket T) --to <account> [--revoke] [--dry-run] [--yes]
```

**Given an incident case**, it releases every member's evidence copies, read from the
members by the Lambda rather than from the command line, under **one KMS grant per
case**, named `fip-<case-id>`. It shows the plan first: each member, its snapshots,
and who they are shared to now. A member still acquiring has no copies yet and is
listed as not covered. A revoke removes the share from every member's copies and
retires the grants of the case **and of every case merged into it**. Each release or
revoke is a signed custody record under the case, an entry on each member's run, and a
`RELEASED` or `REVOKED` record in the case log. A closed case releases nothing; reopen
it first. A revoke is always allowed.

**Given an isolation run**, it does the same for that run's evidence alone, but only
for a run in no case. A run whose hosts are in an incident case is refused, with the
case to use instead, so that every release is in the case's log and a closed case stays
closed.

Either way it gives an analysis account (§10) a share of each evidence snapshot and a
KMS grant on the forensic key. It needs both: a shared encrypted snapshot cannot be
opened without the grant. The grant is created first, and if the signed record cannot
be written, the shares and the grant are withdrawn again, so access never exists
without its record. The snapshot ids come from the table, not the command line. The
account may be outside your organization.

The analysis account may create volumes from the snapshots and decrypt them; not delete
them, re-encrypt anything under your key, or widen its own access. The grant includes
`ReEncryptFrom` because EBS re-encrypts a volume made from another account's snapshot
into the analysis account's own key; that moves data out of your key, never into it.
A release made before this grant included it lets the analysis account see the
snapshots but not build volumes from them: revoke and release again. Each release writes a
signed custody record, `cases/<id>/custody/<time>-release.json`, and an entry on the
row.

| Option | Meaning |
|---|---|
| `--revoke` | Remove the share **and** retire the grant. Removing only the share would leave access that the snapshot's permissions do not show |
| `--dry-run` | Show what would happen. Changes nothing |
| `--yes` | Skip the confirmation |

> **A revoke does not reach volumes already created.** A volume the analysis account
> made while it had access still exists there. FIP ends access; it cannot recover copies.

### 6.12 `fip restore`

```
fip restore <account>:<instance> [--dry-run] [--yes]
fip restore (--case C | --ticket T) [<member>…] [--dry-run] [--yes]
```

**Given an incident case**, it asks each member account which hosts are still
contained, then restores those, or only the members named (`fip-…/i-…` or `i-…`). Every
plan is shown first and one confirmation covers them all. Each host is then restored
exactly as below, with its own signed custody record.

Puts a contained instance back on the security groups it had, taken from the case's
signed manifest. **It reconnects the instance**: if it is still compromised, it can
reach out again at once. It runs as the orchestrator; no login to the member account is
needed.

The plan lists each interface, its current groups and the groups it would get back:

| Status | Meaning |
|---|---|
| `RESTORE` | Will go back to the groups shown |
| `OK` | Already on its original groups. Only the tag is cleared |
| `SKIP` | No record of its original groups. Left alone |
| `BLOCKED` | Left alone: an original group no longer exists, or the interface's tag disagrees with the signed manifest, meaning someone changed the tag |

**Worked when** `Originals from` reads `the signed manifest (signature checked)`, and
the run ends `Restored.` with each interface `result: RESTORED` and a `Custody record`
line. It checks the groups after the change rather than assuming the call worked.

**Where the groups come from.** The manifest, after checking its signature and that
this installation signed it. Containment also writes a `fip:original-sgs` tag on each
interface, but anyone in the member account can edit a tag, so it is only a cross-check.
It stands alone only when a case failed before writing its manifest, and the plan then
says `the fip:original-sgs tag only`.

**What it changes.** It removes the `fip:original-sgs` tag, because a later case would
otherwise record today's groups as the originals. It keeps `fip:case-id`, which links
the instance to its evidence, and the isolation group, which is free and reused. Each
restore writes a signed custody record. **Auto Scaling changes are reported, with the
command to undo each, but not undone** (§9).

**What `--allow-restore Yes` permits** (§6.1, the default). FIP's member role may
attach any **existing** security group in that account to an interface FIP has tagged.
IAM cannot check that the groups are the recorded originals, so `fip restore` enforces
that from the signed manifest. The role still cannot create a group with rules, add a
rule, or touch an instance FIP has not tagged. To keep restore a human step, configure
`--allow-restore No`, then `fip deploy`.

**After upgrading from a version without restore**, run `fip deploy` once. Until then it
fails with `unknown action 'restore'` or access denied.

By hand: [Appendix B.7](#b7-restore-by-hand).

### 6.13 `fip cleanup`

```
fip cleanup --list
fip cleanup --test [--dry-run] [--yes]
```

`--list` shows everything tagged `application=fipv2` in each configured account, with
its class (§11) and incident case (`fip:case`), grouped by both. Changes nothing.

`--test` terminates instances and deletes snapshots tagged both `application=fipv2` and
`fip:class=test`: the test instance and its snapshots, in the member and evidence
accounts. It shows them and asks first; `--dry-run` only shows them. It runs with your
own profiles, not FIP's roles. **Never run it in a real incident.**

**Worked when** `fip cleanup --test --dry-run` afterwards prints
`Nothing tagged application=fipv2 and fip:class=test in any configured account.`

**What stays, deliberately:** the manifests and custody records, the case row, and the
isolation group `fip-isolation-<vpc>`. None costs anything to speak of. In a
production install, a test instance's evidence copy is labeled `evidence`, so cleanup
leaves it; delete it as [Appendix B.6](#b6-clean-up-a-test-by-hand) describes.
Evidence and FIP's own stacks are never removed by this. To uninstall FIP, see
`cdk/RECOVERY.md`.

### 6.14 `fip version`

Prints the version, the commit, and where `fip` resolved to. **If you link `fip` from
a removable or network volume, it breaks when that volume is not mounted**, and you
will find out during an incident; this is the quickest check that the link still
points at a real checkout.

### 6.15 `fip case`

```
fip case open    [--ticket T]… [--comment C]
fip case list    [--all] [--ticket T]
fip case show    <case | --ticket T> [--verify]
fip case ticket  <case | --ticket T> T [--comment C]
fip case comment <case | --ticket T> C
fip case move    <member>… (--to <case> | --ticket T) --comment C
fip case merge   <into> <from>… --comment C
fip case close   <case | --ticket T> --comment C [--force]
fip case reopen  <case | --ticket T> --comment C
```

Incident cases: when to use one is §5.1, the whole design §5.3. Wherever a case is
named, `--ticket T` also works if exactly one case carries that ticket.

| Verb | Does |
|---|---|
| `open` | Opens a case, `case-<UTC time>-<random>`, and prints `CASE=…` to set. Tickets and a comment are optional and go in its first record |
| `list` | Open cases, newest first. `--all` adds closed cases and every isolation run, which show as kind `isolation`. `--ticket T` filters |
| `show` | State, tickets and a timeline of every event, with who did it. Given an isolation run's id (`fip-…`), shows that run instead |
| `ticket` | Adds a ticket from your own system. Refused if the case already carries it, or is not open |
| `comment` | Adds a comment. It is signed and permanent, so write it as you would a note in a case file |
| `move` | Moves members into an open case. A member is `fip-…/i-…`; `fip-…` names every target of that run, and `case-…` every member of that case. One `MEMBER_MOVED` record goes in each case's log; members in no case have only the destination's. `--comment` is required |
| `merge` | Moves every member of each `<from>` into `<into>`, then makes each `<from>` an alias (`MERGED` in both logs). Tickets may be given in place of case ids. `--comment` is required |
| `close` | Closes the incident. It first asks every member account whether each host is still contained, and reads each member's share state. **Refused** while any host is contained, any evidence is shared, or any host could not be checked. `--force` overrides, and the `CLOSED` record lists exactly what it overrode. Closing deletes nothing: retention (§8) still decides how long evidence is kept. A closed case takes no new members, moves or releases; a revoke still works |
| `reopen` | Opens a closed case again. `--comment` is required |

**Isolating into a case.** `fip isolate --case C` (or `--ticket T`) records the run's
targets in the case as it starts, before any host is touched. Each target becomes a
**member**, named `<run id>/<instance id>`. One `MEMBER_ATTACHED` record names them, and
`show` lists them. A closed or unknown case refuses the run at its first step. The run's
own id, records and evidence are unchanged; the case only points at them.

**The case log.** Each event is a signed record, schema `fip.case/1` (fields:
[§7](#reading-a-case-log)), at
`cases/<case-id>/log/<sequence>.json` in the evidence bucket, under the same Object Lock
settings as manifests (§8). Each record holds the SHA-256 of the one before it, so a
deleted, reordered or replaced record is detectable even in test mode, where nothing is
locked. Records are signed by the orchestrator Lambda with the manifest key; the CLI
never signs. Two responders writing at once cannot fork the log: each record's sequence
number is claimed by a conditional write, and the loser retries at the next number.

**Worked when** `show` ends
`Log ............. VERIFIED  N record(s), each signed by this installation, none missing or out of order`.
A `FAIL` names the record and the problem; `--verify` prints the check for every record.
Each record can also be checked on its own with `fip verify <file> --ours` (§6.9).

`open`, `ticket` and `comment` run as the orchestrator; `list` and `show` read with the
evidence profile, as `fip evidence` does. A case's row in `fip-cases` is an index kept in
step with its log; the log is the record.

---

## 7. Reading a manifest

The manifest records the instance as found, the containment actions including **the
original security groups**, the source snapshots, the evidence copies, both hashes, and
an ECDSA P-384 signature with the public key needed to verify it.

Two hashes are recorded and they are **not** interchangeable:

- **`evidence[].sha256`** — taken over the retained copy in your evidence account. This
  is the hash of record and what later verification runs against.
- **`sourceAttestation[].sha256`** — what was read in the member account at acquisition
  time.

**They are not expected to match, and nothing should compare them.** A snapshot and its
cross-account copy have been measured to differ in at least one block while both read
back stably. Comparing them produces a false integrity failure, which for evidence is
worse than no check at all.

The digest is a Merkle root, not a plain `sha256sum` of a disk image. The manifest
records the block size, the volume size and every range digest, so a third party can
recompute it independently.

### Integrity and origin

| Question | What a pass proves | What it does not prove |
|---|---|---|
| **Integrity:** has this file changed since it was signed? | Nobody altered it after signing | Who signed it |
| **Origin:** was it signed by *your* FIP signing key? | It came from your FIP installation | Nothing further; with integrity, this is the whole claim |

Integrity alone is not enough to rely on a record. The public key travels inside the
file, so anyone can fabricate a record, sign it with a key of their own, and it will
pass every integrity check. Origin closes that gap by comparing the key inside the
file with the key you expect. Who checks which:

| Who | Command | Checks |
|---|---|---|
| Anyone holding the file: examiner, counsel, an opposing expert | `fip verify manifest.json` | Integrity |
| The FIP operator | `fip verify manifest.json --ours` | Integrity and origin |
| Someone outside your accounts, with your key file (§6.10) | `fip verify manifest.json --public-key fip-signing-key.pem` | Integrity and origin |

`fip verify` prints the fingerprint of the key inside the file as `Embedded key`, so it
can also be compared with a fingerprint read out by phone.

**What the integrity check does**, in order. The fourth step is the one hand-rolled
verification usually misses:

1. the envelope carries the exact bytes that were signed
2. those bytes hash to the digest recorded beside them
3. the ECDSA P-384 signature over those bytes verifies under the embedded public key
4. **the readable copy in the envelope matches the signed bytes**. An envelope whose
   `manifest` was edited while `signedPayloadBase64` was left alone passes 1 to 3

The `keyId` field in the file is a **label**, outside the signed bytes, and anyone can
edit it. `fip verify` prints it as `Key label` and never relies on it. Before November
2026, `--key-id` compared only that label, so a forged record carrying your key's ARN
passed. It now compares the key itself.

### Integrity by hand

With nothing but `jq` and `openssl`. This is also what each envelope's own
`signature.verify` field contains, and like `fip verify` without an expected key, it
establishes integrity only:

```sh
ENV=manifest.json

jq -r .signature.signedPayloadBase64 "$ENV" | base64 -d > signed-manifest.json
jq -r .signature.value            "$ENV" | base64 -d > signature.der
jq -r .signature.publicKeyDer     "$ENV" | base64 -d > pubkey.der
openssl pkey -pubin -inform DER -in pubkey.der -out pubkey.pem
openssl dgst -sha384 -verify pubkey.pem -signature signature.der signed-manifest.json
```

The last command must print `Verified OK`.

**Verify against `signedPayloadBase64`, not against the readable `manifest` object.**
The signature covers an exact byte sequence. The readable copy nested in the envelope is
for humans; re-serializing it will not reproduce those bytes, because its indentation
differs once nested. `signature.signedPayloadSha256` lets you confirm you decoded the
right thing before you start.

### Reading a case log

An incident case's log is a series of records at
`cases/<case-id>/log/000001.json`, `000002.json` and so on, in the evidence bucket.
Each file is a signed envelope like a manifest: the signature, the public key and
`signedPayloadBase64`, which holds the exact bytes that were signed. The signed
document, schema `fip.case/1`, always has:

| Field | Holds |
|---|---|
| `schema` | `fip.case/1` |
| `caseId` | The case |
| `seq` | The record's number, from 1; also its file name |
| `event` | What happened (below) |
| `at` | When, in UTC |
| `actor` | Who: the AWS identity that ran the command |
| `prev` | `null` in record 1. Otherwise `seq`, `key` and `sha256` of the record before: the SHA-256 of that record's signed bytes |

and, by event:

| `event` | Also holds |
|---|---|
| `OPENED` | `tickets`, `comment`. Always record 1 |
| `TICKET_ADDED` | `ticket`, `comment` |
| `COMMENT` | `comment` |
| `MEMBER_ATTACHED` | `actionId` (the run), `executionArn`, `members`: each `member`, `accountId`, `instanceId` |
| `MEMBER_MOVED` | `from` (a case, or `null` for a run in no case), `to`, `members`, `comment`; `via: merge` when a merge made it. The source case's copy adds `counterpart`, naming the destination's record |
| `MERGED` | In the case merged away: `mergedInto`, `comment`. In the survivor: `absorbed`, `tickets`, `comment`, `counterpart` |
| `ABORTED` | `aborts` (the `seq`, `key` and `event` withdrawn) and `reason`. Written when a move, merge or close was refused after its record was signed; the withdrawn record changed nothing |
| `RELEASED`, `REVOKED` | `analysisAccountId`, `members`, `snapshots`, `kmsGrantNames`, `custodyKey` (the matching custody record) |
| `CLOSED` | `comment`, `forced`, `overridden` (what `--force` overrode, empty if nothing), `memberCount` |
| `REOPENED` | `comment` |

**Checking the chain.** `fip evidence <case>` and `fip case show` check each record's
signature, and then that record N's `prev.sha256` is the SHA-256 of record N−1's
signed bytes, that numbers run from 1 with no gap, and that record 1 is `OPENED`. A
deleted record leaves a gap; a replaced or reordered one breaks a hash. By hand, for
records 1 and 2:

```sh
jq -r .signature.signedPayloadBase64 000001.json | base64 -d | shasum -a 256
jq -r .signature.signedPayloadBase64 000002.json | base64 -d | jq -r .prev.sha256
```

The two hashes must match. Each record's signature is checked as for a manifest, above,
or with `fip verify <file> --ours`.

---

## 8. Production retention — a decision, not a default

The evidence bucket is created with **S3 Object Lock enabled and no default
retention**. Those are different things, and the distinction is the whole design:

- Object Lock cannot be added to a bucket after it is created, so it is always enabled.
- Whether anything is *locked* is decided per object as it is written. FIP sets the lock
  on each manifest and custody record when it writes it.

FIP locks nothing until you say so. Switching on production mode requires **you** to
supply a duration in days:

```sh
fip configure --production --retention-days <your number> --retention-mode GOVERNANCE
fip deploy
```

By hand, in `cdk.json`, then redeploy both central stacks (Appendix A.2, A.3).

There is no default duration and FIP asserts no legal minimum. Forensic data has no
obvious statutory retention, and enforcing a period you did not choose — with a control
you cannot undo — is not this tool's job.

- **`GOVERNANCE`** — removable by a principal holding `s3:BypassGovernanceRetention`,
  with every bypass logged. The sane operating choice.
- **`COMPLIANCE`** — not even the root user can delete inside the window. Sometimes
  exactly right, and a commitment to the full term's storage cost that no lifecycle
  policy can shorten.

Deploying with `productionMode: true` and no `retentionDays` fails at synthesis. That
is deliberate: an ambiguous instruction about immutability should not be guessed at.

**What is locked:** every manifest and custody record FIP writes after the change, each
for that many days from when it is written. Objects written in test mode stay unlocked.
The evidence snapshots themselves are not covered by S3 Object Lock. They are protected
by FIP's roles, which can neither delete a snapshot nor grant that right (§1).

---

## 9. Containment and Auto Scaling

### What happens, in order

`FipCase`, once per case:

```
OpenCase        create the case row with an empty targets map
AcquireTargets  Map over targets, 4 at a time, one FipAcquisition each.
                A target that fails is RECORDED, not fatal to the case.
SummarizeCase   roll up to ACQUIRED / PARTIAL / FAILED
```

`FipAcquisition`, once per target:

```
TagTarget          tag the instance, its volumes and its network interfaces
ContainInstance    move every interface to a no-ingress/no-egress group;
                   detach from its Auto Scaling group WITHOUT letting the
                   group launch a replacement
StopInstance       only if stopInstance was true
CreateSnapshots    crash-consistent, multi-volume, tagged at creation
WaitForSnapshots   poll until complete; the EBS direct APIs cannot read a
                   snapshot before then
HashSnapshots      plan → parallel ranges → Merkle root (source attestation)
ShareToEvidence    grant the evidence account use of the member key, then share
CopyToEvidence     copy into the evidence account under YOUR forensic key
HashEvidenceCopies the hash of record, over what is retained
SignAndWriteManifest  sign, write to the Object Lock bucket, record the case
```

Containment happens **first**. It stops exfiltration and lateral movement immediately.

### Why a replacement is not launched by default

Detaching an instance from an Auto Scaling group normally makes the group launch a
replacement to maintain desired capacity. That replacement comes from the **same launch
template, AMI, user data and instance profile** as the host you just isolated. If the
compromise vector is any of those, or an exposed application baked into the image, the
replacement is just as vulnerable. Detection fires, FIP isolates, the group replaces, and
round it goes, with a fresh set of snapshots billed each time.

So by default FIP gives up the capacity instead: the group runs one instance short until
a human raises it again. **That is a real cost and it is the lesser one.** A degraded
group is a visible problem someone fixes by patching the launch template, whereas a
containment loop looks like the tool working.

If the group is already at its **minimum size** it cannot give up capacity, so FIP
suspends the group's `Launch` process instead. That is group-wide and blocks all
scale-out until resumed.

`--allow-replacement` restores capacity-maintaining behavior when you want it. It is
opt-in because the loop is not obvious.

### Undoing it after a restore

`fip restore` reports what containment did to the group, with the command to undo it,
but does not run that command. Re-attaching capacity puts back an instance built from a
launch template that may be how the attacker got in, so that stays a deliberate human
step. The manifest's `containment.autoScaling.mechanism` says which applies:

| `mechanism` | What happened | To restore |
|---|---|---|
| `desired-capacity-decremented` | The group gave up one instance of capacity. Nothing group-wide was changed | Raise desired capacity by one, **after** the launch template is known good |
| `launch-suspended` | The group was already at its minimum size. Its `Launch` process was suspended — **group-wide, and it blocks all scale-out** | `aws autoscaling resume-processes --auto-scaling-group-name <g> --scaling-processes Launch`. It launches the deferred replacement **immediately**, so patch the launch template first |
| `capacity-maintained` | `--allow-replacement` was used. A replacement was launched from the same launch template | Nothing to undo. Check whether the replacement is compromised too |

Re-attach the isolated instance only if you actually want it back in service; it is
usually evidence, not capacity.

If a manifest field reads `alreadyIsolatedOriginalUnknown: true`, the instance was
already contained with no record of its prior groups. FIP says so rather than guessing.

---

## 10. Analysis access

**Optional, and it costs money while it exists.** Acquisition and custody do not depend
on this stack. Deploy it when you have something to analyze.

### How an examiner gets in

There is **no bastion, no key pair and no ingress rule anywhere** in this stack:

| | |
|---|---|
| Network | One VPC, **private isolated subnets only**. No internet gateway, no NAT, **no route off the VPC at all** |
| Access | AWS Systems Manager Session Manager, over interface endpoints for SSM, its two message channels and CloudWatch Logs. Outbound-initiated, so nothing listens |
| Credential | An IAM role. There is no key to hold, lose or rotate |
| Audit | Keystroke-level transcript to S3 **and** CloudWatch, KMS-encrypted, in a bucket the examiner cannot delete from |

Because there is no route out of the VPC, a disk image that executes something while
being examined **cannot reach the internet**. That property comes from the route table
rather than from a firewall rule, which is why adding a NAT gateway to this VPC would
quietly remove it.

### Deploy

Replace the example number below with your analysis account id. This needs a
`fip-analysis` profile for that account. If it is in your organization,
add it with `fip configure --analysis` (§6.1). If a third party holds it, they run this step
with their own credentials.

```sh
export FIP_ANALYSIS_ACCOUNT_ID=333333333333
npx cdk bootstrap aws://$FIP_ANALYSIS_ACCOUNT_ID/$AWS_REGION --profile fip-analysis
npx cdk deploy FipAnalysisStack --profile fip-analysis
```

The stack is only created when `FIP_ANALYSIS_ACCOUNT_ID` is set, and it is
**account-agnostic** — a third-party examiner can deploy it in their own tenant without
giving you credentials there.

Name the examiners who may connect, as a comma-separated list of principal ARNs:

```sh
cdk deploy FipAnalysisStack --context fip:examinerPrincipalArns=arn:aws:iam::999988887777:role/Examiner
```

You can deploy first and name them later — examiner ARNs are rarely known before an
incident. Until then the role trusts only the analysis account itself.

### Connect

```sh
aws ssm start-session --document-name FipForensicSession --target <instance id>
```

**Use that document name.** `FipForensicSession` is what carries the logging
configuration. A plain `start-session` would use the account default document and
produce no transcript — which is why `ssm:StartSession` is granted on the instance **and**
the document together, not on either alone.

FIP does **not** overwrite your account-level `SSM-SessionManagerRunShell` document.
Changing it would alter every unrelated session in the account. If you want these
settings to be the account default, that is your call to make, not ours.


### Release the evidence to the analysis account

Evidence does **not** flow to the analysis account automatically, and that is deliberate:
the analysis account may belong to a third party, so releasing evidence is a
chain-of-custody event that a human decides, per case. Use `fip release` (§6.11), from
the orchestrator, and `fip release --revoke` to withdraw it.

### Mount evidence read-only

As the examiner role, create a volume from a released snapshot in the workstation's
Availability Zone and attach it. EBS re-encrypts the volume into the analysis account's
own key; the evidence snapshot is not changed.

```sh
aws ec2 create-volume --snapshot-id <snapshot id> --availability-zone <workstation AZ>
aws ec2 attach-volume --volume-id <volume id> --instance-id <workstation id> --device /dev/sdf
```

Then, in a session on the workstation, check the filesystem type, set the device
read-only, and mount it with the options for that type:

```sh
lsblk -f
sudo blockdev --setro /dev/nvme1n1 /dev/nvme1n1p1
# xfs (Amazon Linux, RHEL and their relatives):
sudo mount -o ro,norecovery,nouuid,noexec,nodev /dev/nvme1n1p1 /mnt/evidence
# ext3/ext4:
sudo mount -o ro,noload,noexec,nodev /dev/nvme1n1p1 /mnt/evidence
```

`norecovery` (xfs) and `noload` (ext3/ext4) matter: without them the kernel replays the
journal, **writing to the volume you are treating as evidence**. `ro` alone does not
prevent that. Each is rejected by the other filesystem, so check the type first.
`nouuid` lets xfs mount a disk cloned from the same image as the workstation, which
otherwise has a duplicate UUID. `blockdev --setro` refuses writes at the device as well.

Booting evidence is not part of the examiner role: it needs a snapshot made in the
analysis account, which would have no manifest or provenance. If a case needs it, an
administrator of the analysis account builds a working copy (volume, snapshot, image)
and launches it in the isolated subnets with a security group that has no rules and
the instance metadata service disabled. Tag the copies `fip:class=test` and remove
them when done; they are not evidence.

### Get results out

The VPC has no route out, so findings leave the way the session transcripts do: over the
VPC's S3 gateway endpoint, into the **results bucket** (stack output `ResultsBucket`). From
the workstation:

```sh
aws s3 cp findings.tar.gz s3://<results bucket>/results/<case id>/ --checksum-algorithm SHA256
```

| | |
|---|---|
| Write | The workstation can **add** objects under `results/` and nothing else: no read-back, no delete. The bucket refuses any write that does not arrive through this VPC's S3 endpoint, an administrator's included |
| Keep | Object Lock is enabled and versioning is on, so an overwrite keeps the earlier version. Nothing is locked by default; set a retention or legal hold on an object if it becomes part of the record |
| Key | Results have their own KMS key, separate from the transcript key, so a reader of results cannot read session transcripts |
| Read | The `FipResultsReader` role (stack output `ResultsReaderRoleArn`) reads and lists results from outside the VPC, and is denied every write, delete and retention change |

Name who may read results the same way as examiners:

```sh
cdk deploy FipAnalysisStack --context fip:resultsReaderPrincipalArns=arn:aws:iam::999988887777:role/Counsel
```

Until you do, the role trusts only the analysis account itself. Results do **not** go back
through a snapshot: the examiner cannot create one, because a snapshot made here would sit
beside the evidence with no manifest and no provenance.

### Cost, and turning it off

Five interface endpoints (the four above plus KMS) and the workstation bill hourly whether or not anyone is
working. **Stop the workstation between engagements** — Session Manager reconnects when
it starts again, with no key or address to re-establish. The instance has termination
protection on, so stopping is the intended idle state rather than terminating.

---
## 11. Tags, and finding what FIP made

Everything FIP creates is tagged, so you can find all of it, see what it costs, and
remove what a test made without touching anything else.

| Tag | Values | On |
|---|---|---|
| `application` | `fipv2` | Everything FIP creates or launches: its stacks and their resources, snapshots, evidence copies, the isolation security group, and the test instance (§6.5) |
| `fip:class` | `infrastructure` · `evidence` · `test` | The same. Decides what a cleanup may remove |
| `fip:component` | `core` · `orchestrator` · `member` · `analysis` | The stacks and their resources |
| `fip:environment` | `test` · `production` | The stacks, from `fip deploy`, and what FIP creates |
| `fip:case-id` | the isolation run id | Everything a run touched: the instance, its volumes and interfaces, and every snapshot |
| `fip:case` | the incident case id | Snapshots and evidence copies of a run made with `--case`. Set once, at creation: a later move or merge does not change it, so the case log, not the tag, says where a member is now |
| your own | from `fip configure --tag` | The stacks and their resources |

**`fip:class` is the one that matters.**

- `infrastructure` covers the stacks and what they hold. Remove these by deleting the
  stacks, as `cdk/RECOVERY.md` describes, never resource by resource.
- `evidence` covers snapshots from a real case. Nothing in FIP removes these.
- `test` covers the test instance (§6.5), every snapshot taken in a test-mode install, and,
  in a production install, the member snapshots of a test instance. `fip cleanup --test`
  removes these.

**Your instances are never tagged `application=fipv2`.** An instance FIP contains gets
only `fip:case-id`, on it, its volumes and its network interfaces. No search for FIP's
own resources can reach a host under investigation.

**Your own tags,** such as a cost center, go on the stacks and every resource in them.
Set them with `fip configure --tag KEY=VALUE`. Keys beginning `aws:` or `fip:`, and
`application`, are reserved. Snapshots and the isolation group carry only FIP's tags,
because FIP's role in each member account may write no other tag keys.

**To see everything FIP made**, in every configured account:

```sh
fip cleanup --list
```

It lists each resource with its class. Cost Explorer can group spending by
`application` once you activate it as a cost allocation tag, in the Billing console of
your management account.

---
## 12. Troubleshooting

**Start here:**

This checks the tools, your credentials and both central stacks:

```sh
fip doctor
```

This adds one member account, end to end:

```sh
fip doctor --member 444444444444
```

It is entirely read-only — it describes, never creates — and every check in it
corresponds to something that has actually failed in practice: a missing `jq`, an unset
account id, an external ID never issued, an evidence role that cannot be assumed because
the orchestrator account id was wrong. **Run it after installing and again before you
need it**, so a broken install is discovered at any time other than incident time.

| Symptom | Cause |
|---|---|
| `AccessDenied` assuming `FipResponderRole` | External ID missing or wrong. It must be the one in `/fip/member/<account>/external-id` in the **orchestrator** account |
| `SNAPSHOT_NOT_FOUND` from the EBS APIs | The snapshot has not finished. The state machine waits; a manual call must too |
| `AuthFailure: Not authorized to use key` on share | KMS permissions on the member's own CMK. EC2 returns no encoded message here — **read CloudTrail**, which names the exact denied action |
| `Client.InvalidKMSKey.InvalidState` on an instance launch | A key leaving `PendingDeletion` has had its grants revoked. Recreate the grant; the error does not mention grants |
| Execution fails at `HashEvidenceCopies` | `FipEvidenceRole` needs the EBS direct-API actions in the **evidence** account |
| A Lambda times out hashing | Lower `FIP_HASH_RANGE_BLOCKS` (default 4000 ≈ 2 GiB per invocation) |
| `fip-isolate.sh` reports `NO EXTERNAL ID` | `FipMemberStack` was never deployed to that account, or was deployed without the responder role. Run `fip deploy --only members` (§6.2) |
| Case is `PARTIAL` | Expected behavior, not an error. Read `failures` on the case row; the successful targets' evidence is complete. Re-run the failed targets with the same `--case-id` |
| Case is `FAILED` with no target errors | `FipCase` could not open the case row. It writes to `fip-cases` in the **evidence** account via `FipEvidenceRole` |
| `States.Runtime` in `FipAcquisition` | A hand-written input is missing a field the states reference. `caseId`, `accountId` and `instanceId` are required; `stopInstance` is not |

---
## 13. What FIP does not do

Stated plainly, because a forensics tool that overstates itself is worse than one that
does less.

- **No memory capture.** Volatile state is lost. Designed but not built.
- **No detonation.** No sandbox, no sinkhole, no traffic analysis.
- **No automatic triggering.** Cases start when a human starts one; no GuardDuty rule.
- **No enumeration.** You supply the instance ids.
- **Single region per deployment.**
- **No forensic tooling of its own.** §10 gives you an isolated workstation with
  `sleuthkit` and nothing else. Commercial tooling, a SIFT image or your own AMI is yours
  to install, and FIP has no opinion about which.
- **No automated evidence delivery.** Releasing evidence to the analysis account is a
  deliberate, human-initiated step (§10), not something a case does on its own.
- **No recovery of released copies.** Revoking access does not reach a volume the analysis
  account already created from the evidence.

---
## 14. Further reading

| | |
|---|---|
| [../cdk/RECOVERY.md](../cdk/RECOVERY.md) | Teardown and rebuild, including what cannot be undone |
| [../cdk/README.md](../cdk/README.md) | Developer notes for the CDK app |
| [architecture/](architecture/README.md) | C4 model of what is built |

---
## Appendix A. Setup with shell commands

Each section does one part of `fip configure` and `fip deploy` (§3) with `aws` and
`cdk` commands, for when the CLI is unavailable or you want to see what it runs. Do them
in order.

### A.1 Set the account ids and profiles

The same as `fip configure` (§6.1).

Everything after this step is copied and pasted as written. The values you type are
here, and only here. They are shell variables, so a new terminal window starts
without them. The end of this step saves them to a file that any new terminal can
reload.

```sh
cd cdk
npm ci
export FIP_CDK_DIR=$PWD
```

`FIP_CDK_DIR` remembers this folder, so later steps work from any directory.

Put the CLI on your PATH once, so that during an incident nobody has to remember where
this was checked out. Run **one** of these two. The first needs no `sudo`:

```sh
ln -s "$PWD/bin/fip" ~/.local/bin/fip
```

The second installs system-wide. It needs `sudo` because `/usr/local/bin` is owned by
root on Apple Silicon:

```sh
sudo ln -s "$PWD/bin/fip" /usr/local/bin/fip
```

**A note on pasting.** The command blocks in this manual contain no `#` comments. Your
shell may not accept them: zsh, the macOS default, treats `#` as a command unless the
`interactivecomments` option is set.

**Your inputs.** Replace the three example numbers with your own 12-digit account ids.
In order: the account that runs the cases, the account that holds the evidence, and the
first account FIP will cover.

```sh
export AWS_REGION=us-east-1
export FIP_ORCHESTRATOR_ACCOUNT_ID=111111111111
export FIP_EVIDENCE_ACCOUNT_ID=222222222222
export FIP_MEMBER_ACCOUNT_ID=444444444444
```

**Verify** that all three are set. Every later step depends on them:

```sh
for id in "$FIP_ORCHESTRATOR_ACCOUNT_ID" "$FIP_EVIDENCE_ACCOUNT_ID" "$FIP_MEMBER_ACCOUNT_ID"; do
  case "$id" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) echo "ok   $id" ;;
    *) echo "STOP '$id' is not a 12-digit account id" ;;
  esac
done
```

Three `ok` lines, or fix the export that printed `STOP`.

If you run AWS Organizations, you can look up the first two by account name instead.
The script must be **sourced**, because it exports into your shell. It searches for
accounts named `FIP Orchestrator` and `FIP Evidence`; set
`FIP_ORCHESTRATOR_ACCOUNT_NAME` and `FIP_EVIDENCE_ACCOUNT_NAME` first if yours differ.

```sh
source ./bin/discover-accounts.sh
```

**Your organization id, looked up rather than typed.** It must end up as an id
(`o-…`) or, if you have no AWS Organization, the word `none`. Never leave it empty:
the member stack refuses to deploy without it.

```sh
export FIP_ORG_ID=$(aws organizations describe-organization \
  --query Organization.Id --output text)
echo "organization: $FIP_ORG_ID"
```

If the lookup fails with `AWSOrganizationsNotInUseException`, you have no organization:
`export FIP_ORG_ID=none`. Any other failure is a credentials problem; fix it rather than
writing `none`, which would drop a trust condition you are entitled to.

**The profiles.** One per account. **If you already have a profile that reaches an
account with the access FIP needs, use it**: set the matching variable below to its name,
and the loop leaves that profile alone. Otherwise keep the `fip-` name and the loop
writes it into `~/.aws/config`. Each written profile assumes a role in its account,
starting from your default credentials.

```sh
export FIP_ORCHESTRATOR_PROFILE=fip-orchestrator
export FIP_EVIDENCE_PROFILE=fip-evidence
export FIP_MEMBER_PROFILE=fip-member
```

To see which existing profiles reach which account (signing in with each takes a
moment):

```sh
for p in $(aws configure list-profiles); do
  echo "$p -> $(aws sts get-caller-identity --profile $p --query Account --output text 2>/dev/null || echo none)"
done
```

The profiles this writes assume a role in each account. The role name is the one
your accounts already have for administration: `AWSControlTowerExecution` under Control
Tower, `OrganizationAccountAccessRole` for accounts created by AWS Organizations.

Set the role name first. Change it to `OrganizationAccountAccessRole` if that is what
your accounts have:

```sh
export FIP_ADMIN_ROLE=AWSControlTowerExecution
```

Then write the profiles:

```sh
for pair in $FIP_ORCHESTRATOR_PROFILE:$FIP_ORCHESTRATOR_ACCOUNT_ID \
            $FIP_EVIDENCE_PROFILE:$FIP_EVIDENCE_ACCOUNT_ID \
            $FIP_MEMBER_PROFILE:$FIP_MEMBER_ACCOUNT_ID; do
  name=${pair%%:*}; id=${pair#*:}
  if [ -z "$id" ]; then echo "skipped $name: its account id is not set"; continue; fi
  if aws configure list-profiles | grep -qx "$name"; then echo "kept $name: it exists"; continue; fi
  aws configure set role_arn arn:aws:iam::${id}:role/${FIP_ADMIN_ROLE} --profile $name
  aws configure set source_profile default --profile $name
  aws configure set region $AWS_REGION --profile $name
done
```

A profile that already exists is kept, however it signs in, IAM Identity Center
included. Nothing below cares how a profile authenticates.

**Verify:** each profile lands in its own account.

```sh
for p in $FIP_ORCHESTRATOR_PROFILE $FIP_EVIDENCE_PROFILE $FIP_MEMBER_PROFILE; do
  echo "$p -> $(aws sts get-caller-identity --profile $p --query Account --output text)"
done
```

Each line must show the matching id from your inputs. An error, or the wrong number,
means that profile's role name or source credentials are wrong. Fix it before going on.

**Save the values.** This writes them to `~/.fip/install.env` and shows the result:

```sh
mkdir -p ~/.fip
cat > ~/.fip/install.env <<EOF
export AWS_REGION=$AWS_REGION
export FIP_ORCHESTRATOR_ACCOUNT_ID=$FIP_ORCHESTRATOR_ACCOUNT_ID
export FIP_EVIDENCE_ACCOUNT_ID=$FIP_EVIDENCE_ACCOUNT_ID
export FIP_MEMBER_ACCOUNT_ID=$FIP_MEMBER_ACCOUNT_ID
export FIP_ORG_ID=$FIP_ORG_ID
export FIP_ADMIN_ROLE=$FIP_ADMIN_ROLE
export FIP_ORCHESTRATOR_PROFILE=$FIP_ORCHESTRATOR_PROFILE
export FIP_EVIDENCE_PROFILE=$FIP_EVIDENCE_PROFILE
export FIP_MEMBER_PROFILE=$FIP_MEMBER_PROFILE
export FIP_CDK_DIR=$FIP_CDK_DIR
EOF
cat ~/.fip/install.env
```

**In any new terminal**, reload the values and return to the CDK folder before
continuing. The `npx cdk` commands only work from there:

```sh
source ~/.fip/install.env && cd "$FIP_CDK_DIR"
```

The external ID from A.4 is not saved in this file. A.4 is safe to rerun and reads it
back.

### A.2 Set the retention posture

The same as the test or production choice in `fip configure` (§3.2). By hand,
`cdk.json` decides. Leave `cdk.json` as shipped for installation and testing:

```json
"fip:productionMode": false,
"fip:retentionMode": "GOVERNANCE",
"fip:retentionDays": null
```

`productionMode: false` means **nothing is locked**. Deploying and exercising FIP will
not leave undeletable objects in your account.

When you go to production, set `fip:productionMode` to `true` and supply
`fip:retentionDays` yourself. FIP ships no default duration and asserts no legal
minimum — see §8.

### A.3 Bootstrap and deploy the two central stacks

Each account is bootstrapped and deployed with **its own** profile (§2):

```sh
npx cdk bootstrap aws://$FIP_EVIDENCE_ACCOUNT_ID/$AWS_REGION     --profile $FIP_EVIDENCE_PROFILE
npx cdk bootstrap aws://$FIP_ORCHESTRATOR_ACCOUNT_ID/$AWS_REGION --profile $FIP_ORCHESTRATOR_PROFILE

ORG_CONTEXT="--context=fip:orgId=$FIP_ORG_ID"; [ "$FIP_ORG_ID" != none ] || ORG_CONTEXT=""
npx cdk deploy FipCoreStack         --profile $FIP_EVIDENCE_PROFILE     $ORG_CONTEXT
npx cdk deploy FipOrchestratorStack --profile $FIP_ORCHESTRATOR_PROFILE $ORG_CONTEXT
```

`ORG_CONTEXT` passes your organization id when you have one, and nothing when it is
`none`.

Both stacks carry the product tags `application=fipv2`, `fip:class` and `fip:component`
from the code (§11). `fip deploy` also adds `fip:environment` and your own tags. To add
them by hand, append `--tags fip:environment=test` (and `--tags KEY=VALUE` for each of
yours) to both deploy lines.

Order matters: `FipOrchestratorStack` grants itself the right to assume a role that
`FipCoreStack` creates.

**Bootstrap grants `AdministratorAccess` unless you say otherwise.** That is CDK's
default for the role CloudFormation deploys with. To narrow it, create a policy covering
what FIP deploys and pass it with `--cloudformation-execution-policies <policy arn>` on
each bootstrap. FIP does not yet ship that policy. Whatever you choose, `iam:*` remains,
because CDK cannot create roles without it.

**Keep the organization id on every later deploy too.** It adds the
`aws:PrincipalOrgID` conditions described in §2. A redeploy without it removes those
conditions from a running installation, and nothing warns you.

**Verify:**

```sh
aws cloudformation describe-stacks --stack-name FipCoreStack --profile $FIP_EVIDENCE_PROFILE \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
```

You should see `EvidenceBucketName`, `EvidenceKeyArn`, `CaseTableName`,
`ResponderTopicArn`, `EvidenceRoleArn`, and a `RetentionPolicy` reading
`{"productionMode":false,"mode":"NONE","days":null}`.

Confirm Object Lock is enabled and **carries no rule**:

```sh
aws s3api get-object-lock-configuration --profile $FIP_EVIDENCE_PROFILE \
  --bucket fip-evidence-$FIP_EVIDENCE_ACCOUNT_ID-$AWS_REGION
```

Expected, exactly:

```json
{
    "ObjectLockConfiguration": {
        "ObjectLockEnabled": "Enabled"
    }
}
```

A `Rule` key means something is locking objects. Stop and investigate before
proceeding.

### A.4 Issue an external ID per member account

Each member account gets its own unpredictable identifier, issued by **you** (the
orchestrator operator), not chosen by the account owner. This is what prevents one
member account inducing your orchestrator to act against another.

It is **not a secret** — AWS states it is visible to anyone who can read the role — but
it must be unguessable and it must be yours to assign.

It is stored in the **orchestrator** account, which is where FIP looks it up at run
time. This reuses the account's existing ID if it already has one, and issues a new one
if not. Safe to run twice:

```sh
if [ -z "$FIP_MEMBER_ACCOUNT_ID" ]; then
  echo "STOP FIP_MEMBER_ACCOUNT_ID is not set: run  source ~/.fip/install.env"
else
  EXTERNAL_ID_PARAM=/fip/member/$FIP_MEMBER_ACCOUNT_ID/external-id
  EXTERNAL_ID=$(aws ssm get-parameter --profile $FIP_ORCHESTRATOR_PROFILE \
    --name $EXTERNAL_ID_PARAM --query Parameter.Value --output text 2>/dev/null)
  if [ -n "$EXTERNAL_ID" ]; then
    echo "ok   reusing the existing external ID"
  else
    NEW_ID="fip-$(python3 -c "import secrets,string;a=string.ascii_letters+string.digits;print(''.join(secrets.choice(a) for _ in range(32)))")"
    if aws ssm put-parameter --profile $FIP_ORCHESTRATOR_PROFILE \
         --name $EXTERNAL_ID_PARAM --value "$NEW_ID" --type String \
         --description "FIP external ID for member account $FIP_MEMBER_ACCOUNT_ID" \
         --query Version --output text >/dev/null; then
      EXTERNAL_ID=$NEW_ID
      echo "ok   issued a new external ID"
    else
      echo "STOP the external ID was not stored; see the error above"
    fi
  fi
fi
```

It prints one line. Go on only after an `ok` line. The block never overwrites an
existing ID. If the read fails for some other reason, such as expired credentials, the
write is refused as well, and you get `STOP`.

Reuse matters. The member stack in A.5 is deployed with this value, and the two must
match. Overwriting the parameter of an account that is already enrolled breaks its
trust path until A.5 is run again.

**Verify:** `echo $EXTERNAL_ID` prints `fip-` followed by 32 letters and digits.

### A.5 Deploy the member stack

The member template is committed at `cdk/synth/FipMemberStack.template.json` and
carries no CDK bootstrap requirement, so it deploys three ways: plain CloudFormation,
a self-managed StackSet, or a service-managed StackSet across an organization.

Deploy with the **member account's** profile:

```sh
aws cloudformation deploy --profile $FIP_MEMBER_PROFILE \
  --template-file "$FIP_CDK_DIR/synth/FipMemberStack.template.json" \
  --stack-name FipMemberStack \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      OrchestratorAccountId=$FIP_ORCHESTRATOR_ACCOUNT_ID \
      EvidenceAccountId=$FIP_EVIDENCE_ACCOUNT_ID \
      ExternalId="$EXTERNAL_ID" \
      OrganizationId="$FIP_ORG_ID" \
      DeployResponderRole=Yes \
      AllowRestore=Yes \
  --tags application=fipv2 fip:class=infrastructure fip:component=member fip:environment=test
```

The `--tags` line gives the stack the product tags of §11. In production, write
`fip:environment=production`, and add any tags of your own to the same line.

`OrganizationId` is required, with no default: your organization id, so each role
also requires the orchestrator to be inside your organization (`aws:PrincipalOrgID`),
or `none` if you have no organization. Check it took:

```sh
aws iam get-role --profile $FIP_MEMBER_PROFILE --role-name FipInventoryRole \
  --query 'Role.AssumeRolePolicyDocument.Statement[].Condition.StringEquals."aws:PrincipalOrgID"' --output text
```

It must print your organization id, or `None` when you configured `none`.

`DeployResponderRole=No` installs only the read-only `FipInventoryRole`. Use that to
grant visibility before an engagement begins, and switch it to `Yes` when response
capability is actually wanted.

`AllowRestore=Yes` lets `fip restore` (§6.12) put a contained instance back on its
original security groups. `No` keeps that a manual step done with this account's own
credentials. §6.12 explains what `Yes` permits.

**Verify the trust path end to end** — from the orchestrator account:

First confirm this terminal still has the values from A.1 and A.4. A new window does
not until you reload them, and every check below would then fail for that reason alone:

```sh
if [ -n "$FIP_MEMBER_ACCOUNT_ID" ] && [ -n "$EXTERNAL_ID" ]; then echo "ok   variables set"; else echo "STOP run  source ~/.fip/install.env  and then the A.4 block"; fi
```

```sh
RESPONDER=arn:aws:iam::${FIP_MEMBER_ACCOUNT_ID}:role/FipResponderRole
```

This runs all three checks and prints `PASS` or `FAIL` for each. The right external ID
must be accepted. A wrong one, and none at all, must both be refused:

```sh
trust_check() {
  aws sts assume-role --profile $FIP_ORCHESTRATOR_PROFILE --role-arn $RESPONDER \
    --role-session-name trust-check "$@" >/dev/null 2>&1
}
if trust_check --external-id "$EXTERNAL_ID"; then echo "PASS right ID accepted"; else echo "FAIL right ID refused"; fi
if trust_check --external-id fip-wrong; then echo "FAIL wrong ID accepted"; else echo "PASS wrong ID refused"; fi
if trust_check; then echo "FAIL missing ID accepted"; else echo "PASS missing ID refused"; fi
```

You need three `PASS` lines. If you see `FAIL right ID refused`, first make sure the variable check above printed
`ok`. If it did, the external ID in the orchestrator account does not match the one the
member stack was deployed with: rerun A.4 and A.5. Either of the other two `FAIL` lines means the confused-deputy protection
is not working. Do not proceed.

To cover another account, set `FIP_MEMBER_ACCOUNT_ID` and `FIP_MEMBER_PROFILE` to it
and its profile as in A.1, and repeat A.4 and A.5.

---

## Appendix B. Isolation with shell commands

Each section does one `fip` step with `aws` commands, for when `fip` is unavailable or
you want to see what it does. They use the values `fip configure` saved, so load them
into the shell first:

```sh
source ~/.fip/install.env
```

`TARGET` and `RUN` are the values from §4. The instance id alone is the part of
`TARGET` after the colon:

```sh
INSTANCE=${TARGET#*:}
```

### B.1 Launch a test instance by hand

The same as `fip test-instance` (§6.5). Without a default VPC, add `--subnet-id` with a
subnet of yours to `run-instances`.

```sh
AMI=$(aws ssm get-parameter --profile $FIP_MEMBER_PROFILE \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
INSTANCE=$(aws ec2 run-instances --profile $FIP_MEMBER_PROFILE \
  --image-id $AMI --instance-type t3.micro \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=fip-install-test},{Key=application,Value=fipv2},{Key=fip:class,Value=test}]' \
  --query 'Instances[0].InstanceId' --output text)
TARGET=$FIP_MEMBER_ACCOUNT_ID:$INSTANCE
```

**Verify:** this prints `ok   running`, usually within a minute:

```sh
aws ec2 wait instance-running --profile $FIP_MEMBER_PROFILE --instance-ids $INSTANCE && echo "ok   running"
```

### B.2 Find the instance by hand

The same as `fip instances` (§6.4), for one member account:

```sh
aws ec2 describe-instances --profile $FIP_MEMBER_PROFILE \
  --filters Name=instance-state-name,Values=running,stopped \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`]|[0].Value]' \
  --output table
```

### B.3 Start an isolation by hand

`fip isolate` pre-flights each target, then starts the `FipCase` state machine. Starting
it directly skips the pre-flight:

```sh
aws stepfunctions start-execution --profile $FIP_ORCHESTRATOR_PROFILE \
  --state-machine-arn arn:aws:states:${AWS_REGION}:${FIP_ORCHESTRATOR_ACCOUNT_ID}:stateMachine:FipCase \
  --input '{
    "caseId": "fip-manual-0001",
    "stopInstance": false,
    "targets": [
      { "accountId": "111122223333", "instanceId": "i-0abc" },
      { "accountId": "444455556666", "instanceId": "i-0def" }
    ]
  }'
```

| Field | Meaning |
|---|---|
| `caseId` | The run id (the field keeps its older name). Yours to choose; start it `fip-` so `fip case` can attach and move it. Becomes the `fip:case-id` tag, the manifest prefix and the table key |
| `targets` | One `{accountId, instanceId}` per instance. Any number, any mix of accounts |
| `stopInstance` | Applies to every target in the run. Optional, default `false` |
| `asgPolicy` | `prevent-replacement` (default) or `allow-replacement`. Optional |

`FipCase` fans out to one `FipAcquisition` execution per target, so `FipAcquisition`
still takes a single `accountId`/`instanceId` if you want to drive one instance directly.

### B.4 Watch an isolation by hand

`fip status` reads two things. The execution, using the ARN `fip isolate` printed:

```sh
aws stepfunctions describe-execution --profile $FIP_ORCHESTRATOR_PROFILE \
  --execution-arn <execution ARN> --query status
```

And the run's row, which lives in the **evidence** account:

```sh
aws dynamodb get-item --profile $FIP_EVIDENCE_PROFILE --table-name fip-cases \
  --key "{\"caseId\":{\"S\":\"$RUN\"}}"
```

### B.5 Collect and verify the evidence by hand

The same as `fip evidence` (§6.8). Everything is in the **evidence bucket**, in the
**evidence account**; an `aws s3 ls` with your default credentials looks in a different
account and finds no FIP bucket at all. Copy the case to the current directory:

```sh
aws s3 cp --recursive --profile $FIP_EVIDENCE_PROFILE \
  s3://fip-evidence-$FIP_EVIDENCE_ACCOUNT_ID-$AWS_REGION/cases/$RUN/ .
```

Then check each file against your signing key. `--ours` looks the key up in the
orchestrator stack:

```sh
AWS_PROFILE=$FIP_ORCHESTRATOR_PROFILE fip verify $INSTANCE/manifest.json --ours
```

With neither `fip` nor its key lookup, §7 checks integrity with `jq` and `openssl`
alone.

### B.6 Clean up a test by hand

The same as `fip cleanup --test` (§6.13), and the way to remove a test's evidence copy in
a production install. **Never run it against a real case**: it deletes the evidence.

**1. Terminate the test instance.** Containment does not stop it, so it is still
running and billing:

```sh
aws ec2 terminate-instances --profile $FIP_MEMBER_PROFILE --instance-ids $INSTANCE \
  --query 'TerminatingInstances[0].CurrentState.Name' --output text
```

```sh
aws ec2 wait instance-terminated --profile $FIP_MEMBER_PROFILE --instance-ids $INSTANCE && echo "ok   terminated"
```

**2. Delete the case's snapshots.** There are two per volume: the source snapshot in the
member account and the evidence copy in the evidence account. Both carry the case id as
the `fip:case-id` tag, so this finds exactly that case's snapshots. List them first:

```sh
for p in $FIP_MEMBER_PROFILE $FIP_EVIDENCE_PROFILE; do
  echo "$p: $(aws ec2 describe-snapshots --profile $p --owner-ids self \
    --filters Name=tag:fip:case-id,Values=$RUN --query 'Snapshots[].SnapshotId' --output text)"
done
```

If those are the test case's snapshots, delete them:

```sh
for p in $FIP_MEMBER_PROFILE $FIP_EVIDENCE_PROFILE; do
  for s in $(aws ec2 describe-snapshots --profile $p --owner-ids self \
      --filters Name=tag:fip:case-id,Values=$RUN --query 'Snapshots[].SnapshotId' --output text); do
    aws ec2 delete-snapshot --profile $p --snapshot-id $s && echo "deleted $p $s"
  done
done
```

**Verify:** run the listing again. Both lines must end with nothing after the colon.

### B.7 Restore by hand

The same as `fip restore` (§6.12), using the member account's own credentials, for when
restore is not allowed (`AllowRestore=No`) or `fip` is unavailable. Read the original
groups from the manifest's `containment.originalSecurityGroups`, or from the interface
tag:

```sh
aws ec2 describe-network-interfaces --profile $FIP_MEMBER_PROFILE \
  --filters Name=attachment.instance-id,Values=$INSTANCE \
  --query 'NetworkInterfaces[].[NetworkInterfaceId,TagSet[?Key==`fip:original-sgs`]|[0].Value]' \
  --output text
```

Then apply them to each interface, replacing the example ids with that output. Commas
in the tag become spaces here:

```sh
aws ec2 modify-network-interface-attribute --profile $FIP_MEMBER_PROFILE \
  --network-interface-id eni-0123456789abcdef0 --groups sg-0aaa1111 sg-0bbb2222
```

Unlike `fip restore`, this writes no custody record, and does not check the tag against
the signed manifest.
