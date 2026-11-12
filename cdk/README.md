# FIP v2 — CDK app

The stacks and the `fip` command. To install and use FIP, follow
[the manual](../docs/MANUAL.md); this file is for changing it.

## The stacks

| Stack | Account | Contents |
|---|---|---|
| `FipCoreStack` | Evidence | Evidence CMK, Object Lock evidence bucket, case table, responder topic, `FipEvidenceRole` |
| `FipOrchestratorStack` | Orchestrator | `FipCase` and `FipAcquisition` state machines, member-action Lambda, manifest signing key |
| `FipMemberStack` | Each member account | `FipInventoryRole` (read-only) and, optionally, `FipResponderRole` |
| `FipAnalysisStack` | Analysis, optional | Isolated VPC and examiner workstation reached by Session Manager, session transcripts, tools and results buckets, `FipExaminerRole` and `FipResultsReader` |

`bin/` holds `fip` and its subcommands; `lambda/member-action/` holds the one Lambda;
`synth/` holds the committed member template (see its README).

## Running it

```sh
npm ci
npm test            # assertions on the design decisions; no AWS credentials needed
npm run nag         # cdk-nag; must be clean
```

Synth and deploy need account ids; `fip configure` saves them and `fip deploy` passes
them (manual §3). `fip deploy` covers the core, orchestrator and member stacks; the
analysis stack is deployed on its own, in the analysis account (manual §10).

## Two things to know before editing

**Object Lock is enabled on the bucket and applied per object.** Those are
different operations. The bucket flag cannot be added after creation, so it is
always on; retention is written per object at acquisition time from
`/fip/evidence/retention-policy`. Nothing is locked during install and test,
and production mode requires a customer-supplied duration in days. There is no
default and none should be added (manual §8).

**FIP fits the customer, not the reverse**, which has two halves.

It does not *require* what the customer lacks: SCPs, tag policies, org-wide
StackSets, a delegated administrator, a Config aggregator, an organization at
all — optional hardening. `fip:orgId` is optional and its absence degrades a
defense-in-depth condition rather than failing a deployment.

It does not *forbid* what the customer chooses: procedural advice belongs in
runbooks and defaults, never in refusals. Only two things may be refused, and
neither is a preference: incoherent configuration (`fip:productionMode` true with
no duration), and unintended irreversibility (compliance-locking objects during a
test run).

## Language

JavaScript rather than TypeScript: there is no build step to break during an
incident, and `cdk assertions` is language-agnostic.
