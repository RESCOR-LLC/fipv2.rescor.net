# FIP — recovery and teardown

**Rebuilding is trivial. Tearing down is not**, and that asymmetry is deliberate:
`RemovalPolicy.RETAIN` on evidence infrastructure is what stops a stack operation
destroying a case. Read the Object Lock warning before assuming any of this is
reversible.

Throughout, set these to your own values:

```sh
ORCHESTRATOR=<orchestrator account id>
EVIDENCE=<evidence account id>
REGION=<region>
ROLE=<a role you can assume into those accounts>   # e.g. OrganizationAccountAccessRole
```

## Rebuild — the easy direction

```sh
cd cdk
npm ci
npm test                                  # assertions on the design decisions
source ./bin/discover-accounts.sh         # or just export the account ids
npx cdk bootstrap aws://$EVIDENCE/$REGION # only if CDKToolkit is absent
npx cdk deploy FipCoreStack FipOrchestratorStack
```

Nothing here depends on prior state. If every resource below were deleted this
recreates all of it — except the bucket-name reuse window in step 3.

## Teardown — the hard direction

`cdk destroy` **will not remove most of this.** Every evidence-bearing resource is
`RETAIN`, so destroy detaches them and leaves them running.

### 0. STOP — is production retention in force?

```sh
aws ssm get-parameter --name /fip/evidence/retention-policy \
  --query Parameter.Value --output text
```

- `mode: NONE` — nothing is locked. This is the shipped default.
- `mode: GOVERNANCE` — deletable only with `s3:BypassGovernanceRetention`, and every
  bypass is logged. Not something to do casually.
- `mode: COMPLIANCE` — **teardown of the evidence bucket is impossible** until every
  object's retention expires. Not by you, not by root, not by AWS Support. That is the
  intended behavior and why production mode requires a deliberate decision.

### 1. Detach the stacks

```sh
npx cdk destroy FipOrchestratorStack   # removes Lambda, state machine, log groups
npx cdk destroy FipCoreStack           # RETAINs the CMK, buckets and table
```

### 2. Case table

```sh
aws dynamodb delete-table --table-name fip-cases
```

### 3. Buckets — versioned, so delete markers count too

Names are deterministic: `fip-evidence-$EVIDENCE-$REGION` and
`fip-evidence-access-logs-$EVIDENCE-$REGION`. Delete every version **and** every
delete marker, then the bucket.

**Then wait before recreating.** S3 holds a deleted bucket name for roughly 5–60
minutes. `cdk deploy` inside that window fails on bucket creation. Wait it out — do not
"fix" it by changing the bucket name.

### 4. KMS keys — the slow one

```sh
aws kms schedule-key-deletion --key-id alias/fip-evidence          --pending-window-in-days 7
aws kms schedule-key-deletion --key-id alias/fip-manifest-signing  --pending-window-in-days 7
```

**Minimum 7 days, maximum 30. There is no immediate delete.** Until it elapses the
alias is occupied. Rebuilding inside the window means `aws kms cancel-key-deletion`,
which restores the key and lets `cdk deploy` adopt it by alias.

Note: a key coming out of `PendingDeletion` has had its grants revoked. Anything that
relied on a grant — an Auto Scaling service-linked role launching encrypted volumes,
for instance — fails with `Client.InvalidKMSKey.InvalidState` until the grant is
recreated, and the error does not mention grants.

### 5. Member accounts

`FipMemberStack` is separate and lives in each member account. Delete the stack there;
it removes only the two roles and the permissions boundary. It does **not** remove:

- isolation security groups (`fip-isolation-<vpc>`) — harmless, free, and reused
- `fip:*` tags on instances, volumes, interfaces and snapshots
- any snapshot FIP created — **those are evidence; delete them deliberately, never as
  part of a teardown script**

## What cannot be recovered from

**Evidence under COMPLIANCE-mode Object Lock.** By design. See step 0.

**AWS accounts.** `DeletionPolicy` on `AWS::Organizations::Account` is `Retain`; an
account created programmatically cannot leave the organization until someone manually
supplies payment details and accepts the EULA; and `CloseAccount` suspends for up to 90
days. Treat accounts as fixed and rebuild inside them.

## Known follow-up

`cdk bootstrap` defaults its CloudFormation execution policy to `AdministratorAccess`.
Scope it with `--cloudformation-execution-policies` to a policy covering only what FIP
deploys. `iam:*` is unavoidable — CDK cannot create execution roles without it — so a
permissions boundary on CDK-created roles is the control that actually closes the gap.
