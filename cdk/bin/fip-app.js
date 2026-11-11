#!/usr/bin/env node
/**
 * FIP v2 — CDK app entry. Manual: docs/MANUAL.md.
 *
 * JavaScript rather than TypeScript: there is no build step to break during
 * an incident, and `cdk assertions` is language-agnostic.
 *
 * FIP DOES NOT IMPOSE A CCOE. The base package does forensic isolation
 * and gives you a way to analyze images. Every organizational control —
 * the forensic-OU SCP, tag policies, a service-managed StackSet across the
 * org root, a delegated administrator, a Config aggregator — is an
 * optional hardening layer, switchable by the customer, never a
 * precondition. So: fip:orgId is optional, and the three accounts below
 * may collapse into fewer if that is what the customer has.
 *
 * THREE ACCOUNTS — separate by default, collapsible on request:
 *   - Orchestrator — in-org, delegated admin. Runs the state machines.
 *   - Evidence     — in-org. CMK, Object Lock bucket, case table. This
 *                    account never leaves your control.
 *   - Analysis     — MAY BE OUTSIDE THIS ORGANIZATION, because third-party
 *                    forensic examiners are granted access to it, and may
 *                    differ per case. Never assume aws:PrincipalOrgID
 *                    holds on that path. Optional.
 *
 * Account IDs come from the environment via ./bin/discover-accounts.sh —
 * never hardcoded. `fip configure` saves them; `fip deploy` passes them.
 *
 * Deploy order:
 *   1. source ./bin/discover-accounts.sh
 *   2. cdk deploy FipCoreStack   --profile fip-evidence
 *   3. Deploy FipMemberStack as a service-managed StackSet from the
 *      delegated admin, targeting the org root — NOT with `cdk deploy`.
 *      See synth/ for the template to hand to the StackSet.
 */

const { App, Aspects, DefaultStackSynthesizer } = require('aws-cdk-lib');
const { FipCoreStack, resolveRetentionPolicy } = require('../lib/fip-core-stack');
const { FipMemberStack } = require('../lib/fip-member-stack');
const { FipOrchestratorStack } = require('../lib/fip-orchestrator-stack');
const { FipAnalysisStack } = require('../lib/fip-analysis-stack');

const app = new App();

const REGION = process.env.AWS_REGION || 'us-east-1';

function requireAccountId(envKey) {
  const id = process.env[envKey];
  if (!id) {
    throw new Error(
      `${envKey} is not set. Either export it directly, or run ` +
      `\`source ./bin/discover-accounts.sh\` to look it up in AWS Organizations. ` +
      `If the account does not exist yet and you run AWS Control Tower, vend it ` +
      `through Account Factory rather than organizations:CreateAccount — a ` +
      `raw-API account lands unenrolled and unbaselined. Avoid OUs whose SCPs ` +
      `restrict bucket configuration to the Control Tower execution role; CDK's ` +
      `deploy role is not that principal.`
    );
  }
  return id;
}

// Optional. When set, org-scoped conditions are added as defense in
// depth. When absent, FIP still deploys — a customer with a single
// account and no organization is a supported deployment, not an error.
const orgId = app.node.tryGetContext('fip:orgId') || null;
// Resolved here as well as in the core stack, because the Lambda is what
// applies it: Object Lock retention is set per object as each manifest and
// custody record is written. It also labels what the Lambda creates; in
// test mode, evidence is fip:class=test and `fip cleanup` may remove it.
const retention = resolveRetentionPolicy(app.node);

// ── Evidence account: custody of everything that matters ──────────────
new FipCoreStack(app, 'FipCoreStack', {
  env: {
    account: requireAccountId('FIP_EVIDENCE_ACCOUNT_ID'),
    region: REGION,
  },
  orgId,
  // The orchestrator is the only in-org principal that writes evidence.
  // Passed by ID so the CMK key policy can name it rather than granting
  // the whole organization.
  // Collapsing orchestrator into the evidence account is a supported
  // minimal deployment. Separating them is better and is the default we
  // recommend; requiring it would be imposing a CCOE.
  orchestratorAccountId:
    process.env.FIP_ORCHESTRATOR_ACCOUNT_ID || requireAccountId('FIP_EVIDENCE_ACCOUNT_ID'),
  description:
    'FIP evidence foundation — CMK, Object Lock evidence bucket, case table, responder topic',
});

// ── Orchestrator account: the acquisition control plane ───────────────
// Holds no evidence and no customer data — only the state machine, the
// member-action Lambda, and the manifest signing key.
new FipOrchestratorStack(app, 'FipOrchestratorStack', {
  env: {
    account: process.env.FIP_ORCHESTRATOR_ACCOUNT_ID || requireAccountId('FIP_EVIDENCE_ACCOUNT_ID'),
    region: REGION,
  },
  evidenceAccountId: requireAccountId('FIP_EVIDENCE_ACCOUNT_ID'),
  orgId,
  // Optional. Sets a default for the release action; absent is supported, and
  // the account can also be named per release, because a third-party
  // examiner's account may differ per case.
  analysisAccountId: process.env.FIP_ANALYSIS_ACCOUNT_ID || null,
  retention,
  description: 'FIP acquisition control plane — FipCase and FipAcquisition state machines, member-action Lambda, manifest signing key',
});

// ── Analysis account: where an examiner works ─────────────────────────
// OPT-IN, and only synthesized when FIP_ANALYSIS_ACCOUNT_ID is set. Two
// reasons, both deliberate:
//
//   1. The analysis account MAY BE OUTSIDE YOUR ORGANIZATION, held by a
//      third-party examiner, and may differ per case. It is not part of the
//      base install and must never be a precondition for acquisition.
//   2. Cost. Interface endpoints and a workstation bill hourly whether or not
//      anyone is working. Acquisition and custody do not depend on this
//      stack, so nobody should pay for it before they have something to
//      analyze.
//
// Evidence is safe in the evidence account without it. This is the thing that
// gives examiners access with no bastion, no key pair and no ingress rule.
if (process.env.FIP_ANALYSIS_ACCOUNT_ID) {
  new FipAnalysisStack(app, 'FipAnalysisStack', {
    // ACCOUNT-AGNOSTIC, unlike the other stacks, and for a reason beyond
    // convenience. An env-specific stack containing a VPC makes CDK resolve
    // the account's availability zones through a context lookup, which needs
    // credentials IN THAT ACCOUNT at synth time. That breaks CI, and worse,
    // it breaks the whole third-party case: a template for an examiner's own
    // tenant cannot require us to hold credentials there. Agnostic means CDK
    // emits Fn::GetAZs and the examiner deploys it themselves — the same
    // reasoning as FipMemberStack.
    env: { region: REGION },
    evidenceAccountId: requireAccountId('FIP_EVIDENCE_ACCOUNT_ID'),
    // Passed, but NOT used to scope examiner trust. A third-party examiner's
    // account is not in your organization by definition, so org conditions
    // cannot carry that boundary.
    orgId,
    instanceType: app.node.tryGetContext('fip:analysisInstanceType') || undefined,
    // ARNs of the principals who may open a session. Comma-separated in
    // context so an engagement can be configured without a code change.
    examinerPrincipalArns: (app.node.tryGetContext('fip:examinerPrincipalArns') || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    // ARNs of the principals who may read results from outside the VPC.
    resultsReaderPrincipalArns: (app.node.tryGetContext('fip:resultsReaderPrincipalArns') || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    description:
      'FIP analysis account — isolated VPC, Session Manager workstation, examiner role. No bastion.',
  });
}

// ── Member-account payload: the StackSet ships THIS, and only this ────
// Synthesized here so it is reviewable and testable; deployed as a
// service-managed StackSet with automatic deployment, so a newly vended
// account is covered the moment it exists.
new FipMemberStack(app, 'FipMemberStack', {
  env: { region: REGION },
  // No bootstrap requirement. The default synthesizer injects a
  // CheckBootstrapVersion rule and a BootstrapVersion SSM lookup, which
  // would force `cdk bootstrap` into EVERY member account — CDK deploy
  // roles and an assets bucket in accounts that need neither, and a hard
  // stop for the two deployment shapes FIP supports: plain CloudFormation
  // and self-managed StackSets. This stack has no assets, so the rule buys
  // nothing and costs the property the committed template exists for.
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  // No orgId: the organization is the OrganizationId parameter, so the one
  // committed template serves every install.
  orchestratorAccountId: process.env.FIP_ORCHESTRATOR_ACCOUNT_ID || '',
  description: 'FIP member-account payload — FipInventoryRole (read-only) only',
});

// cdk-nag is opt-in rather than always-on: it is a CI gate, and having it
// fire on every local `cdk synth` trains people to ignore it.
if (app.node.tryGetContext('fip:nag') === 'true') {
  const { AwsSolutionsChecks, NagSuppressions } = require('cdk-nag');
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

  // Suppressions live here, not in the stacks, so cdk-nag stays a dev
  // dependency and never enters a deployment's require() path.
  //
  // Each one states its evidence. A suppression without a reason is just
  // a disabled test, and this is the file where that would go unnoticed.
  NagSuppressions.addResourceSuppressionsByPath(
    app.node.tryFindChild('FipMemberStack'),
    '/FipMemberStack/FipInventoryRole/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'ec2:Describe*, autoscaling:Describe*, elasticloadbalancing:Describe* and ' +
        'the other actions in INVENTORY_ACTIONS do not support resource-level ' +
        'permissions — AWS evaluates them against "*" only, so scoping them is ' +
        'not possible rather than merely unattempted. The control that matters ' +
        'here is that every action in the list is read-only, which ' +
        'test/fip-member-stack.test.js asserts on each action individually. ' +
        'The mutating FipResponderRole IS resource-scoped ' +
        'by aws:ResourceTag/fip:case-id.',
      appliesTo: ['Resource::*'],
    }],
  );

  // The permissions boundary is a CEILING, not a grant. It has to span "*"
  // because it bounds actions against resources that do not exist yet when
  // a case opens — the snapshots this role is about to create. Narrowing
  // the ceiling narrows what the role can EVER do, which is the opposite of
  // the control's purpose. Its operative half is the Deny statements
  // (iam:*, organizations:*, account:*, terminate, delete-snapshot), and
  // test/fip-member-stack.test.js asserts each of those denies individually.
  NagSuppressions.addResourceSuppressionsByPath(
    app.node.tryFindChild('FipMemberStack'),
    '/FipMemberStack/Responder/FipResponderBoundary/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'Permissions boundary — a maximum, not a grant. Must cover resources not yet ' +
        'created at case-open time. The Deny statements carry the control and are ' +
        'individually asserted by unit tests.',
      appliesTo: ['Resource::*'],
    }],
  );

  // The responder's wildcards are scoped by CONDITION rather than by
  // resource ARN, which AwsSolutions-IAM5 does not inspect:
  //   - Describe* actions do not support resource-level permissions at all.
  //   - Every mutating statement carries aws:ResourceTag/fip:case-id or
  //     aws:RequestTag/fip:case-id; CreateTags is bounded by aws:TagKeys.
  //   - Instance ARNs cannot be enumerated before an incident exists, so
  //     guest triage is scoped by ssm:resourceTag/fip:case-id instead.
  //   - The two SSM documents are AWS-managed and named exactly; only
  //     account and region are wild.
  // The one genuinely unscoped statement is FleetContainmentUnscoped, and
  // it is labeled as such in the source: ASGs, target groups and ECS
  // container instances belong to the customer's workload and will not
  // carry fip:case-id when an incident starts. Per-case generated policy is
  // future work.
  NagSuppressions.addResourceSuppressionsByPath(
    app.node.tryFindChild('FipMemberStack'),
    '/FipMemberStack/Responder/FipResponderRole/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'Scoped by condition rather than resource ARN: aws:ResourceTag/fip:case-id, ' +
        'aws:RequestTag/fip:case-id, aws:TagKeys and ssm:resourceTag/fip:case-id. ' +
        'Describe* actions are not resource-scopable. Target instance ARNs are ' +
        'unknowable before an incident. Fleet containment (ASG/ELB/ECS) is knowingly ' +
        'unscoped pending per-case policy generation.',
      appliesTo: [
        'Resource::*',
        'Resource::arn:<AWS::Partition>:ec2:*:*:instance/*',
        // Acquisition touches every volume on the target instance and creates a
        // snapshot per volume; neither set can be enumerated before the case
        // exists. Both statements are scoped by fip:case-id instead — by
        // aws:ResourceTag on the sources, aws:RequestTag on the snapshots.
        'Resource::arn:<AWS::Partition>:ec2:*:*:volume/*',
        'Resource::arn:<AWS::Partition>:ec2:*:*:snapshot/*',
        // Containment. The VPC is the customer's and cannot be enumerated at
        // deploy time; the security group is created by this role and born
        // tagged fip:isolation, which is what scopes rule removal to FIP's own
        // groups; the interfaces belong to the instance under acquisition and
        // are scoped by fip:case-id, tagged in the first step of the case.
        'Resource::arn:<AWS::Partition>:ec2:*:*:vpc/*',
        'Resource::arn:<AWS::Partition>:ec2:*:*:security-group/*',
        'Resource::arn:<AWS::Partition>:ec2:*:*:network-interface/*',
        'Resource::arn:<AWS::Partition>:ssm:*:*:document/AWS-RunShellScript',
        'Resource::arn:<AWS::Partition>:ssm:*:*:document/AWS-RunPowerShellScript',
      ],
    }],
  );

  // fip restore (FipRestorePolicy, AllowRestore=Yes).
  NagSuppressions.addResourceSuppressionsByPath(
    app.node.tryFindChild('FipMemberStack'),
    '/FipMemberStack/Restore/FipRestorePolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'Restore attaches the groups an interface had before isolation, which are ' +
        'the customer\'s and cannot be named before an incident. The interface and ' +
        'instance halves of ModifyNetworkInterfaceAttribute are still authorized ' +
        'only where aws:ResourceTag/fip:case-id is set, so this statement can move ' +
        'only a case\'s own interfaces. DeleteTags is scoped by condition to the ' +
        'single key fip:original-sgs on case-tagged interfaces, with Null ' +
        'aws:TagKeys false so an empty key list cannot delete every tag. Asserted ' +
        'in test/fip-member-stack.test.js.',
      appliesTo: [
        'Resource::arn:<AWS::Partition>:ec2:*:<AWS::AccountId>:security-group/*',
        'Resource::arn:<AWS::Partition>:ec2:*:<AWS::AccountId>:network-interface/*',
      ],
    }],
  );

  // ── Evidence account ────────────────────────────────────────────────
  NagSuppressions.addResourceSuppressionsByPath(
    app.node.tryFindChild('FipCoreStack'),
    '/FipCoreStack/FipEvidenceRole/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'ec2:CopySnapshot names its source by id and region rather than ARN, and ' +
        'the destination snapshot does not exist when the call is authorized, so ' +
        'neither side is scopeable. The EBS direct APIs are likewise not ' +
        'resource-scopable. The kms:*DataKey*/ReEncrypt* wildcards are CDK\'s own ' +
        'grantEncryptDecrypt expansion against a single named key. The S3 wildcard ' +
        'is confined to the cases/ prefix and to PutObject/GetObject — this role ' +
        'has no delete and cannot alter retention, so it can add evidence and ' +
        'never remove it. The real control is that this role exists only in the ' +
        'evidence account and can do nothing else there.',
      appliesTo: [
        'Resource::*',
        'Action::kms:GenerateDataKey*',
        'Action::kms:ReEncrypt*',
        'Resource::<FipEvidence97536970.Arn>/cases/*',
        // Releasing a case's evidence to an analysis account. Snapshot ids do
        // not exist at deploy time, so the ARN is wild — but the statement
        // carries a condition on aws:ResourceTag/fip:case-id, which every
        // evidence copy is born with, so an untagged or unrelated snapshot
        // cannot be shared out of this account. AwsSolutions-IAM5 inspects
        // resource ARNs and not conditions, which is why this needs saying.
        // test/fip-core-stack.test.js asserts the condition is present and
        // that this role still has no ec2:DeleteSnapshot.
        'Resource::arn:<AWS::Partition>:ec2:*:*:snapshot/*',
      ],
    }],
  );

  // ── Orchestrator ────────────────────────────────────────────────────
  const orchestrator = app.node.tryFindChild('FipOrchestratorStack');

  NagSuppressions.addResourceSuppressionsByPath(
    orchestrator,
    '/FipOrchestratorStack/FipMemberAction/ServiceRole/Resource',
    [{
      id: 'AwsSolutions-IAM4',
      reason:
        'AWSLambdaBasicExecutionRole grants CloudWatch Logs write and nothing else. ' +
        'FIP uses no managed policies on roles that reach INTO member accounts. This is ' +
        'the function\'s own log-writing role inside the orchestrator account, and its ' +
        'cross-account reach is defined entirely by the inline policy alongside it.',
      appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
    }],
  );

  NagSuppressions.addResourceSuppressionsByPath(
    orchestrator,
    '/FipOrchestratorStack/FipMemberAction/ServiceRole/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'Member account IDs cannot be enumerated at deploy time — that is the whole ' +
        'point of an org-wide responder role, and new accounts are covered the moment ' +
        'they are vended. What IS pinned is the role NAME (only FipResponderRole, never ' +
        'an arbitrary role) and, where the customer has an organization, an ' +
        'aws:ResourceOrgId condition. The SSM wildcard is one parameter per member ' +
        'account at a fixed path ending in /external-id.',
      appliesTo: [
        'Resource::arn:<AWS::Partition>:iam::*:role/FipResponderRole',
        // Regex, not a literal: the rendered ARN embeds the orchestrator's
        // account id and region, so a literal only matches the account it was
        // written against. It was written against CI's placeholder, which meant
        // the suppression held in CI and failed on every real deployment —
        // exactly backwards. Found 2026-09-22.
        { regex: String.raw`/^Resource::arn:<AWS::Partition>:ssm:.*:parameter/fip/member/\*/external-id$/g` },
      ],
    }],
  );

  NagSuppressions.addResourceSuppressionsByPath(
    orchestrator,
    '/FipOrchestratorStack/FipAcquisition/Role/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'CDK grants the state machine lambda:InvokeFunction on the function plus its ' +
        'versions and aliases, which is the trailing :* — the function itself is pinned. ' +
        'The Resource::* entries are X-Ray trace submission (tracingEnabled) and ' +
        'CloudWatch Logs delivery, neither of which supports resource-level permissions.',
      appliesTo: [
        'Resource::<FipMemberAction0941B49B.Arn>:*',
        'Resource::*',
      ],
    }],
  );

  NagSuppressions.addResourceSuppressionsByPath(
    orchestrator,
    '/FipOrchestratorStack/FipCase/Role/DefaultPolicy/Resource',
    [{
      id: 'AwsSolutions-IAM5',
      reason:
        'The fan-out parent. Two of these are the same CDK grant expansions as ' +
        'FipAcquisition above: lambda:InvokeFunction on the function plus its versions ' +
        'and aliases, and Resource::* for X-Ray submission and CloudWatch Logs ' +
        'delivery, neither of which supports resource-level permissions. The third is ' +
        'the .sync integration: states:DescribeExecution and states:StopExecution are ' +
        'authorized against EXECUTION ARNs, and an execution does not exist when the ' +
        'policy is written, so the wildcard is on the execution id. The state machine ' +
        'it belongs to is pinned by name — FipCase can start and observe ' +
        'FipAcquisition and nothing else.',
      appliesTo: [
        'Resource::<FipMemberAction0941B49B.Arn>:*',
        'Resource::*',
        // Regex for the same reason as the SSM entry above: the rendered ARN
        // carries the orchestrator's account id and region, so a literal would
        // match only the account it was written against — CI's placeholder.
        // It also embeds an Fn::Select over the child's Ref, which is not
        // stable text worth pinning.
        { regex: String.raw`/^Resource::arn:<AWS::Partition>:states:.*:execution:.*\*$/g` },
      ],
    }],
  );

  // ── Analysis account ────────────────────────────────────────────────
  // Only present when FIP_ANALYSIS_ACCOUNT_ID is set, so guard the lookup
  // rather than assuming the stack exists.
  const analysis = app.node.tryFindChild('FipAnalysisStack');
  if (analysis) {
    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipAnalysisWorkstationRole/Resource',
      [{
        id: 'AwsSolutions-IAM4',
        reason:
          'AmazonSSMManagedInstanceCore is what lets the SSM agent on this instance ' +
          'register and carry a session. FIP uses no managed policies on roles that ' +
          'reach INTO member accounts. This role reaches nowhere: it is an instance profile in the analysis ' +
          'account with no cross-account trust at all. It is also the policy AWS ' +
          'documents for this purpose, and hand-rolling it would drift from whatever ' +
          'Session Manager requires next.',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSSMManagedInstanceCore'],
      }],
    );

    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipAnalysisWorkstationRole/DefaultPolicy/Resource',
      [{
        id: 'AwsSolutions-IAM5',
        reason:
          'Transcript writing, append-only and confined to one prefix of one bucket. ' +
          'NOTE what is deliberately absent: s3:DeleteObject*. CDK grantWrite would ' +
          'have included it, which would let the examiner — who holds a shell on this ' +
          'instance and therefore its role — delete the transcript of the session they ' +
          'are in. The kms wildcards are CDK\'s own grant expansion against a single ' +
          'named key, and this role can Encrypt but not Decrypt, so it cannot read ' +
          'back another session. Results are the same shape: s3:PutObject only, on ' +
          'the results/ prefix of the results bucket, with no read-back and no delete.',
        appliesTo: [
          'Resource::<FipSessionLogs1E41B5D5.Arn>/sessions/*',
          { regex: String.raw`/^Resource::<FipResults[0-9A-F]+\.Arn>\/results\/\*$/g` },
          'Action::kms:GenerateDataKey*',
          { regex: String.raw`/^Resource::<FipSessionLogGroup.*\.Arn>.*$/g` },
        ],
      }],
    );

    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipExaminerRole/DefaultPolicy/Resource',
      [{
        id: 'AwsSolutions-IAM5',
        reason:
          'Two wildcards, both unavoidable. The session ARN wildcard is AWS\'s own ' +
          'documented form for scoping TerminateSession/ResumeSession to the caller\'s ' +
          'OWN sessions — ${aws:userid} is not available as a resource path segment any ' +
          'other way. The Resource::* statement is ec2:DescribeInstances and the ssm ' +
          'Describe/GetConnectionStatus calls, none of which support resource-level ' +
          'permissions; all are read-only. What matters is that ssm:StartSession IS ' +
          'pinned, to one instance AND the logged session document, and that this role ' +
          'carries an explicit Deny on every route to altering the audit trail. ' +
          'test/fip-analysis-stack.test.js asserts both.',
        appliesTo: [
          'Resource::*',
          { regex: String.raw`/^Resource::arn:<AWS::Partition>:ssm:.*:session/.*\*$/g` },
        ],
      }],
    );

    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipResultsReaderRole/DefaultPolicy/Resource',
      [{
        id: 'AwsSolutions-IAM5',
        reason:
          'Read-only: s3:Get* on the results/ prefix of the one results bucket, whose ' +
          'object names are written by the examiner and cannot be known at deploy time. ' +
          'The role carries an explicit Deny on every write, delete and retention ' +
          'change; test/fip-analysis-stack.test.js asserts it.',
        appliesTo: [
          { regex: String.raw`/^Resource::<FipResults[0-9A-F]+\.Arn>\/results\/\*$/g` },
        ],
      }],
    );

    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipAnalysisWorkstation/Resource',
      [{
        id: 'AwsSolutions-EC28',
        reason:
          'Detailed (one-minute) monitoring bills per instance and tells an examiner ' +
          'nothing a forensic workstation needs. The signal that matters here is the ' +
          'session transcript, which is captured keystroke-level to S3 and CloudWatch, ' +
          'plus VPC flow logs proving the workstation talked only to the endpoints. ' +
          'Termination protection, which is the other half of this rule pair, IS ' +
          'enabled.',
      }],
    );

    NagSuppressions.addResourceSuppressionsByPath(
      analysis,
      '/FipAnalysisStack/FipSessionAccessLogs/Resource',
      [{
        id: 'AwsSolutions-S1',
        reason:
          'This IS the access-log bucket. Giving it its own access-log bucket is a ' +
          'recursive dependency and an unbounded cost, and access logs are not ' +
          'evidence. Same decision as the evidence bucket\'s access logs in ' +
          'FipCoreStack.',
      }],
    );
  }
}
