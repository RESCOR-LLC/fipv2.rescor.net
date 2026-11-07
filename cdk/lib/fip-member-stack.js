/**
 * FipMemberStack — the ONLY thing FIP puts in a member account.
 *
 * Two roles, deliberately separate:
 *
 *   FipInventoryRole  — read-only. Assumed constantly, changes nothing.
 *   FipResponderRole  — mutating. Snapshot, tag, contain, stop. Deployed
 *                       but assumed only during a case, and every
 *                       assumption should alarm.
 *
 * The responder is gated behind the DeployResponderRole parameter so the
 * retainer model is expressible in one template: inventory at
 * signing, responder activated per engagement.
 *
 * ── Deploy this whichever way the customer's org allows ───────────────
 * FIP does not impose a CCOE. This template is deliberately plain
 * so it works in all three shapes:
 *
 *   1. Plain CloudFormation, per account. Works with no organization at
 *      all. Manual, and entirely acceptable for a handful of accounts.
 *   2. Self-managed StackSet. Needs no org-level trust, only the
 *      administration/execution role pair.
 *   3. Service-managed StackSet at the org root with automatic
 *      deployment, so newly vended accounts are covered on creation.
 *      Best posture, and requires org buy-in — which is why it is the
 *      recommendation and not the requirement.
 *
 * OrchestratorAccountId is a CloudFormation parameter rather than a
 * synth-time constant so one template serves every deployment shape
 * without re-synthesis.
 *
 * No managed policies, and nothing like AdministratorAccess, here or anywhere.
 *
 * Manual: docs/MANUAL.md §6.2
 */

const { Stack, CfnParameter, CfnCondition, CfnOutput, Fn, Aws } = require('aws-cdk-lib');
const { Construct } = require('constructs');
const iam = require('aws-cdk-lib/aws-iam');

// The tag every forensic artifact carries, and the key that scopes every
// destructive permission below.
const CASE_TAG = 'fip:case-id';
// Marks FIP's own isolation groups so they can be found, reused and stripped
// without the role being able to touch any other security group.
const ISOLATION_TAG = 'fip:isolation';
// Written by containment on each interface it changes; read back by restore.
const ORIGINAL_SG_TAG = 'fip:original-sgs';
const { APPLICATION_TAG, APPLICATION, tagStack } = require('./fip-tags');

/**
 * Apply a CloudFormation Condition to every resource under `scope`.
 * L2 constructs expand into several CfnResources (role, policy, boundary),
 * and all of them have to share the condition or the template is invalid.
 */
function applyCondition(scope, condition) {
  for (const child of scope.node.findAll()) {
    const res = child.node.defaultChild || child;
    if (res && res.cfnOptions) res.cfnOptions.condition = condition;
  }
}

// Read-only, enumerated rather than wildcarded, so that reviewing what
// FIP can see in a member account is a matter of reading this list.
const INVENTORY_ACTIONS = [
  'ec2:DescribeInstances',
  'ec2:DescribeInstanceStatus',
  'ec2:DescribeInstanceAttribute',
  'ec2:DescribeVolumes',
  'ec2:DescribeSnapshots',
  'ec2:DescribeImages',
  'ec2:DescribeSecurityGroups',
  'ec2:DescribeNetworkInterfaces',
  'ec2:DescribeSubnets',
  'ec2:DescribeVpcs',
  'ec2:DescribeTags',
  'ec2:DescribeSnapshotAttribute',
  'ec2:DescribeSecurityGroupRules',
  'ssm:DescribeInstanceInformation',
  'autoscaling:DescribeAutoScalingGroups',
  'autoscaling:DescribeAutoScalingInstances',
  'elasticloadbalancing:DescribeTargetGroups',
  'elasticloadbalancing:DescribeTargetHealth',
  'ecs:ListContainerInstances',
  'ecs:DescribeContainerInstances',
  'eks:ListClusters',
  'eks:DescribeCluster',
  // Read-only, and it is what lets pre-flight refuse a target whose volumes
  // are encrypted with an AWS-MANAGED key. An AWS-managed key's policy cannot
  // be edited, so FIP can never be granted kms:CreateGrant on it and the
  // cross-account share is impossible — see fip-isolate.sh. Without this,
  // that failure surfaces eight minutes into a case with instances already
  // contained, as it did on 2026-10-21.
  'kms:DescribeKey',
];

// Acquisition — non-destructive, and never gated behind a human.
const ACQUISITION_ACTIONS = [
  'ec2:CreateSnapshots',
  'ec2:CreateSnapshot',
];

// Reading the snapshot block stream to hash it in place, before anything
// attaches, mounts or boots the volume.
const HASHING_ACTIONS = [
  'ebs:ListSnapshotBlocks',
  'ebs:ListChangedBlocks',
  'ebs:GetSnapshotBlock',
];

// Handing evidence to the forensic account. Sharing is free and instant;
// the copy happens on the far side under the forensic CMK.
// Snapshot-scoped, because the snapshot IS ours and IS tagged.
const EVIDENCE_TRANSFER_ACTIONS = [
  'ec2:ModifySnapshotAttribute',
];

// KMS against the MEMBER ACCOUNT'S OWN EBS key. These deliberately are NOT
// scoped by fip:case-id: that CMK belongs to the customer, FIP has no business
// tagging someone else's encryption key, and in a real member account it would
// usually lack permission to. Discovered by running a real acquisition:
// kms:CreateGrant was denied because the key carried no
// case tag and never would.
// Metadata only. Called DIRECTLY by FIP and by EC2 under the caller's own
// identity during ModifySnapshotAttribute, so kms:ViaService is NOT satisfied
// and must not be required — verified in a live test, where requiring it
// denied the share with EC2 AuthFailure "Not authorized to use key".
const MEMBER_KEY_METADATA_ACTIONS = [
  'kms:DescribeKey',
];

// The operations that actually touch plaintext. These ARE performed by EBS on
// the caller's behalf, so kms:ViaService holds and confines them to EBS — this
// role can never use the customer's key to decrypt anything else.
// Sharing an encrypted snapshot makes EC2 re-encrypt its data key under the
// caller's identity. That needs BOTH directions of ReEncrypt and the plaintext
// GenerateDataKey — not just the From/WithoutPlaintext variants, which is what
// this list originally had. CloudTrail named the missing actions
// (kms:ReEncryptTo, kms:GenerateDataKey) in one query after three rounds of
// guessing at the identity policy; EC2's own AuthFailure says only "Not
// authorized to use key" and carries no encoded message to decode.
const MEMBER_KEY_CRYPTO_ACTIONS = [
  'kms:ReEncryptFrom',
  'kms:ReEncryptTo',
  'kms:Decrypt',
  'kms:GenerateDataKey',
  'kms:GenerateDataKeyWithoutPlaintext',
];

// Containment. Service-affecting, so a confirmation gate sits in front
// of them — in the CLI and the state machine, not here.
const CONTAINMENT_ACTIONS = [
  'ec2:ModifyInstanceAttribute',
  'ec2:ModifyNetworkInterfaceAttribute',
  'ec2:StopInstances',
  'ec2:RevokeSecurityGroupEgress',
  'ec2:RevokeSecurityGroupIngress',
  'autoscaling:DetachInstances',
  'autoscaling:SuspendProcesses',
  'autoscaling:ResumeProcesses',
  'elasticloadbalancing:DeregisterTargets',
  'ecs:UpdateContainerInstancesState',
];

// Live triage and volatile capture inside the guest.
const GUEST_ACTIONS = [
  'ssm:SendCommand',
  'ssm:GetCommandInvocation',
  'ssm:ListCommandInvocations',
  'ssm:CancelCommand',
];

/**
 * Deliberately ABSENT from the responder role, each for a reason:
 *
 *   ec2:TerminateInstances  — FIP acquires and contains. Destroying the
 *                             host is the customer's action in their own
 *                             console, not something this role can do.
 *   ec2:DeleteSnapshot      — FIP must never be able to delete evidence.
 *                             Removing evidence is a human act, outside FIP.
 *   iam:*                   — no exceptions.
 *
 * ec2:CreateSecurityGroup WAS on this list, on the reasoning that the member
 * stack would pre-create one isolation group and the responder would only
 * apply it. That reasoning was wrong: security groups are VPC-scoped, a member
 * account may have many VPCs, and the compromised instance can be in any of
 * them — none knowable at deploy time. Pre-creating would have meant either
 * an SG in every VPC forever, or no isolation for instances in VPCs created
 * after deployment, which is the case that matters during an incident.
 *
 * Granting it costs little: a security group with no rules permits nothing,
 * creation is scoped to groups born tagged fip:isolation, and rule removal is
 * scoped to groups already carrying that tag. The role can create an empty
 * group and strip it. It cannot touch anyone else's.
 */
const DELIBERATELY_EXCLUDED = [
  'ec2:TerminateInstances',
  'ec2:DeleteSnapshot',
];

class FipMemberStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    tagStack(this, 'member');  // application=fipv2 and fip:class (lib/fip-tags.js)

    const orchestratorAccountId = new CfnParameter(this, 'OrchestratorAccountId', {
      type: 'String',
      description:
        'Account ID of the FIP orchestrator, the only principal permitted to ' +
        'assume this role.',
      allowedPattern: '^[0-9]{12}$',
      constraintDescription: 'Must be a 12-digit AWS account ID.',
    });

    // NOT a secret, despite how these are usually described. AWS is explicit:
    // "AWS does not treat the external ID as a secret ... The external ID for
    // a role can be seen by anyone with permission to view the role." So no
    // noEcho here — hiding it in DescribeStacks output while it sits in plain
    // sight in this role's own trust policy would only teach the wrong model.
    //
    // What it actually is: an unpredictable identifier, one per member
    // account, that solves the confused-deputy problem. It stops member
    // account A from inducing the FIP orchestrator to act against member
    // account B. That matters most when one orchestrator serves several
    // customers — a forensics provider running FIP as a service — which is
    // also the shape where aws:PrincipalOrgID cannot help.
    //
    // CRITICAL: it must be generated by whoever operates the ORCHESTRATOR,
    // not chosen by the account owner deploying this template. AWS: "it must
    // be generated by Example Corp and *not* their customers." A value the
    // account owner picks defeats the entire control.
    //
    // Mandatory, with no default. FIP does not limit the customer's
    // options, but this is a baseline property of the trust boundary rather
    // than an operational preference — the same category as enforcing TLS.
    const evidenceAccountId = new CfnParameter(this, 'EvidenceAccountId', {
      type: 'String',
      description:
        'Account ID holding the FIP evidence bucket and forensic CMK. The only ' +
        'account this role may grant access to the member key.',
      allowedPattern: '^[0-9]{12}$',
      constraintDescription: 'Must be a 12-digit AWS account ID.',
    });

    const externalId = new CfnParameter(this, 'ExternalId', {
      type: 'String',
      description:
        'Unpredictable per-account identifier issued by the FIP orchestrator ' +
        'operator, required on sts:AssumeRole. Not a secret — it is visible in ' +
        'this role trust policy. Do not invent your own value; use the one you ' +
        'were issued, or the confused-deputy protection it provides is void.',
      // AWS permits 2-1224 chars from this set. The floor here is deliberately
      // higher: AWS recommends "a random string generated by the third party",
      // and a two-character external ID is guessable, which is the one property
      // it must not be.
      allowedPattern: '^[A-Za-z0-9+=,.@:/-]{16,1224}$',
      constraintDescription:
        'At least 16 characters, alphanumeric plus + = , . @ : / - and no spaces.',
    });

    // Defense in depth when the customer has an organization: the
    // orchestrator's caller must also be inside it. A parameter, not synth
    // context, because this one template serves every install: as context it
    // was baked out of the committed template, and members deployed from it
    // silently lacked the condition. No default, so a deploy that forgets it
    // fails. "none" is the explicit choice for an install with no
    // organization, where the external ID and the named account carry the
    // guard alone; requiring an organization would be imposing one.
    const organizationId = new CfnParameter(this, 'OrganizationId', {
      type: 'String',
      description:
        'Your AWS Organizations id (o-...), required of the orchestrator as ' +
        'aws:PrincipalOrgID on every assume. The word none only if you have ' +
        'no organization.',
      allowedPattern: '^(o-[a-z0-9]{10,32}|none)$',
      constraintDescription: 'An organization id (o-...), or the word none.',
    });
    const hasOrganization = new CfnCondition(this, 'HasOrganization', {
      expression: Fn.conditionNot(Fn.conditionEquals(organizationId.valueAsString, 'none')),
    });

    const conditions = {
      StringEquals: {
        'sts:ExternalId': externalId.valueAsString,
        'aws:PrincipalOrgID': Fn.conditionIf(
          hasOrganization.logicalId, organizationId.valueAsString, Aws.NO_VALUE,
        ),
      },
    };

    const inventoryRole = new iam.Role(this, 'FipInventoryRole', {
      roleName: 'FipInventoryRole',
      description:
        'FIP read-only inventory. Assumed constantly; can change nothing.',
      assumedBy: new iam.PrincipalWithConditions(
        new iam.AccountPrincipal(orchestratorAccountId.valueAsString),
        conditions,
      ),
    });

    inventoryRole.addToPolicy(new iam.PolicyStatement({
      sid: 'FipReadOnlyInventory',
      actions: INVENTORY_ACTIONS,
      // Describe actions are not resource-scopable; the constraint that
      // matters is that every action above is read-only.
      resources: ['*'],
    }));

    new CfnOutput(this, 'InventoryRoleArn', { value: inventoryRole.roleArn });

    // ── FipResponderRole — the mutating one ───────────────────────────
    // Gated, so inventory can land at retainer signing and the responder
    // only when an engagement actually starts.
    const deployResponder = new CfnParameter(this, 'DeployResponderRole', {
      type: 'String',
      allowedValues: ['Yes', 'No'],
      default: 'Yes',
      description:
        'Deploy the mutating FipResponderRole. Choose No to grant read-only ' +
        'inventory now and activate response capability later.',
    });
    const responderEnabled = new CfnCondition(this, 'ResponderEnabled', {
      expression: Fn.conditionEquals(deployResponder.valueAsString, 'Yes'),
    });

    const responderScope = new Construct(this, 'Responder');

    // Permissions boundary: a ceiling the role cannot exceed even
    // if its own policy is later edited by someone with iam:PutRolePolicy
    // in this account. The deny half is the part that matters.
    const boundary = new iam.ManagedPolicy(responderScope, 'FipResponderBoundary', {
      managedPolicyName: 'FipResponderBoundary',
      description: 'Ceiling for FipResponderRole — cannot be exceeded by policy edits.',
      statements: [
        new iam.PolicyStatement({
          sid: 'CeilingAllow',
          actions: [
            ...INVENTORY_ACTIONS, ...ACQUISITION_ACTIONS, ...HASHING_ACTIONS,
            ...EVIDENCE_TRANSFER_ACTIONS,
            ...MEMBER_KEY_METADATA_ACTIONS, ...MEMBER_KEY_CRYPTO_ACTIONS,
            ...CONTAINMENT_ACTIONS, ...GUEST_ACTIONS, 'kms:CreateGrant',
            'ec2:CreateTags', 'ec2:CreateSecurityGroup',
            // Restore only, and only for one tag key: see FipRestorePolicy.
            'ec2:DeleteTags',
          ],
          resources: ['*'],
        }),
        new iam.PolicyStatement({
          sid: 'NeverEscalate',
          effect: iam.Effect.DENY,
          actions: ['iam:*', 'organizations:*', 'account:*'],
          resources: ['*'],
        }),
        new iam.PolicyStatement({
          sid: 'NeverDestroyEvidenceOrHosts',
          effect: iam.Effect.DENY,
          actions: DELIBERATELY_EXCLUDED,
          resources: ['*'],
        }),
      ],
    });

    const responderRole = new iam.Role(responderScope, 'FipResponderRole', {
      roleName: 'FipResponderRole',
      description:
        'FIP acquisition and containment. Assumed only during a case; every ' +
        'assumption should raise an alarm.',
      permissionsBoundary: boundary,
      assumedBy: new iam.PrincipalWithConditions(
        new iam.AccountPrincipal(orchestratorAccountId.valueAsString),
        conditions,
      ),
    });

    // Reading is unscopeable and harmless — same statement as inventory.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'Read',
      actions: INVENTORY_ACTIONS,
      resources: ['*'],
    }));

    // Tagging is the FIRST action of a case, so it cannot itself be scoped
    // by the tag it is about to set. Scope it by tag KEY instead: this role
    // can only ever write fip:* tags, never touch anyone else's. The one
    // other key is the product tag, and only with FIP's own value: it marks
    // what FIP created (lib/fip-tags.js), so the role may not set it to
    // anything else, or use it to relabel a customer's resource as ours.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'TagFipArtifactsOnly',
      actions: ['ec2:CreateTags'],
      resources: ['*'],
      conditions: {
        'ForAllValues:StringLike': { 'aws:TagKeys': ['fip:*', APPLICATION_TAG] },
        StringEqualsIfExists: { [`aws:RequestTag/${APPLICATION_TAG}`]: APPLICATION },
      },
    }));

    // Acquisition. Non-destructive and ungated.
    //
    // TWO statements, not one, and the reason is not obvious: ec2:CreateSnapshots
    // is authorized SEPARATELY against every resource it touches — the instance,
    // each volume, and each snapshot it creates. `aws:RequestTag` exists only in
    // the created-snapshot evaluations. A single statement requiring RequestTag
    // therefore denies the call at the *instance* evaluation, before any snapshot
    // is considered, with "no identity-based policy allows ec2:CreateSnapshots".
    //
    // Found by walking a real acquisition by hand.
    // iam:SimulatePrincipalPolicy does NOT catch it — it does not model
    // multi-resource actions — so a unit test alone would not have caught it
    // either. sts:decode-authorization-message is what identifies it.

    // (a) Source resources must ALREADY carry the case tag. This is why tagging
    //     the instance AND its volumes is step 1 of a case, before any snapshot.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AcquireFromTaggedSources',
      actions: ACQUISITION_ACTIONS,
      resources: [
        `arn:${Aws.PARTITION}:ec2:*:*:instance/*`,
        `arn:${Aws.PARTITION}:ec2:*:*:volume/*`,
      ],
      conditions: {
        StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' },
      },
    }));

    // (b) Created snapshots must be born tagged — that is what makes every
    //     downstream statement scopeable at all.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CreateTaggedSnapshots',
      actions: [...ACQUISITION_ACTIONS, 'ec2:CreateTags'],
      resources: [`arn:${Aws.PARTITION}:ec2:*:*:snapshot/*`],
      conditions: {
        StringLike: { [`aws:RequestTag/${CASE_TAG}`]: '*' },
      },
    }));

    // Hash in place, then share to the forensic account. Both restricted to
    // artifacts this role tagged — these ARE ours.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'HashAndTransferTaggedEvidence',
      actions: [...HASHING_ACTIONS, ...EVIDENCE_TRANSFER_ACTIONS],
      resources: ['*'],
      conditions: {
        StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' },
      },
    }));

    // The customer's own EBS CMK. Not tag-scopeable (see MEMBER_KEY_ACTIONS).
    // Bounded instead by kms:ViaService, so these permissions are usable only
    // through EBS/EC2 and never for arbitrary decryption of unrelated data.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadMemberKeyMetadata',
      actions: MEMBER_KEY_METADATA_ACTIONS,
      resources: ['*'],
    }));

    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'UseMemberKeyViaEbsOnly',
      actions: MEMBER_KEY_CRYPTO_ACTIONS,
      resources: ['*'],
      conditions: {
        StringEquals: { 'kms:ViaService': `ec2.${Aws.REGION}.amazonaws.com` },
      },
    }));

    // Granting the evidence account use of the member key is what makes an
    // encrypted snapshot shareable at all. Constrained by GRANTEE rather than by
    // tag: this role can only ever hand access to the one account that holds
    // FIP's evidence, and nowhere else.
    // EC2 creates a grant on the caller's behalf when sharing an encrypted
    // snapshot. That grant's grantee is an AWS service principal, not the
    // evidence account, so the GranteePrincipal constraint below cannot match
    // it — which is why sharing failed with EC2 AuthFailure "Not authorized to
    // use key" even once DescribeKey was allowed. kms:GrantIsForAWSResource is
    // the documented condition for exactly this case, and it confines the
    // permission to grants AWS creates for its own resources.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowEbsServiceCreatedGrant',
      actions: ['kms:CreateGrant'],
      resources: ['*'],
      conditions: {
        Bool: { 'kms:GrantIsForAWSResource': 'true' },
      },
    }));

    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'GrantEvidenceAccountOnly',
      actions: ['kms:CreateGrant'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'kms:GranteePrincipal': `arn:${Aws.PARTITION}:iam::${evidenceAccountId.valueAsString}:root`,
        },
      },
    }));

    // Containment, scoped to the tagged instance.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ContainTaggedInstances',
      actions: ['ec2:ModifyInstanceAttribute', 'ec2:ModifyNetworkInterfaceAttribute',
                'ec2:StopInstances'],
      resources: ['*'],
      conditions: {
        StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' },
      },
    }));

    // Volatile capture in the guest, scoped to the tagged instance via SSM's
    // own resource-tag key.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'GuestTriageOnTaggedInstances',
      actions: GUEST_ACTIONS,
      resources: [
        `arn:${Aws.PARTITION}:ec2:*:*:instance/*`,
        `arn:${Aws.PARTITION}:ssm:*:*:document/AWS-RunShellScript`,
        `arn:${Aws.PARTITION}:ssm:*:*:document/AWS-RunPowerShellScript`,
      ],
      conditions: {
        StringLike: { [`ssm:resourceTag/${CASE_TAG}`]: '*' },
      },
    }));

    // ── Isolation security group ──────────────────────────────────
    // The original design said the member stack would pre-create this. That
    // does not survive contact with reality: a security group is VPC-scoped,
    // a member account may have many VPCs, and the compromised instance can
    // be in any of them — none of them known at deploy time. So the responder
    // creates it on demand, per VPC, and reuses it across cases.
    //
    // ec2:CreateSecurityGroup is multi-resource in exactly the way
    // ec2:CreateSnapshots is: it is
    // authorized against the VPC it is created IN as well as the group being
    // created. aws:RequestTag exists only for the latter, so requiring it on
    // both denies every call.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CreateIsolationSgInAnyVpc',
      actions: ['ec2:CreateSecurityGroup'],
      // The VPC is the customer's and is not ours to tag, so no condition here.
      // Creating a security group grants nothing by itself — an SG with no
      // rules permits nothing, which is the entire point of this one.
      resources: [`arn:${Aws.PARTITION}:ec2:*:*:vpc/*`],
    }));

    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CreateIsolationSgBornTagged',
      actions: ['ec2:CreateSecurityGroup', 'ec2:CreateTags'],
      resources: [`arn:${Aws.PARTITION}:ec2:*:*:security-group/*`],
      conditions: {
        StringLike: { [`aws:RequestTag/${ISOLATION_TAG}`]: '*' },
      },
    }));

    // Strip the default allow-all egress rule from our own isolation group.
    // A new security group has no inbound rules and one outbound allow-all;
    // removing that is what makes it isolate rather than merely exist.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'StripRulesFromOwnIsolationSg',
      actions: ['ec2:RevokeSecurityGroupEgress', 'ec2:RevokeSecurityGroupIngress'],
      resources: [`arn:${Aws.PARTITION}:ec2:*:*:security-group/*`],
      conditions: {
        StringLike: { [`aws:ResourceTag/${ISOLATION_TAG}`]: '*' },
      },
    }));

    // Swapping an ENI's groups is authorized against the ENI, the instance and
    // the groups involved. The ENIs are tagged in the same first step as the
    // instance and its volumes, which is what makes this scopeable.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ApplyIsolationToTaggedInterfaces',
      actions: ['ec2:ModifyNetworkInterfaceAttribute'],
      resources: [
        `arn:${Aws.PARTITION}:ec2:*:*:network-interface/*`,
        `arn:${Aws.PARTITION}:ec2:*:*:security-group/*`,
        `arn:${Aws.PARTITION}:ec2:*:*:instance/*`,
      ],
      conditions: {
        StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' },
      },
    }));

    // NOT tag-scoped, and honestly so: Auto Scaling groups, target groups
    // and ECS container instances belong to the customer's workload and
    // will not be carrying fip:case-id when an incident starts. Scoping
    // these needs a per-case policy generated at acquisition time, which is
    // future work. Recorded rather than silently wildcarded.
    responderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'FleetContainmentUnscoped',
      actions: ['autoscaling:DetachInstances', 'autoscaling:SuspendProcesses',
                'autoscaling:ResumeProcesses',
                'elasticloadbalancing:DeregisterTargets',
                'ecs:UpdateContainerInstancesState'],
      resources: ['*'],
    }));

    applyCondition(responderScope, responderEnabled);

    // ── Restore: putting a contained instance back on its original groups ──
    //
    // The one place this role may attach a security group FIP did not create.
    // Chosen over requiring the member account's own credentials: in a crisis the person restoring service should not first
    // have to find an admin login for the affected account.
    //
    // What it widens, stated plainly. ModifyNetworkInterfaceAttribute is
    // authorized against the interface, the instance AND every group being
    // attached. The interface and instance must still carry fip:case-id
    // (ApplyIsolationToTaggedInterfaces). The GROUPS cannot be tag-scoped:
    // the originals are the customer's and carry no FIP tag. So with this
    // policy the role may put any EXISTING security group in the account onto
    // an interface FIP has tagged. It still cannot create a group with rules,
    // add a rule to any group, or touch an untagged instance's interfaces.
    // IAM has no condition that compares the groups requested with the
    // fip:original-sgs tag, so the restore code enforces that instead: it
    // takes the groups from the signed manifest, and refuses when the tag
    // disagrees.
    //
    // Its own parameter, so a customer who would rather keep restore a human
    // step with their own credentials can deploy without it.
    const allowRestore = new CfnParameter(this, 'AllowRestore', {
      type: 'String',
      allowedValues: ['Yes', 'No'],
      default: 'Yes',
      description:
        'Let FIP restore a contained instance to its original security groups ' +
        '(fip restore). No keeps restore a manual step with this account\'s own ' +
        'credentials.',
    });
    const restoreEnabled = new CfnCondition(this, 'RestoreEnabled', {
      expression: Fn.conditionAnd(
        responderEnabled,
        Fn.conditionEquals(allowRestore.valueAsString, 'Yes'),
      ),
    });

    const restoreScope = new Construct(this, 'Restore');
    new iam.Policy(restoreScope, 'FipRestorePolicy', {
      policyName: 'FipRestorePolicy',
      roles: [responderRole],
      statements: [
        new iam.PolicyStatement({
          sid: 'AttachOriginalGroupsOnRestore',
          actions: ['ec2:ModifyNetworkInterfaceAttribute'],
          resources: [`arn:${Aws.PARTITION}:ec2:*:${Aws.ACCOUNT_ID}:security-group/*`],
        }),
        // Clearing fip:original-sgs once restored, so a later case cannot
        // mistake today's groups for the originals. Only that key, only on
        // interfaces FIP tagged. The Null condition matters: DeleteTags with
        // no keys deletes EVERY tag, and ForAllValues over an empty key set
        // is vacuously true, so without it this would allow exactly that.
        new iam.PolicyStatement({
          sid: 'ClearOriginalGroupsTagOnly',
          actions: ['ec2:DeleteTags'],
          resources: [`arn:${Aws.PARTITION}:ec2:*:${Aws.ACCOUNT_ID}:network-interface/*`],
          conditions: {
            StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' },
            'ForAllValues:StringEquals': { 'aws:TagKeys': [ORIGINAL_SG_TAG] },
            Null: { 'aws:TagKeys': 'false' },
          },
        }),
      ],
    });
    applyCondition(restoreScope, restoreEnabled);

    const responderOut = new CfnOutput(this, 'ResponderRoleArn', {
      value: responderRole.roleArn,
      condition: responderEnabled,
    });
    void responderOut;
  }
}

module.exports = {
  FipMemberStack, INVENTORY_ACTIONS, ACQUISITION_ACTIONS, HASHING_ACTIONS,
  EVIDENCE_TRANSFER_ACTIONS, MEMBER_KEY_METADATA_ACTIONS, MEMBER_KEY_CRYPTO_ACTIONS,
  CONTAINMENT_ACTIONS, GUEST_ACTIONS,
  DELIBERATELY_EXCLUDED, CASE_TAG, ISOLATION_TAG, ORIGINAL_SG_TAG,
};
