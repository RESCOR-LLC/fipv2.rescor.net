/**
 * FipCoreStack — the evidence foundation. Deploys to the EVIDENCE account.
 *
 * Everything in FIP that must survive a compromised member account lives
 * here: the CMK evidence is re-encrypted under, the Object Lock
 * bucket the signed manifests land in, the case table, and the
 * responder topic that carries approval task tokens.
 *
 * ── Object Lock: enabled here, applied elsewhere ──────────────────────
 * These are two different things and the distinction is the whole design
 *:
 *
 *   ENABLED  — a bucket-creation-time flag. Cannot be added afterward, so
 *              the standing rule is to enable it on every new bucket,
 *              always. Enabling it locks NOTHING by itself.
 *   APPLIED  — per-object retention, set at write time by the acquisition
 *              runtime, from the policy this stack publishes to SSM.
 *
 * So this stack sets objectLockEnabled: true and deliberately sets NO
 * default retention. During install and test nothing is locked at all —
 * deploying and exercising FIP in a customer's account must never leave
 * undeletable objects and an unbillable storage commitment behind.
 * Production mode is an explicit switch that REQUIRES the customer to
 * supply a duration in days. There is no default and none will be
 * invented here: forensic data has no obvious statutory retention, and
 * enforcing one the customer did not choose is not this tool's job.
 *
 * ── FIP does not impose a CCOE ────────────────────────────────────────
 * The base package does forensic isolation and gives you a way to analyze
 * images. That is the product. Everything organizational — an SCP-backed
 * forensic OU, tag policies, a service-managed StackSet across the org
 * root, a delegated administrator, a Config aggregator — is an OPTIONAL
 * hardening layer the customer may switch on, never a precondition for
 * FIP working. Concretely, in this stack: `orgId` is optional, and its
 * absence degrades a defense-in-depth condition rather than failing the
 * deployment. FIP must run for a customer with one account and no
 * organization at all.
 *
 * Manual: docs/MANUAL.md §8
 */

const { Stack, Duration, RemovalPolicy, CfnOutput, Aws } = require('aws-cdk-lib');
// Imported rather than redeclared. This tag is the scoping mechanism for
// policies in THREE accounts, so two copies of the string is two chances for
// them to drift apart — and a drifted tag fails as an AccessDenied in a
// different account from the one that was edited.
const { CASE_TAG } = require('./fip-member-stack');
const s3 = require('aws-cdk-lib/aws-s3');
const kms = require('aws-cdk-lib/aws-kms');
const iam = require('aws-cdk-lib/aws-iam');
const sns = require('aws-cdk-lib/aws-sns');
const ssm = require('aws-cdk-lib/aws-ssm');
const dynamodb = require('aws-cdk-lib/aws-dynamodb');
const { tagStack } = require('./fip-tags');

const VALID_RETENTION_MODES = ['GOVERNANCE', 'COMPLIANCE'];

/**
 * Resolve the evidence retention policy from context, and refuse to
 * produce an incoherent one. Exported for direct unit testing, because
 * "production mode without a duration must fail" is a decision, not an
 * implementation detail.
 */
function resolveRetentionPolicy(node) {
  const productionMode = node.tryGetContext('fip:productionMode') === true
    || node.tryGetContext('fip:productionMode') === 'true';
  const mode = node.tryGetContext('fip:retentionMode') || 'GOVERNANCE';
  const rawDays = node.tryGetContext('fip:retentionDays');
  const days = rawDays === null || rawDays === undefined || rawDays === ''
    ? null
    : Number(rawDays);

  if (!productionMode) {
    // Install/test. Nothing is locked, whatever else context says.
    return { productionMode: false, mode: 'NONE', days: null };
  }

  if (!VALID_RETENTION_MODES.includes(mode)) {
    throw new Error(
      `fip:retentionMode must be one of ${VALID_RETENTION_MODES.join(', ')} ` +
      `when fip:productionMode is true (got ${JSON.stringify(mode)}).`
    );
  }
  if (!Number.isInteger(days) || days < 1) {
    throw new Error(
      'fip:productionMode is true, so fip:retentionDays must be a positive ' +
      'integer number of days supplied by the customer. FIP ships no default ' +
      'retention and asserts no legal minimum — see manual §8.'
    );
  }
  return { productionMode: true, mode, days };
}

class FipCoreStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    tagStack(this, 'core');  // application=fipv2 and fip:class (lib/fip-tags.js)

    // orgId is optional by design — see the CCOE note in the header.
    const { orgId = null, orchestratorAccountId } = props;
    const retention = resolveRetentionPolicy(this.node);

    // ── Evidence CMK ──────────────────────────────────────────────────
    // Evidence is copied out of the (potentially compromised) member
    // account and re-encrypted under THIS key, in THIS account, so that
    // custody no longer depends on a grant living in the account you
    // have just declared hostile.
    const evidenceKey = new kms.Key(this, 'FipEvidenceKey', {
      alias: 'alias/fip-evidence',
      description: 'FIP evidence encryption — snapshots, manifests, case data',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // Principal:"*" guarded by ArnLike on aws:SourceArn does not work:
    // SourceArn is not populated for a principal calling KMS directly, so
    // it either never grants or grants far too broadly. Name the principal.
    //
    // The org condition is defense in depth ON TOP of a named account,
    // not the thing doing the work — so when the customer has no
    // organization we simply omit it rather than refusing to deploy.
    //
    // CAREFUL: aws:PrincipalOrgID evaluates the CALLING principal, so this
    // is the ORCHESTRATOR's organization, not this evidence account's. When
    // a forensics provider operates FIP on a customer's behalf
    // (provider-operated) and this stack is deployed into the customer's
    // account, setting fip:orgId to the customer's org silently locks the
    // provider out of the evidence they were engaged to collect. Set it to
    // the provider's org, or omit it and let the named account plus the
    // external ID carry the trust. Set it to your own org only for a
    // self-operated deployment.
    evidenceKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowOrchestratorUse',
      principals: [new iam.AccountPrincipal(orchestratorAccountId)],
      actions: [
        'kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*',
        'kms:GenerateDataKey*', 'kms:DescribeKey', 'kms:CreateGrant',
      ],
      resources: ['*'],
      ...(orgId ? { conditions: { StringEquals: { 'aws:PrincipalOrgID': orgId } } } : {}),
    }));

    // ── Access logs for the evidence bucket ───────────────────────────
    // No Object Lock here: a locked access-log bucket is a recursive
    // dependency and a cost trap, and access logs are not evidence.
    const accessLogsBucket = new s3.Bucket(this, 'FipEvidenceAccessLogs', {
      bucketName: `fip-evidence-access-logs-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [{ id: 'expire-access-logs', expiration: Duration.days(400) }],
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ── The evidence bucket ───────────────────────────────────────────
    const evidenceBucket = new s3.Bucket(this, 'FipEvidence', {
      // Account+region suffix: bucket names are globally unique, and a
      // hardcoded name blocks recreation for S3's post-delete
      // consistency window. Same reasoning as pki's log archive.
      bucketName: `fip-evidence-${this.account}-${this.region}`,

      // Enabled, never defaulted. See the header comment — this is the
      // single most consequential pair of lines in the stack.
      objectLockEnabled: true,
      // objectLockDefaultRetention: DELIBERATELY ABSENT.

      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: evidenceKey,
      bucketKeyEnabled: true,
      enforceSSL: true,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'evidence/',
      // DeletionPolicy: Delete would be precisely backwards for evidence.
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ── The retention policy, published for the runtime ───────────────
    // The bucket cannot express "no retention now, customer-chosen
    // retention later" — only per-object writes can. So the decision
    // lives here, in one inspectable place, and the acquisition runtime
    // reads it at write time.
    const retentionParam = new ssm.StringParameter(this, 'FipRetentionPolicy', {
      parameterName: '/fip/evidence/retention-policy',
      stringValue: JSON.stringify(retention),
      description:
        'Evidence retention applied per object at write time. mode NONE means ' +
        'install/test: nothing is locked. Switching to production requires a ' +
        'customer-supplied duration in days (manual §8).',
    });

    // ── Case table ────────────────────────────────────────────────────
    const caseTable = new dynamodb.Table(this, 'FipCases', {
      tableName: 'fip-cases',
      partitionKey: { name: 'caseId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: evidenceKey,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ── Responder topic ───────────────────────────────────────────────
    // Carries Step Functions task tokens for the few gates that survive
    // FIP's design, and case notifications. The customer subscribes their own
    // Lambda here to build Slack/Teams/PagerDuty approval — that is the
    // whole integration surface, deliberately.
    const responderTopic = new sns.Topic(this, 'FipResponders', {
      topicName: 'fip-responders',
      displayName: 'FIP responder notifications and approval requests',
      masterKey: evidenceKey,
    });

    // ── FipEvidenceRole — the orchestrator's way in ───────────────────
    // ec2:CopySnapshot must be called in the DESTINATION account, so the copy
    // that finally moves evidence out of the compromised member account can
    // only be initiated from here. Sharing snapshots and granting key access
    // alone would leave ownership — and therefore the power to
    // delete the evidence — with the account under investigation.
    //
    // Deliberately narrow. This role copies snapshots in, writes manifests and
    // case records, and nothing else. It cannot read member accounts, cannot
    // delete snapshots, and cannot touch the retention policy.
    const evidenceRole = new iam.Role(this, 'FipEvidenceRole', {
      roleName: 'FipEvidenceRole',
      description: 'Assumed by the FIP orchestrator to land evidence in this account',
      assumedBy: new iam.PrincipalWithConditions(
        new iam.AccountPrincipal(orchestratorAccountId),
        orgId ? { StringEquals: { 'aws:PrincipalOrgID': orgId } } : {},
      ),
    });

    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CopySnapshotsIntoThisAccount',
      actions: ['ec2:CopySnapshot', 'ec2:DescribeSnapshots', 'ec2:CreateTags'],
      // CopySnapshot names the source by id and region, not by ARN, and the
      // destination snapshot does not exist yet — neither side is scopeable.
      // The control is that this role exists only in the evidence account and
      // can do nothing else with EC2.
      resources: ['*'],
    }));

    // Hashing the RETAINED copy happens here, in the evidence account, because
    // this is where the artifact of record lives. Easy to forget: the
    // responder role has these for the source snapshot, but that is a
    // different role in a different account reading a different artifact.
    // Releasing a case's evidence to an analysis account, and withdrawing it
    // again. createVolumePermission lets that account turn a snapshot into a
    // volume; it confers no delete, and this role has no ec2:DeleteSnapshot
    // to confer. Scoped to snapshots carrying a case tag, which every
    // evidence copy is born with — so this cannot share an untagged or
    // unrelated snapshot out of the account.
    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReleaseTaggedEvidenceToAnalysis',
      actions: ['ec2:ModifySnapshotAttribute'],
      resources: [`arn:${Aws.PARTITION}:ec2:*:*:snapshot/*`],
      conditions: { StringLike: { [`aws:ResourceTag/${CASE_TAG}`]: '*' } },
    }));

    // Withdrawal must be able to complete. A release creates a KMS grant as
    // well as a snapshot share, and removing only the share leaves access that
    // is invisible in the snapshot's permissions — so the grant has to be
    // retirable or "revoked" would be a lie.
    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'WithdrawEvidenceGrants',
      actions: ['kms:ListGrants', 'kms:RetireGrant', 'kms:RevokeGrant'],
      resources: [evidenceKey.keyArn],
    }));

    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'HashRetainedEvidence',
      actions: ['ebs:ListSnapshotBlocks', 'ebs:ListChangedBlocks', 'ebs:GetSnapshotBlock'],
      resources: ['*'],
    }));

    // Reading the SOURCE key during the copy. The comment that used to sit here
    // said the grant the member account issues during the share step was
    // sufficient and "no permission on it is needed here". THAT IS WRONG, and
    // it made every cross-account copy fail with "Given key ID is not
    // accessible" — measured on 2026-10-21, after the grant was confirmed
    // present on the member key.
    //
    // A KMS grant to an external account's root makes the key AVAILABLE to
    // that account; it does not by itself authorize any particular principal
    // in it. The receiving account's IAM must also allow the action. Both are
    // required, and only one was there.
    //
    // Resource must be * because member CMK ARNs are unknowable at deploy time
    // — that is the whole point of an org-wide responder role. kms:ViaService
    // confines this to EC2, which is the only path that should ever use it: the
    // snapshot copy. Same scoping the member stack already uses for the
    // customer's own key.
    // SPLIT, and the split is the whole point — this is the second time this
    // exact trap has been hit in this codebase. kms:DescribeKey is called
    // DIRECTLY, not through EC2, so a kms:ViaService condition is never
    // satisfied for it and the statement silently does not apply. The member
    // stack already learned this (MEMBER_KEY_METADATA_ACTIONS vs
    // MEMBER_KEY_CRYPTO_ACTIONS) and the lesson was not carried across.
    //
    // Measured on 2026-10-21: with DescribeKey behind ViaService, CopySnapshot
    // was ACCEPTED and the async copy then failed "Given key ID is not
    // accessible" — the API call succeeds and the background work does not,
    // which is why this was invisible until a real copy ran.
    //
    // A cross-account encrypted copy needs DescribeKey AND CreateGrant AND
    // Decrypt on the SOURCE key, not Decrypt alone.
    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'DescribeSourceKeysDuringCopy',
      actions: ['kms:DescribeKey'],
      // No ViaService: a direct call cannot satisfy it. Metadata only — this
      // reveals a key's existence and spec, and confers no use of it.
      resources: ['*'],
    }));

    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'UseSourceKeysDuringCopy',
      actions: [
        'kms:Decrypt',
        'kms:ReEncryptFrom',
        'kms:GenerateDataKeyWithoutPlaintext',
        'kms:CreateGrant',
      ],
      // Member CMK ARNs are unknowable at deploy time. ViaService confines
      // every one of these to EC2, which is the only path that should use
      // them: the snapshot copy.
      resources: ['*'],
      conditions: {
        StringEquals: { 'kms:ViaService': `ec2.${Stack.of(this).region}.amazonaws.com` },
      },
    }));

    // Re-encryption under the forensic CMK is the point of the copy.
    evidenceKey.grantEncryptDecrypt(evidenceRole);
    evidenceKey.grant(evidenceRole, 'kms:CreateGrant', 'kms:DescribeKey');

    // The manifest, and only the manifest. No delete, no retention changes —
    // this role must never be able to remove or unlock evidence.
    evidenceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'WriteManifestsOnly',
      actions: ['s3:PutObject', 's3:PutObjectTagging', 's3:GetObject'],
      resources: [`${evidenceBucket.bucketArn}/cases/*`],
    }));

    // In production, setting retention as each object is written. S3 needs
    // s3:PutObjectRetention for the Object Lock headers on a PUT. Pinned to
    // the configured mode, so this role cannot write a weaker lock; and it
    // cannot shorten or remove one, which in GOVERNANCE mode needs
    // s3:BypassGovernanceRetention and in COMPLIANCE mode is impossible.
    if (retention.productionMode) {
      evidenceRole.addToPolicy(new iam.PolicyStatement({
        sid: 'LockEvidenceAtWriteTime',
        actions: ['s3:PutObjectRetention'],
        resources: [`${evidenceBucket.bucketArn}/cases/*`],
        conditions: { StringEquals: { 's3:object-lock-mode': retention.mode } },
      }));
    }

    caseTable.grant(evidenceRole, 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:GetItem');

    new CfnOutput(this, 'EvidenceRoleArn', { value: evidenceRole.roleArn });
    new CfnOutput(this, 'EvidenceBucketName', { value: evidenceBucket.bucketName });
    new CfnOutput(this, 'EvidenceKeyArn', { value: evidenceKey.keyArn });
    new CfnOutput(this, 'CaseTableName', { value: caseTable.tableName });
    new CfnOutput(this, 'ResponderTopicArn', { value: responderTopic.topicArn });
    new CfnOutput(this, 'RetentionPolicy', {
      value: retentionParam.stringValue,
      description: 'Resolved at synth time from cdk.json context.',
    });

    this.evidenceBucket = evidenceBucket;
    this.evidenceKey = evidenceKey;
    this.caseTable = caseTable;
    this.responderTopic = responderTopic;
  }
}

module.exports = { FipCoreStack, resolveRetentionPolicy, VALID_RETENTION_MODES };
