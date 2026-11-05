/**
 * member-action — every call FIP makes INTO a member account goes through here.
 *
 * Why a Lambda rather than Step Functions' native cross-account Credentials:
 * that field takes a role ARN and nothing else (aws-cdk-lib
 * aws-stepfunctions/lib/task-credentials.d.ts — `interface Credentials { role }`).
 * It cannot supply an sts:ExternalId, and FipResponderRole's trust policy
 * requires one. Rather than weaken the confused-deputy control to suit the
 * integration, the assume-role happens here.
 *
 * This is also where the scale requirements land — every action is
 * idempotent and safe to retry, because Step Functions will retry them.
 */

import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import {
  EC2Client, DescribeInstancesCommand, CreateTagsCommand, CreateSnapshotsCommand,
  DescribeSnapshotsCommand, ModifySnapshotAttributeCommand,
  DescribeSecurityGroupsCommand, CreateSecurityGroupCommand,
  DescribeNetworkInterfacesCommand,
  RevokeSecurityGroupEgressCommand, ModifyNetworkInterfaceAttributeCommand,
  StopInstancesCommand, DeleteTagsCommand,
} from '@aws-sdk/client-ec2';
import {
  AutoScalingClient, DescribeAutoScalingInstancesCommand, DetachInstancesCommand,
  SuspendProcessesCommand,
} from '@aws-sdk/client-auto-scaling';
import {
  KMSClient, CreateGrantCommand, SignCommand, GetPublicKeyCommand,
  ListGrantsCommand, RetireGrantCommand,
} from '@aws-sdk/client-kms';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import {
  DynamoDBClient, PutItemCommand, UpdateItemCommand, GetItemCommand, TransactWriteItemsCommand,
} from '@aws-sdk/client-dynamodb';
import { CopySnapshotCommand } from '@aws-sdk/client-ec2';
import { EBSClient, ListSnapshotBlocksCommand, GetSnapshotBlockCommand } from '@aws-sdk/client-ebs';
import { createHash, verify as cryptoVerify } from 'node:crypto';
import {
  isCaseId, caseLogKey, sha256Hex, checkTicket, checkComment, buildCaseEvent,
  rowUpdateFor, signedDocument, summarizeAction, attachedMembers,
  parseMemberSpec, targetsOfAction, locateMember, memberId, moveTransaction, mergeTransaction,
} from './case-log.mjs';

const REGION = process.env.AWS_REGION;
const EVIDENCE_ACCOUNT = process.env.FIP_EVIDENCE_ACCOUNT_ID;
const EVIDENCE_BUCKET = process.env.FIP_EVIDENCE_BUCKET;
const CASE_TABLE = process.env.FIP_CASE_TABLE;
// Optional. The analysis account may not exist, may be outside the
// organization, and may differ per case, so nothing may depend on it.
const ANALYSIS_ACCOUNT = process.env.FIP_ANALYSIS_ACCOUNT_ID || null;
const EVIDENCE_KEY_ALIAS = process.env.FIP_EVIDENCE_KEY_ALIAS ?? 'alias/fip-evidence';
/**
 * What containment does about an Auto Scaling group that would otherwise
 * replace the instance being isolated. See containInstance for why the
 * default is what it is.
 */
const ASG_POLICIES = new Set(['prevent-replacement', 'allow-replacement']);
const DEFAULT_ASG_POLICY = 'prevent-replacement';

const SIGNING_KEY_ALIAS = process.env.FIP_SIGNING_KEY_ALIAS ?? 'alias/fip-manifest-signing';
const CASE_TAG = 'fip:case-id';
/**
 * The incident case an isolation run was attached to, on what the run
 * creates. A convenience for the console and for cleanup, NOT evidence: the
 * signed case log is the record of membership. fip:case-id above stays the
 * run's own id, because permissions, grants and manifests are keyed on it.
 */
const INCIDENT_TAG = 'fip:case';
const incidentTags = (incident) => (isCaseId(incident) ? [{ Key: INCIDENT_TAG, Value: incident }] : []);
/**
 * Which instance a snapshot came from. Load-bearing once a case can cover more
 * than one instance: the reuse checks below used to match on the case tag
 * alone, so a second target in the SAME account would find the FIRST target's
 * snapshots, report `reused: true`, and never acquire anything — while its
 * manifest recorded the other instance's evidence. Silent, and worst in the
 * exact fleet case FipCase exists for. Permitted by the member role's
 * aws:TagKeys condition, which allows any fip:* key.
 */
const SOURCE_INSTANCE_TAG = 'fip:source-instance';
const SOURCE_SNAPSHOT_TAG = 'fip:source-snapshot';
const ISOLATION_TAG = 'fip:isolation';
const ORIGINAL_SG_TAG = 'fip:original-sgs';

/**
 * Product tags (lib/fip-tags.js, manual §11), on what this Lambda creates:
 * snapshots, evidence copies and the isolation group. Never on the
 * customer's instance, its volumes or its interfaces, which get fip:case-id
 * only, so that no sweep by application=fipv2 can reach a contained host.
 *
 * fip:class says whether a cleanup may remove it. Everything from a test-mode
 * install is `test`, and so are snapshots of an instance tagged fip:class=test
 * (the manual's test instance). Their evidence copies in a production install
 * stay `evidence`: an evidence account is not where a guess should lean
 * towards deletion.
 */
const APPLICATION_TAG = 'application';
const APPLICATION = 'fipv2';
const CLASS_TAG = 'fip:class';
const ENVIRONMENT_TAG = 'fip:environment';
const ENVIRONMENT = process.env.FIP_ENVIRONMENT === 'production' ? 'production' : 'test';

function productTags(fipClass) {
  return [
    { Key: APPLICATION_TAG, Value: APPLICATION },
    { Key: CLASS_TAG, Value: fipClass },
    { Key: ENVIRONMENT_TAG, Value: ENVIRONMENT },
  ];
}

/**
 * Object Lock retention for what is written to the evidence bucket. The bucket
 * has Object Lock enabled and no default rule, so nothing is locked unless the
 * write says so: this is where production mode takes effect. Empty in test
 * mode, which is what lets an install be exercised and torn down.
 */
const RETENTION_MODE = process.env.FIP_RETENTION_MODE ?? 'NONE';
const RETENTION_DAYS = Number(process.env.FIP_RETENTION_DAYS || 0);

function objectLock() {
  if (RETENTION_MODE === 'NONE') return {};
  if (!['GOVERNANCE', 'COMPLIANCE'].includes(RETENTION_MODE)
      || !Number.isInteger(RETENTION_DAYS) || RETENTION_DAYS < 1) {
    // Refuse rather than write unlocked evidence in an install that asked
    // for locking. The stack validates this at synth; this is the backstop.
    throw new Error(`invalid retention: mode ${RETENTION_MODE}, days ${process.env.FIP_RETENTION_DAYS}`);
  }
  return {
    ObjectLockMode: RETENTION_MODE,
    ObjectLockRetainUntilDate: new Date(Date.now() + RETENTION_DAYS * 86400000),
  };
}

function evidenceClass(sourceTags = []) {
  if (ENVIRONMENT === 'test') return 'test';
  return sourceTags.some((t) => t.Key === CLASS_TAG && t.Value === 'test') ? 'test' : 'evidence';
}

const sts = new STSClient({ region: REGION });
const ssm = new SSMClient({ region: REGION });

/**
 * Assume FipResponderRole in a member account, supplying the external ID that
 * account was issued. The ID is looked up per member account rather than held
 * in config — it is not a secret (AWS is explicit about that) but it IS
 * per-account, and the orchestrator is its issuer of record.
 */
async function memberCredentials(accountId, caseId) {
  const { Parameter } = await ssm.send(new GetParameterCommand({
    Name: `/fip/member/${accountId}/external-id`,
  }));
  const { Credentials } = await sts.send(new AssumeRoleCommand({
    RoleArn: `arn:aws:iam::${accountId}:role/FipResponderRole`,
    RoleSessionName: caseId.slice(0, 64),
    ExternalId: Parameter.Value,
    DurationSeconds: 3600,
  }));
  return {
    accessKeyId: Credentials.AccessKeyId,
    secretAccessKey: Credentials.SecretAccessKey,
    sessionToken: Credentials.SessionToken,
  };
}

const ec2For = (c) => new EC2Client({ region: REGION, credentials: c });

/**
 * Assume FipEvidenceRole in the evidence account.
 *
 * A SECOND credential path, and a necessary one: ec2:CopySnapshot must be
 * called in the DESTINATION account, so the step that finally moves evidence
 * out of the compromised member account cannot be performed with
 * FipResponderRole. No external ID here — the evidence account is ours, and
 * the trust is a named account plus, where an organization exists,
 * aws:PrincipalOrgID.
 */
async function evidenceCredentials(caseId) {
  const { Credentials } = await sts.send(new AssumeRoleCommand({
    RoleArn: `arn:aws:iam::${EVIDENCE_ACCOUNT}:role/FipEvidenceRole`,
    RoleSessionName: caseId.slice(0, 64),
    DurationSeconds: 3600,
  }));
  return {
    accessKeyId: Credentials.AccessKeyId,
    secretAccessKey: Credentials.SecretAccessKey,
    sessionToken: Credentials.SessionToken,
  };
}

/**
 * Sign a document in the ORCHESTRATOR account with the Lambda's own identity,
 * and return a self-contained, independently verifiable envelope.
 *
 * ── Why signedPayloadBase64 exists ────────────────────────────────────
 * The signature is over the exact bytes of `JSON.stringify(document, null, 2)`.
 * Those bytes were NOT recoverable from the envelope that used to be written:
 * `document` sat nested inside it, and re-serializing a nested object does not
 * reproduce the original indentation, so a verifier following the documented
 * openssl command had to guess the serialization and would usually fail.
 *
 * A chain-of-custody signature that cannot be checked from the stored artifact
 * is decoration. The exact signed bytes are therefore carried verbatim, and
 * `verify` below is a command that actually works on the stored object alone.
 * The readable copy is kept because a human reading evidence should not have
 * to base64-decode it first.
 */
async function signEnvelope(documentKey, document, filename = `${documentKey}.json`) {
  const body = JSON.stringify(document, null, 2);

  const kmsLocal = new KMSClient({ region: REGION });
  const signed = await kmsLocal.send(new SignCommand({
    KeyId: SIGNING_KEY_ALIAS,
    Message: Buffer.from(body),
    MessageType: 'RAW',
    SigningAlgorithm: 'ECDSA_SHA_384',
  }));
  const pub = await kmsLocal.send(new GetPublicKeyCommand({ KeyId: SIGNING_KEY_ALIAS }));

  return {
    [documentKey]: document,
    signature: {
      algorithm: 'ECDSA_SHA_384',
      keyId: signed.KeyId,
      value: Buffer.from(signed.Signature).toString('base64'),
      publicKeyDer: Buffer.from(pub.PublicKey).toString('base64'),
      // The bytes that were actually signed. Verify against THIS, not against
      // a re-serialization of the object above.
      signedPayloadBase64: Buffer.from(body).toString('base64'),
      signedPayloadSha256: createHash('sha256').update(body).digest('hex'),
      verify: [
        `jq -r .signature.signedPayloadBase64 <this> | base64 -d > ${filename}`,
        'jq -r .signature.value <this> | base64 -d > signature.der',
        'jq -r .signature.publicKeyDer <this> | base64 -d > pubkey.der',
        'openssl pkey -pubin -inform DER -in pubkey.der -out pubkey.pem',
        `openssl dgst -sha384 -verify pubkey.pem -signature signature.der ${filename}`,
      ].join(' && '),
    },
  };
}

/** Tag the instance AND its volumes. Must happen first: every later statement
 *  in FipResponderRole is scoped by this tag, and ec2:CreateSnapshots is
 *  authorized against the source resources, not only the created snapshots. */
async function tagTarget({ accountId, instanceId, caseId, request = {} }, creds) {
  // The incident case, if FipCase attached this run to one. Read from the
  // whole input because it is optional: a hand-run FipAcquisition without it
  // must still work. Returned so later states can read it from $.target,
  // where it always exists.
  const incident = isCaseId(request.incident) ? request.incident : null;
  const ec2 = ec2For(creds);
  const d = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
  const inst = d.Reservations?.[0]?.Instances?.[0];
  if (!inst) throw new Error(`instance ${instanceId} not found in ${accountId}`);
  const volumes = (inst.BlockDeviceMappings ?? []).map((b) => b.Ebs?.VolumeId).filter(Boolean);
  // ENIs are tagged here too: ModifyNetworkInterfaceAttribute is scoped by
  // aws:ResourceTag/fip:case-id, so containment is only possible on interfaces
  // this case has claimed.
  const enis = (inst.NetworkInterfaces ?? []).map((n) => n.NetworkInterfaceId).filter(Boolean);

  await ec2.send(new CreateTagsCommand({
    Resources: [instanceId, ...volumes, ...enis],
    Tags: [{ Key: CASE_TAG, Value: caseId }],
  }));
  return {
    instanceId, volumes, enis, incident,
    instanceType: inst.InstanceType,
    privateIp: inst.PrivateIpAddress,
    // The instance as found, for the manifest.
    asFound: { state: inst.State?.Name, launchTime: inst.LaunchTime, vpcId: inst.VpcId },
  };
}

/** Crash-consistent multi-volume snapshot. Born tagged, which is what makes
 *  every downstream permission scopeable. Idempotent by case tag: if snapshots
 *  for this case already exist we return them rather than making more. */
async function createSnapshots({ instanceId, caseId, incident = null }, creds) {
  const ec2 = ec2For(creds);

  // Scoped by case AND INSTANCE. The case tag alone is not a unique key once
  // FipCase fans out: two instances in one account share a case id, so the
  // second one would match the first one's snapshots here.
  const existing = await ec2.send(new DescribeSnapshotsCommand({
    OwnerIds: ['self'],
    Filters: [
      { Name: `tag:${CASE_TAG}`, Values: [caseId] },
      { Name: `tag:${SOURCE_INSTANCE_TAG}`, Values: [instanceId] },
    ],
  }));

  // How many snapshots a complete acquisition of THIS instance should produce.
  // Needed because "some snapshots exist" is not the same as "this instance
  // has already been acquired": a previous run that died midway leaves a
  // partial set, and silently treating it as reuse would under-acquire and
  // record a manifest that looks complete.
  const described = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
  const instance = described.Reservations?.[0]?.Instances?.[0];
  if (!instance) throw new Error(`instance ${instanceId} not found`);
  const expectedVolumes = (instance.BlockDeviceMappings ?? [])
    .filter((b) => b.Ebs?.VolumeId).length;

  if (existing.Snapshots?.length) {
    if (existing.Snapshots.length !== expectedVolumes) {
      throw new Error(
        `case ${caseId} already has ${existing.Snapshots.length} snapshot(s) for `
        + `${instanceId} but the instance has ${expectedVolumes} volume(s). A previous `
        + `run left an incomplete set. Resolve it deliberately — reusing a partial `
        + `set would produce a manifest that looks complete and is not.`,
      );
    }
    return { snapshots: existing.Snapshots.map((s) => s.SnapshotId), reused: true };
  }

  const r = await ec2.send(new CreateSnapshotsCommand({
    InstanceSpecification: { InstanceId: instanceId, ExcludeBootVolume: false },
    Description: `FIP ${caseId} ${instanceId}`,
    TagSpecifications: [{
      ResourceType: 'snapshot',
      Tags: [
        { Key: CASE_TAG, Value: caseId },
        { Key: SOURCE_INSTANCE_TAG, Value: instanceId },
        ...incidentTags(incident),
        ...productTags(evidenceClass(instance.Tags)),
      ],
    }],
  }));
  return { snapshots: r.Snapshots.map((s) => s.SnapshotId), reused: false };
}

async function snapshotStatus({ snapshots }, creds) {
  const ec2 = ec2For(creds);
  const r = await ec2.send(new DescribeSnapshotsCommand({ SnapshotIds: snapshots }));
  const states = r.Snapshots.map((s) => s.State);
  return {
    allComplete: states.every((s) => s === 'completed'),
    anyError: states.some((s) => s === 'error'),
    states,
  };
}

/** SHA-256 over the snapshot's block stream via the EBS direct APIs — no
 *  attach, no mount, no boot. Only valid once the snapshot is
 *  'completed'; the direct APIs report SNAPSHOT_NOT_FOUND before then, which
 *  is why the state machine waits first.
 *
 *  THIS IS AN ATTESTATION OF WHAT WAS READ IN THE MEMBER ACCOUNT. It is NOT
 *  the evidence hash, and it must never be compared for equality against the
 *  hash of the evidence-account copy. Measured 2026-09-19: a source snapshot
 *  and its cross-account re-encrypted copy differ in exactly one block out of
 *  3,389, reproducibly, with AWS's own per-block checksums confirming it. An
 *  equality check across that boundary yields a false integrity failure. The
 *  hash of record is taken over the retained copy (manual §7). */
async function hashSnapshot({ snapshotId }, creds) {
  const ebs = new EBSClient({ region: REGION, credentials: creds });
  const hash = createHash('sha256');
  let token, blocks = 0, bytes = 0, blockSize = 0;
  do {
    const page = await ebs.send(new ListSnapshotBlocksCommand({
      SnapshotId: snapshotId, NextToken: token,
    }));
    blockSize = page.BlockSize ?? blockSize;
    for (const b of page.Blocks ?? []) {
      const d = await ebs.send(new GetSnapshotBlockCommand({
        SnapshotId: snapshotId, BlockIndex: b.BlockIndex, BlockToken: b.BlockToken,
      }));
      const chunk = Buffer.from(await d.BlockData.transformToByteArray());
      // Index is hashed with the data so a reordering cannot collide.
      hash.update(Buffer.from(`${b.BlockIndex}:`)); hash.update(chunk);
      blocks += 1; bytes += chunk.length;
    }
    token = page.NextToken;
  } while (token);
  return { snapshotId, sha256: hash.digest('hex'), blocks, bytes, blockSize };
}

/** Grant the evidence account use of the member's CMK, then share. Order
 *  matters: sharing an encrypted snapshot fails without the key access. */
async function shareToEvidence({ snapshots, caseId }, creds) {
  const ec2 = ec2For(creds);
  const kms = new KMSClient({ region: REGION, credentials: creds });
  const detail = await ec2.send(new DescribeSnapshotsCommand({ SnapshotIds: snapshots }));
  const keys = [...new Set(detail.Snapshots.map((s) => s.KmsKeyId).filter(Boolean))];

  for (const keyId of keys) {
    await kms.send(new CreateGrantCommand({
      KeyId: keyId,
      GranteePrincipal: `arn:aws:iam::${EVIDENCE_ACCOUNT}:root`,
      Operations: ['Decrypt', 'DescribeKey', 'CreateGrant',
                   'GenerateDataKeyWithoutPlaintext', 'ReEncryptFrom'],
      Name: `fip-${caseId}`.slice(0, 256),
    }));
  }
  for (const id of snapshots) {
    await ec2.send(new ModifySnapshotAttributeCommand({
      SnapshotId: id, Attribute: 'createVolumePermission',
      OperationType: 'add', UserIds: [EVIDENCE_ACCOUNT],
    }));
  }
  return { shared: snapshots, keysGranted: keys, evidenceAccount: EVIDENCE_ACCOUNT };
}

/**
 * Find or create this VPC's isolation security group: no inbound rules, no
 * outbound rules. A brand-new group already has no inbound rules and exactly
 * one outbound allow-all, so stripping that is what turns it from "a group"
 * into "isolation".
 *
 * One group per VPC, reused across cases. Creating it on demand rather than
 * pre-creating in the member stack is deliberate — see the note on
 * DELIBERATELY_EXCLUDED in fip-member-stack.js.
 */
async function isolationGroupFor(ec2, vpcId, caseId) {
  const found = await ec2.send(new DescribeSecurityGroupsCommand({
    Filters: [
      { Name: 'vpc-id', Values: [vpcId] },
      { Name: `tag-key`, Values: [ISOLATION_TAG] },
    ],
  }));
  if (found.SecurityGroups?.length) {
    const group = found.SecurityGroups[0];
    // A group made before FIP tagged its own resources has no product tags,
    // so an uninstall searching by application=fipv2 would miss it. Add them.
    if (!(group.Tags ?? []).some((t) => t.Key === APPLICATION_TAG)) {
      await ec2.send(new CreateTagsCommand({
        Resources: [group.GroupId], Tags: productTags('infrastructure'),
      }));
    }
    return { groupId: group.GroupId, created: false };
  }

  const made = await ec2.send(new CreateSecurityGroupCommand({
    GroupName: `fip-isolation-${vpcId}`,
    Description: 'FIP forensic isolation - no ingress, no egress',
    VpcId: vpcId,
    TagSpecifications: [{
      ResourceType: 'security-group',
      Tags: [
        { Key: ISOLATION_TAG, Value: 'true' }, { Key: CASE_TAG, Value: caseId },
        // Created here rather than by a stack, so a stack deletion leaves it.
        // The tag is how an uninstall finds it.
        ...productTags('infrastructure'),
      ],
    }],
  }));

  // Remove the default allow-all egress. Without this the group isolates
  // nothing outbound, which is the half that matters for exfiltration.
  const detail = await ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: [made.GroupId] }));
  const egress = detail.SecurityGroups?.[0]?.IpPermissionsEgress ?? [];
  if (egress.length) {
    await ec2.send(new RevokeSecurityGroupEgressCommand({
      GroupId: made.GroupId, IpPermissions: egress,
    }));
  }
  return { groupId: made.GroupId, created: true };
}

/**
 * Contain the instance: cut its network to nothing, and stop its Auto Scaling
 * group from managing it.
 *
 * Records the ORIGINAL security groups per interface before replacing them.
 * That record is the only way back, and it belongs in the manifest — an
 * isolation you cannot describe or undo is not a containment action, it is
 * an outage.
 */
async function containInstance({ instanceId, caseId, request = {} }, creds) {
  const asgPolicy = request.asgPolicy;
  const ec2 = ec2For(creds);
  const asg = new AutoScalingClient({ region: REGION, credentials: creds });

  const d = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
  const inst = d.Reservations?.[0]?.Instances?.[0];
  if (!inst) throw new Error(`instance ${instanceId} not found`);

  const { groupId, created } = await isolationGroupFor(ec2, inst.VpcId, caseId);

  // Record the ORIGINAL groups as a tag on each interface the first time we
  // contain it, and read that tag back on any subsequent run.
  //
  // Being idempotent in the ACTION is not enough. A re-run against an
  // already-contained instance would otherwise observe the isolation group as
  // the "original" and record that — destroying the only record of how to
  // restore the instance. Observed doing exactly that on 2026-09-22, when a
  // failed run had already contained the host. The restore path is evidence,
  // so it has to survive a retry.
  // DescribeInstances does NOT return tags on network interfaces — the
  // InstanceNetworkInterface shape has no TagSet field at all, so reading
  // n.TagSet silently yields undefined and every re-run looks like a first
  // run. Verified 2026-09-22 against a live ENI whose tag was present and
  // correct. DescribeNetworkInterfaces is the call that returns them.
  const eniIds = (inst.NetworkInterfaces ?? []).map((n) => n.NetworkInterfaceId);
  const eniDetail = eniIds.length
    ? await ec2.send(new DescribeNetworkInterfacesCommand({ NetworkInterfaceIds: eniIds }))
    : { NetworkInterfaces: [] };
  const tagsByEni = new Map(
    (eniDetail.NetworkInterfaces ?? []).map((n) => [n.NetworkInterfaceId, n.TagSet ?? []]),
  );

  const before = [];
  for (const n of inst.NetworkInterfaces ?? []) {
    const eni = n.NetworkInterfaceId;
    const current = (n.Groups ?? []).map((g) => g.GroupId);
    const recorded = (tagsByEni.get(eni) ?? []).find((t) => t.Key === ORIGINAL_SG_TAG)?.Value;

    if (recorded !== undefined) {
      // Already contained by an earlier run; the tag is the truth.
      before.push({ eni, groups: recorded ? recorded.split(',') : [], recoveredFromTag: true });
      continue;
    }

    if (current.length === 1 && current[0] === groupId) {
      // Isolated, but with no record of what it was. Say so rather than
      // pretending the isolation group was the original.
      before.push({ eni, groups: null, alreadyIsolatedOriginalUnknown: true });
      continue;
    }

    await ec2.send(new CreateTagsCommand({
      Resources: [eni],
      Tags: [{ Key: ORIGINAL_SG_TAG, Value: current.join(',') }],
    }));
    before.push({ eni, groups: current, recoveredFromTag: false });
  }

  // Idempotent: applying the isolation group to an already-isolated interface
  // is a no-op, which matters because Step Functions will retry this.
  for (const iface of before) {
    await ec2.send(new ModifyNetworkInterfaceAttributeCommand({
      NetworkInterfaceId: iface.eni, Groups: [groupId],
    })).catch((e) => { if (!/already/i.test(String(e))) throw e; });
  }

  // ── Take the instance out of its ASG, WITHOUT handing the attacker a
  //    fresh one ───────────────────────────────────────────────────────
  //
  // This used to detach with ShouldDecrementDesiredCapacity: false, which
  // keeps the group at its desired capacity by LAUNCHING A REPLACEMENT. The
  // replacement comes from the same launch template, the same AMI, the same
  // user data and the same instance profile as the host being isolated — so
  // if the compromise vector is any of those, or an exposed application on
  // the image, the replacement is just as vulnerable. Detection fires again,
  // FIP isolates again, the group replaces again: a CONTAINMENT LOOP that
  // also bills a fresh set of snapshots every time round.
  //
  // So the default is to prevent the replacement and accept a degraded group.
  // That is a real cost and it is the lesser one: a degraded ASG is a visible
  // problem a human fixes by patching the launch template, whereas a loop
  // looks like the tool working.
  //
  // 'allow-replacement' restores the old behavior for callers who genuinely
  // want capacity maintained — FIP does not forbid what the customer
  // chooses — but it is opt-in, because the loop is not obvious.
  const policy = ASG_POLICIES.has(asgPolicy) ? asgPolicy : DEFAULT_ASG_POLICY;

  let asgResult = { inAsg: false, policy };
  const membership = await asg.send(new DescribeAutoScalingInstancesCommand({
    InstanceIds: [instanceId],
  }));
  const m = membership.AutoScalingInstances?.[0];
  if (m?.AutoScalingGroupName) {
    const groupName = m.AutoScalingGroupName;
    const detach = (decrement) => asg.send(new DetachInstancesCommand({
      InstanceIds: [instanceId],
      AutoScalingGroupName: groupName,
      ShouldDecrementDesiredCapacity: decrement,
    }));

    if (policy === 'allow-replacement') {
      await detach(false);
      asgResult = {
        inAsg: true, autoScalingGroupName: groupName, detached: true, policy,
        mechanism: 'capacity-maintained',
        replacementExpected: true,
        warning:
          'Desired capacity was maintained, so this group has launched a replacement '
          + 'from the same launch template. If the compromise vector is in the image, '
          + 'user data or instance profile, expect the replacement to be compromised too.',
      };
    } else {
      try {
        // Instance-scoped and leaves nothing group-wide behind: the preferred
        // mechanism when the group has the headroom for it.
        await detach(true);
        asgResult = {
          inAsg: true, autoScalingGroupName: groupName, detached: true, policy,
          mechanism: 'desired-capacity-decremented',
          replacementExpected: false,
          restoreHint:
            `Group ${groupName} is running one instance short. Raise its desired `
            + 'capacity once the launch template is known good.',
        };
      } catch (err) {
        // A group already at its minimum cannot give up capacity: AWS rejects
        // the decrement rather than breaching MinSize. Narrow on purpose —
        // any other ValidationError is a real error and must not be swallowed
        // into a silently different containment posture.
        // The separators matter. AWS says "has min-size=2, max-size=2" with
        // HYPHENS, and the shipped pattern only allowed whitespace — so this
        // never matched, the error was rethrown, and the MinSize fallback this
        // branch exists for NEVER FIRED. Containment simply failed instead.
        // Measured against the live message on 2026-10-21; the regex had been
        // written from an assumption about the wording.
        const isMinSizeFloor = err.name === 'ValidationError'
          && /min(imum)?[-_\s]*size/i.test(String(err.message ?? ''));
        if (!isMinSizeFloor) throw err;

        // Fall back to stopping the group from launching AT ALL. More
        // invasive than a decrement — it is group-wide and must be undone —
        // but it is the safe direction, and failing open into a replacement
        // would reintroduce the loop invisibly.
        await asg.send(new SuspendProcessesCommand({
          AutoScalingGroupName: groupName,
          // Launch only. The instance is leaving the group, so health checks
          // and ReplaceUnhealthy no longer apply to it; Launch is the process
          // that would honor desired capacity.
          ScalingProcesses: ['Launch'],
        }));
        await detach(false);
        asgResult = {
          inAsg: true, autoScalingGroupName: groupName, detached: true, policy,
          mechanism: 'launch-suspended',
          replacementExpected: false,
          groupWideChange: `Launch process SUSPENDED on ${groupName}`,
          reason:
            `${groupName} is at its minimum size, so capacity could not be decremented. `
            + 'Suspending Launch was the only way to prevent a replacement.',
          restoreHint:
            `This group cannot scale out until someone runs: aws autoscaling `
            + `resume-processes --auto-scaling-group-name ${groupName} --scaling-processes Launch. `
            + 'It will then launch the deferred replacement immediately, so patch the '
            + 'launch template FIRST.',
        };
      }
    }
  }

  return {
    isolationGroupId: groupId, isolationGroupCreated: created,
    vpcId: inst.VpcId,
    originalSecurityGroups: before,
    asg: asgResult,
  };
}

/** Stop the instance. Off unless the caller asks, because it is service-affecting and not reversible in kind —
 *  instance-store data does not survive it. */
async function stopInstance({ instanceId }, creds) {
  const ec2 = ec2For(creds);
  const r = await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
  return {
    instanceId,
    previousState: r.StoppingInstances?.[0]?.PreviousState?.Name,
    currentState: r.StoppingInstances?.[0]?.CurrentState?.Name,
  };
}

/**
 * Copy the shared snapshots into the evidence account, re-encrypted under the
 * forensic CMK.
 *
 * Sharing snapshots and granting key access alone would make the evidence visible
 * from the forensic account but leave it owned by the member account — the one
 * under investigation. That account could delete the snapshots or revoke the
 * grant. After this step the evidence exists under a key and in an account the
 * compromised environment cannot reach.
 *
 * Idempotent by case tag: a retry returns the copies already made.
 */
async function copyToEvidence({ snapshots, caseId, accountId, incident = null }, creds) {
  const ec2 = ec2For(creds);

  // Idempotent PER SOURCE SNAPSHOT, not per case. The previous check matched
  // the case tag alone, so once a case covered two instances the second
  // target found the first target's copies and returned them as its own —
  // nothing was copied, no error was raised, and the second manifest pointed
  // at the first instance's evidence. Mapping source -> copy also makes a
  // partially completed run resume correctly instead of all-or-nothing.
  const existing = await ec2.send(new DescribeSnapshotsCommand({
    OwnerIds: ['self'],
    Filters: [
      { Name: `tag:${CASE_TAG}`, Values: [caseId] },
      { Name: `tag:${SOURCE_SNAPSHOT_TAG}`, Values: snapshots },
    ],
  }));

  const copyBySource = new Map();
  for (const snap of existing.Snapshots ?? []) {
    // A copy that FAILED is not a copy. Skipping error state is what makes a
    // retry actually retry: on 2026-10-21 three copies failed with "Given key
    // ID is not accessible", and without this the next run would have found
    // them, reported reused: true, and recorded three error snapshots as the
    // evidence of record.
    if (snap.State === 'error') continue;
    const source = (snap.Tags ?? []).find((t) => t.Key === SOURCE_SNAPSHOT_TAG)?.Value;
    if (source) copyBySource.set(source, snap.SnapshotId);
  }

  const copies = [];
  let reusedAny = false;
  for (const source of snapshots) {
    const already = copyBySource.get(source);
    if (already) {
      copies.push(already);
      reusedAny = true;
      continue;
    }
    const r = await ec2.send(new CopySnapshotCommand({
      SourceRegion: REGION,
      SourceSnapshotId: source,
      Description: `FIP ${caseId} evidence copy of ${source} from ${accountId}`,
      Encrypted: true,
      KmsKeyId: 'alias/fip-evidence',
      TagSpecifications: [{
        ResourceType: 'snapshot',
        Tags: [
          { Key: CASE_TAG, Value: caseId },
          { Key: SOURCE_SNAPSHOT_TAG, Value: source },
          { Key: 'fip:source-account', Value: accountId },
          ...incidentTags(incident),
          ...productTags(evidenceClass()),
        ],
      }],
    }));
    copies.push(r.SnapshotId);
  }
  return { copies, reused: reusedAny };
}

async function copyStatus({ copies }, creds) {
  const ec2 = ec2For(creds);
  const r = await ec2.send(new DescribeSnapshotsCommand({ SnapshotIds: copies }));
  const states = r.Snapshots.map((s) => s.State);
  return {
    allComplete: states.every((s) => s === 'completed'),
    anyError: states.some((s) => s === 'error'),
    states,
  };
}

/**
 * Build the case manifest, sign it, and write it to the Object Lock bucket
 * and the case table. This is the artifact that makes the copies evidence
 * rather than merely present.
 *
 * The signature is made with an ECC_NIST_P384 key in the ORCHESTRATOR account
 * — a same-account kms:Sign — so it is verifiable outside AWS by anyone
 * holding the public key, including a third-party examiner with no access to
 * our CloudTrail.
 *
 * Note which hash is which. evidence[].sha256 is taken over the RETAINED COPY
 * and is the hash of record. sourceAttestation[].sha256 is what was read in
 * the member account at acquisition time. They are NOT expected to be equal —
 * measured 2026-09-19, a source and its cross-account copy differ in at least
 * one block — and nothing should ever compare them.
 */
async function writeManifest(event, creds) {
  const { caseId, accountId, instanceId, target, containment, acquisition,
          hashes = [], evidenceHashes = [], copies = [], executionArn } = event;

  const manifest = {
    schema: 'fip.manifest/1',
    caseId,
    createdAt: new Date().toISOString(),
    executionArn: executionArn ?? null,
    source: {
      accountId,
      instanceId,
      instanceType: target?.instanceType ?? null,
      privateIp: target?.privateIp ?? null,
      asFound: target?.asFound ?? null,
      volumes: target?.volumes ?? [],
      networkInterfaces: target?.enis ?? [],
    },
    containment: containment
      ? {
          isolationGroupId: containment.isolationGroupId,
          isolationGroupCreated: containment.isolationGroupCreated,
          vpcId: containment.vpcId,
          originalSecurityGroups: containment.originalSecurityGroups,
          autoScaling: containment.asg,
        }
      : null,
    acquisition: {
      sourceSnapshots: acquisition?.snapshots ?? [],
      reused: acquisition?.reused ?? false,
    },
    // The hash of record: taken over what is retained.
    evidence: evidenceHashes.map((h) => ({
      snapshotId: h.snapshotId, sha256: h.sha256, blocks: h.blocks, bytes: h.bytes,
      account: EVIDENCE_ACCOUNT,
    })),
    // Separate attestation of what was read in the member account. Never to be
    // compared for equality with the above.
    sourceAttestation: hashes.map((h) => ({
      snapshotId: h.snapshotId, sha256: h.sha256, blocks: h.blocks, bytes: h.bytes,
      note: 'read in the member account at acquisition time; not expected to equal the evidence hash',
    })),
    copies,
  };

  const envelope = await signEnvelope('manifest', manifest);

  const s3 = new S3Client({ region: REGION, credentials: creds });
  // Keyed by INSTANCE, not just by case. A case may cover several instances
  // (FipCase fans out over targets), and `cases/<caseId>/manifest.json` would
  // have had each target silently overwrite the previous one's manifest —
  // leaving one survivor and no error. Every target gets its own artifact.
  const key = `cases/${caseId}/${instanceId}/manifest.json`;
  await s3.send(new PutObjectCommand({
    Bucket: EVIDENCE_BUCKET,
    Key: key,
    Body: JSON.stringify(envelope, null, 2),
    ContentType: 'application/json',
    ...objectLock(),
  }));

  // One row per CASE, with a map entry per target — not one row per instance.
  // The table's partition key is caseId alone, so PutItem here had the same
  // collision as the S3 key: the last target to finish won.
  //
  // UpdateItem on a nested path is what makes the fan-out safe. Targets run
  // concurrently, and DynamoDB serializes writes to distinct document paths
  // within an item, so `targets.<instanceId>` cannot lose a sibling's write.
  // Two writers SETting the same parent `targets` map would.
  //
  // This relies on the case row and its empty `targets` map already existing:
  // FipCase's first state is caseOpen. DynamoDB rejects an update whose paths
  // overlap, so the parent cannot be created in this same call.
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
  await ddb.send(new UpdateItemCommand({
    TableName: CASE_TABLE,
    Key: { caseId: { S: caseId } },
    UpdateExpression: 'SET #targets.#instance = :record',
    ExpressionAttributeNames: { '#targets': 'targets', '#instance': instanceId },
    ExpressionAttributeValues: {
      ':record': {
        M: {
          state: { S: 'ACQUIRED' },
          acquiredAt: { S: manifest.createdAt },
          sourceAccount: { S: accountId },
          instanceId: { S: instanceId },
          manifestKey: { S: key },
          evidenceSnapshots: { SS: copies.length ? copies : ['none'] },
        },
      },
    },
  }));

  return { manifestKey: key, bucket: EVIDENCE_BUCKET, signed: true, caseState: 'ACQUIRED' };
}

/**
 * Open a case row before any target runs. Idempotent on purpose: a retried
 * execution, or a second wave of targets added to a case already in flight,
 * must not reset the row or clobber the targets recorded so far.
 *
 * The empty `targets` map matters — see writeManifest. Without it each target
 * would have to create the parent, and concurrent creators would overwrite
 * each other.
 */
async function caseOpen(event, creds) {
  const { caseId, targets = [], openedBy = null, request = {} } = event;
  // Optional-field defaulting lives here because Step Functions has none: a
  // state that references `$.stopInstance` fails outright when the caller
  // omitted it. The parent passes the whole input as `request` instead, and
  // the normalized value is read back from this task's result.
  const stopInstance = request.stopInstance === true;
  const asgPolicy = ASG_POLICIES.has(request.asgPolicy)
    ? request.asgPolicy
    : DEFAULT_ASG_POLICY;
  // An isolation run never writes into an incident case's row: the two
  // share a table, and a run's targets map would corrupt the case.
  if (isCaseId(caseId)) {
    throw new Error(`${caseId} is an incident case, not an isolation id; use --case to attach a run to it`);
  }
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });

  // The incident case to attach to, only if the caller named one: isolate
  // never opens or picks a case on its own. Checked BEFORE anything is
  // written, so a refused attach leaves no trace and touches no host: this
  // is FipCase's first state.
  const incident = request.incident === undefined || request.incident === null || request.incident === ''
    ? null : String(request.incident);
  let members = [];
  if (incident) {
    if (!isCaseId(incident)) throw new Error(`'${incident}' is not an incident case id (case-<UTC>-<hex>)`);
    members = attachedMembers(caseId, targets);
    const caseRow = await readCaseRow(ddb, incident);
    if (!caseRow || caseRow.kind?.S !== 'case') throw new Error(`no incident case ${incident}`);
    if (caseRow.state?.S !== 'OPEN') {
      throw new Error(`case ${incident} is ${caseRow.state?.S}; isolations attach only to open cases`);
    }
  }
  const actor = typeof request.requestedBy === 'string' && request.requestedBy ? request.requestedBy : openedBy;

  const attach = async () => {
    if (!incident) return null;
    // Idempotent: a retried OpenCase, or a re-run naming targets already
    // attached, records only what the case does not hold yet. A member a
    // later `fip case move` placed in another case stays there.
    const have = (await readCaseRow(ddb, incident))?.members?.M ?? {};
    const placed = (await readCaseRow(ddb, caseId))?.cases?.M ?? {};
    const missing = members.filter((m) => !have[m.member]
      && (!placed[m.instanceId] || placed[m.instanceId].S === incident));
    if (!missing.length) return null;
    // Where each member is, on the run's row, before the record: a move
    // reads it, and conditions on it.
    await ensureCasesMap(ddb, caseId);
    const names = { '#cases': 'cases' };
    const sets = [];
    const conds = [];
    missing.forEach((m, i) => {
      names[`#i${i}`] = m.instanceId;
      sets.push(`#cases.#i${i} = :incident`);
      conds.push(`(attribute_not_exists(#cases.#i${i}) OR #cases.#i${i} = :incident)`);
    });
    await ddb.send(new UpdateItemCommand({
      TableName: CASE_TABLE, Key: { caseId: { S: caseId } },
      UpdateExpression: `SET ${sets.join(', ')}`,
      ConditionExpression: conds.join(' AND '),
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: { ':incident': { S: incident } },
    }));
    return appendCaseEvent({
      caseId: incident, event: 'MEMBER_ATTACHED', actor,
      data: { actionId: caseId, executionArn: openedBy ?? null, members: missing },
    }, creds);
  };

  const now = new Date().toISOString();
  try {
    await ddb.send(new PutItemCommand({
      TableName: CASE_TABLE,
      Item: {
        caseId: { S: caseId },
        kind: { S: 'action' },
        state: { S: 'IN_PROGRESS' },
        openedAt: { S: now },
        openedBy: { S: openedBy ?? 'unknown' },
        targetCount: { N: String(targets.length) },
        asgPolicy: { S: asgPolicy },
        requestedTargets: {
          L: targets.map((t) => ({
            M: {
              accountId: { S: String(t.accountId) },
              instanceId: { S: String(t.instanceId) },
            },
          })),
        },
        targets: { M: {} },
        cases: { M: {} },
        ...(incident ? { incident: { S: incident } } : {}),
      },
      ConditionExpression: 'attribute_not_exists(caseId)',
    }));
    const attached = await attach();
    return {
      caseId, caseState: 'IN_PROGRESS', opened: true, openedAt: now, stopInstance, asgPolicy,
      incident, attached,
    };
  } catch (err) {
    // Already open. That is a valid state to proceed from, not a failure:
    // Step Functions retries this task, and an operator may legitimately
    // re-run a case id after a partial failure.
    if (err.name === 'ConditionalCheckFailedException') {
      // A second run under the same id: back to IN_PROGRESS until it
      // finishes, with its targets added to what was requested. Never an
      // incident case's row (kind 'case'); older rows have no kind at all.
      //
      // A run attached to an incident case stays in that case: re-running it
      // under a DIFFERENT case is refused. Moving it is `fip case move`.
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: CASE_TABLE,
          Key: { caseId: { S: caseId } },
          UpdateExpression: 'SET #state = :running, '
            + 'requestedTargets = list_append(if_not_exists(requestedTargets, :none), :more)'
            + (incident ? ', incident = :incident' : ''),
          ConditionExpression: '(attribute_not_exists(kind) OR kind = :action)'
            + (incident ? ' AND (attribute_not_exists(incident) OR incident = :incident)' : ''),
          ExpressionAttributeNames: { '#state': 'state' },
          ExpressionAttributeValues: {
            ':running': { S: 'IN_PROGRESS' },
            ':none': { L: [] },
            ':action': { S: 'action' },
            ':more': {
              L: targets.map((t) => ({
                M: {
                  accountId: { S: String(t.accountId) },
                  instanceId: { S: String(t.instanceId) },
                },
              })),
            },
            ...(incident ? { ':incident': { S: incident } } : {}),
          },
        }));
      } catch (inner) {
        if (inner.name !== 'ConditionalCheckFailedException') throw inner;
        const existing = await readCaseRow(ddb, caseId);
        if (existing?.incident?.S && existing.incident.S !== incident) {
          throw new Error(`isolation run ${caseId} belongs to case ${existing.incident.S}, not ${incident}; `
            + 'start a new run for this case instead');
        }
        throw new Error(`${caseId} is not an isolation run`);
      }
      const attached = await attach();
      return {
        caseId, caseState: 'IN_PROGRESS', opened: false, stopInstance, asgPolicy,
        incident, attached,
        reason: 'case already open',
      };
    }
    throw err;
  }
}

/**
 * Grant or withdraw an analysis account's access to a case's evidence.
 *
 * ── Why this is a separate, explicit action ───────────────────────────
 * Releasing evidence to an analysis account is a CHAIN-OF-CUSTODY EVENT, and
 * the analysis account may belong to a third party outside the organization
 *. So it is never part of acquisition and never automatic: evidence must
 * not flow to an outside party as a side effect of a case being opened. A
 * human decides, per case, and the decision is recorded and signed.
 *
 * Reversible on purpose. An engagement ends, and when it does the examiner's
 * access has to actually stop — which means both halves must be undone: the
 * snapshot share AND the KMS grant. Removing only the share leaves a grant
 * that is invisible in the snapshot's permissions and looks like nothing.
 */
async function releaseToAnalysis(event, creds) {
  const { caseId, copies = [], analysisAccountId, revoke = false, actor = null } = event;

  const target = analysisAccountId || ANALYSIS_ACCOUNT;
  if (!target) {
    throw new Error(
      'no analysis account. Pass analysisAccountId, or set FIP_ANALYSIS_ACCOUNT_ID '
      + 'on the orchestrator. FIP does not assume one exists.',
    );
  }
  if (!/^[0-9]{12}$/.test(String(target))) {
    throw new Error(`analysis account '${target}' is not a 12-digit account id`);
  }
  if (!copies.length) {
    throw new Error(`case ${caseId} has no evidence copies to ${revoke ? 'revoke' : 'release'}`);
  }

  const ec2 = ec2For(creds);
  const kms = new KMSClient({ region: REGION, credentials: creds });

  // 1. The snapshot share. createVolumePermission is what lets the analysis
  //    account turn a snapshot into a volume; it confers no delete.
  for (const snapshotId of copies) {
    await ec2.send(new ModifySnapshotAttributeCommand({
      SnapshotId: snapshotId,
      Attribute: 'createVolumePermission',
      OperationType: revoke ? 'remove' : 'add',
      UserIds: [String(target)],
    }));
  }

  // 2. The key. A shared encrypted snapshot is useless without grant access to
  //    the CMK it is encrypted under, and conversely a grant left behind after
  //    an unshare is access nobody can see in the snapshot's permissions.
  let grants = [];
  if (revoke) {
    const listed = await kms.send(new ListGrantsCommand({
      KeyId: EVIDENCE_KEY_ALIAS,
      GranteePrincipal: `arn:aws:iam::${target}:root`,
    }));
    for (const grant of listed.Grants ?? []) {
      // Only grants this release created. Retiring a grant some other case or
      // engagement depends on would silently break it.
      if (grant.Name !== `fip-${caseId}`) continue;
      await kms.send(new RetireGrantCommand({
        KeyId: EVIDENCE_KEY_ALIAS, GrantId: grant.GrantId,
      }));
      grants.push(grant.GrantId);
    }
  } else {
    const grant = await kms.send(new CreateGrantCommand({
      KeyId: EVIDENCE_KEY_ALIAS,
      GranteePrincipal: `arn:aws:iam::${target}:root`,
      // Named so revoke can find exactly the grants this case created.
      Name: `fip-${caseId}`,
      // Read paths only. No Encrypt, no ReEncrypt, no CreateGrant: an examiner
      // must be able to READ evidence and must not be able to produce new
      // ciphertext under the forensic key or widen their own access.
      Operations: ['Decrypt', 'DescribeKey'],
    }));
    grants.push(grant.GrantId);
  }

  // 3. The record. Signed with the same key as the manifest, so a custody
  //    event is exactly as verifiable as the acquisition it refers to.
  const custody = {
    schema: 'fip.custody/1',
    caseId,
    event: revoke ? 'REVOKED_FROM_ANALYSIS' : 'RELEASED_TO_ANALYSIS',
    at: new Date().toISOString(),
    analysisAccountId: String(target),
    evidenceAccountId: EVIDENCE_ACCOUNT,
    snapshots: copies,
    kmsGrantIds: grants,
    actor,
    note: revoke
      ? 'Snapshot share removed and the case KMS grant retired. Existing volumes already created from these snapshots are NOT destroyed by this.'
      : 'Analysis account may create volumes from these snapshots and decrypt them. It cannot delete them, cannot re-encrypt under the forensic key, and cannot widen its own access.',
  };

  const envelope = await signEnvelope('custody', custody, 'custody.json');
  const key = `cases/${caseId}/custody/${custody.at.replace(/[:.]/g, '-')}-${revoke ? 'revoke' : 'release'}.json`;

  const s3 = new S3Client({ region: REGION, credentials: creds });
  await s3.send(new PutObjectCommand({
    Bucket: EVIDENCE_BUCKET,
    Key: key,
    Body: JSON.stringify(envelope, null, 2),
    ContentType: 'application/json',
    ...objectLock(),
  }));

  // Appended, never overwritten. The history of who held this evidence is
  // itself part of the record, so a revoke must not erase the release.
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
  await ddb.send(new UpdateItemCommand({
    TableName: CASE_TABLE,
    Key: { caseId: { S: caseId } },
    UpdateExpression: 'SET custody = list_append(if_not_exists(custody, :empty), :entry)',
    ExpressionAttributeValues: {
      ':empty': { L: [] },
      ':entry': {
        L: [{
          M: {
            event: { S: custody.event },
            at: { S: custody.at },
            analysisAccountId: { S: String(target) },
            recordKey: { S: key },
            snapshotCount: { N: String(copies.length) },
          },
        }],
      },
    },
  }));

  return {
    caseId,
    event: custody.event,
    analysisAccountId: String(target),
    snapshots: copies,
    kmsGrantIds: grants,
    custodyRecordKey: key,
  };
}

/**
 * Roll the per-target outcomes up into one case-level verdict.
 *
 * Partial success is RECORDED rather than aborting the case,
 * so a case with some targets acquired and some failed resolves to PARTIAL and
 * keeps the evidence it did collect. Only a case where nothing succeeded is
 * FAILED.
 */
async function caseSummary(event, creds) {
  const { caseId, results = [] } = event;
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });

  // The verdict covers every run under this id, not only this one: a second
  // run with --case-id used to overwrite the first run's outcome.
  const { Item: row = {} } = await ddb.send(new GetItemCommand({
    TableName: CASE_TABLE, Key: { caseId: { S: caseId } }, ConsistentRead: true,
  }));
  const plain = (m) => Object.fromEntries(Object.entries(m ?? {})
    .map(([k, v]) => [k, Object.fromEntries(Object.entries(v.M ?? {}).map(([f, x]) => [f, x.S ?? x.N]))]));
  const summary = summarizeAction({
    targets: plain(row.targets?.M),
    previous: (row.failures?.L ?? []).map((f) => plain({ f }).f),
    results,
    requested: (row.requestedTargets?.L ?? []).map((t) => plain({ t }).t),
  });

  const now = new Date().toISOString();
  await ddb.send(new UpdateItemCommand({
    TableName: CASE_TABLE,
    Key: { caseId: { S: caseId } },
    // completedAt is when the latest run finished. closedAt is kept, with
    // the same value, for readers written before completedAt existed; a run
    // finishing never closes anything.
    UpdateExpression: 'SET #state = :state, completedAt = :now, closedAt = :now, '
      + 'succeededCount = :ok, failedCount = :bad, targetCount = :count, failures = :failures',
    ExpressionAttributeNames: { '#state': 'state' },
    ExpressionAttributeValues: {
      ':state': { S: summary.state },
      ':now': { S: now },
      ':ok': { N: String(summary.succeeded) },
      ':bad': { N: String(summary.failed) },
      ':count': { N: String(summary.targetCount) },
      ':failures': {
        L: summary.failures.map((f) => ({
          M: {
            accountId: { S: f.accountId },
            instanceId: { S: f.instanceId },
            error: { S: f.error },
            cause: { S: f.cause },
          },
        })),
      },
    },
  }));

  return {
    caseId,
    caseState: summary.state,
    succeeded: summary.succeeded,
    failed: summary.failed,
    closedAt: now,
    completedAt: now,
    failures: summary.failures.map(({ accountId, instanceId, error }) => ({ accountId, instanceId, error })),
  };
}

/**
 * ── Incident cases ────────────────────────────────────────────────────
 * A case is one incident; see case-log.mjs for the log's format and why it
 * is chained. Its row in fip-cases has kind 'case' and is an index, kept in
 * step with the log. The log, signed and in the evidence bucket, is the
 * record: the row can always be rebuilt from it.
 *
 * Signing happens here, with the Lambda's own identity, as for manifests.
 * The CLI never holds the signing permission.
 */
async function readCaseRow(ddb, caseId) {
  const { Item } = await ddb.send(new GetItemCommand({
    TableName: CASE_TABLE, Key: { caseId: { S: caseId } }, ConsistentRead: true,
  }));
  return Item ?? null;
}

const MEMBERSHIP_EVENTS = new Set(['MEMBER_ATTACHED', 'MEMBER_MOVED', 'MERGED']);

/** A run's row gains its `cases` map if it predates it. A nested SET needs the parent. */
async function ensureCasesMap(ddb, actionId) {
  await ddb.send(new UpdateItemCommand({
    TableName: CASE_TABLE, Key: { caseId: { S: actionId } },
    UpdateExpression: 'SET #cases = if_not_exists(#cases, :empty)',
    ConditionExpression: 'attribute_exists(caseId)',
    ExpressionAttributeNames: { '#cases': 'cases' },
    ExpressionAttributeValues: { ':empty': { M: {} } },
  }));
}

async function applyToRow(ddb, caseId, doc, sha256) {
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: CASE_TABLE, Key: { caseId: { S: caseId } }, ...rowUpdateFor(doc, sha256),
    }));
  } catch (err) {
    // Already at or past this record: someone else applied it, or a later one.
    if (err.name !== 'ConditionalCheckFailedException') throw err;
  }
}

/**
 * Append one event to a case log, and bring the row up to date. The S3 write
 * decides the sequence number (If-None-Match), so concurrent writers cannot
 * both take seq N. A writer that loses reads the winner's record, applies it
 * to the row if the row has not caught up, and tries again at N+1.
 */
async function appendCaseEvent({ caseId, event, data, actor }, creds) {
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
  const s3 = new S3Client({ region: REGION, credentials: creds });

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await readCaseRow(ddb, caseId);
    if (!row || row.kind?.S !== 'case') throw new Error(`no incident case ${caseId}`);
    // Re-checked on every attempt, so a case closed or merged between the
    // caller's own check and this write does not gain or lose a member.
    if (MEMBERSHIP_EVENTS.has(event) && row.state?.S !== 'OPEN') {
      throw new Error(`case ${caseId} is ${row.state?.S}${row.mergedInto?.S ? ` into ${row.mergedInto.S}` : ''}; `
        + 'membership changes only in open cases');
    }
    const last = Number(row.logSeq?.N ?? 0);
    const seq = last + 1;
    const prev = last ? { seq: last, key: caseLogKey(caseId, last), sha256: row.logHead?.S } : null;
    const doc = buildCaseEvent({ caseId, seq, event, at: new Date().toISOString(), actor, prev, data });
    const envelope = await signEnvelope('caseEvent', doc, 'case-event.json');
    const key = caseLogKey(caseId, seq);
    try {
      await s3.send(new PutObjectCommand({
        Bucket: EVIDENCE_BUCKET, Key: key,
        Body: JSON.stringify(envelope, null, 2), ContentType: 'application/json',
        IfNoneMatch: '*',
        ...objectLock(),
      }));
    } catch (err) {
      const status = err.$metadata?.httpStatusCode;
      if (status !== 412 && status !== 409 && err.name !== 'PreconditionFailed') throw err;
      // Lost the race for seq. The record that won may not be on the row yet.
      const o = await s3.send(new GetObjectCommand({ Bucket: EVIDENCE_BUCKET, Key: key }));
      const winner = JSON.parse(await o.Body.transformToString());
      await applyToRow(ddb, caseId, signedDocument(winner), winner.signature.signedPayloadSha256);
      continue;
    }
    await applyToRow(ddb, caseId, doc, envelope.signature.signedPayloadSha256);
    return { seq, key, event, at: doc.at };
  }
  throw new Error(`case ${caseId}: too many concurrent writers; try again`);
}

async function caseAction(event, creds) {
  const { caseId, op, actor = null } = event;
  if (!isCaseId(caseId)) throw new Error(`'${caseId}' is not an incident case id (case-<UTC>-<hex>)`);

  if (op === 'open') {
    const tickets = [...new Set((event.tickets ?? []).map(checkTicket))];
    const comment = checkComment(event.comment);
    const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
    const now = new Date().toISOString();
    try {
      await ddb.send(new PutItemCommand({
        TableName: CASE_TABLE,
        Item: {
          caseId: { S: caseId },
          kind: { S: 'case' },
          state: { S: 'OPEN' },
          openedAt: { S: now },
          openedBy: { S: actor ?? 'unknown' },
          members: { M: {} },
        },
        ConditionExpression: 'attribute_not_exists(caseId)',
      }));
    } catch (err) {
      if (err.name === 'ConditionalCheckFailedException') throw new Error(`case ${caseId} already exists`);
      throw err;
    }
    const record = await appendCaseEvent({
      caseId, event: 'OPENED', actor, data: { tickets, comment },
    }, creds);
    return { op, caseState: 'OPEN', tickets, record };
  }

  if (op === 'ticket') {
    const ticket = checkTicket(event.ticket);
    const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
    const row = await readCaseRow(ddb, caseId);
    if (!row || row.kind?.S !== 'case') throw new Error(`no incident case ${caseId}`);
    if (row.state?.S !== 'OPEN') throw new Error(`case ${caseId} is ${row.state?.S}; tickets are added to open cases`);
    if ((row.tickets?.SS ?? []).includes(ticket)) throw new Error(`case ${caseId} already carries ticket ${ticket}`);
    const record = await appendCaseEvent({
      caseId, event: 'TICKET_ADDED', actor, data: { ticket, comment: checkComment(event.comment) },
    }, creds);
    return { op, ticket, record };
  }

  if (op === 'comment') {
    const record = await appendCaseEvent({
      caseId, event: 'COMMENT', actor, data: { comment: checkComment(event.comment, { required: true }) },
    }, creds);
    return { op, record };
  }

  if (op === 'move') {
    const comment = checkComment(event.comment, { required: true });
    const moves = await moveMembers({ to: caseId, specs: event.members ?? [], comment, actor }, creds);
    return { op, to: caseId, moves };
  }

  if (op === 'merge') {
    const comment = checkComment(event.comment, { required: true });
    const froms = [...new Set(event.from ?? [])];
    if (!froms.length) throw new Error('name at least one case to merge');
    const merged = [];
    // One at a time: each is complete, and recorded, before the next starts.
    for (const from of froms) merged.push(await mergeCase({ into: caseId, from, comment, actor }, creds));
    return { op, into: caseId, merged };
  }

  throw new Error(`unknown case operation '${op}' (have: open, ticket, comment, move, merge)`);
}

/** Why a transaction was refused, in words: which row's condition failed. */
function cancellationReason(err, items) {
  const reasons = err.CancellationReasons ?? [];
  const failed = reasons
    .map((r, i) => (r?.Code === 'ConditionalCheckFailed' ? items[i]?.Update?.Key?.caseId?.S : null))
    .filter(Boolean);
  return failed.length
    ? `changed since it was read: ${failed.join(', ')} (another responder may have acted, or a case is no longer open)`
    : (err.message ?? String(err));
}

/**
 * Run a membership transaction whose signed records are already written.
 * If it is refused, each record is withdrawn by a signed ABORTED note, so
 * the log says exactly what did and did not happen.
 */
async function commitOrAbort(ddb, items, written, actor, creds) {
  try {
    await ddb.send(new TransactWriteItemsCommand({ TransactItems: items }));
  } catch (err) {
    if (err.name !== 'TransactionCanceledException') throw err;
    const reason = cancellationReason(err, items);
    for (const w of written) {
      await appendCaseEvent({
        caseId: w.caseId, event: 'ABORTED', actor,
        data: { aborts: { seq: w.seq, key: w.key, event: w.event }, reason },
      }, creds);
    }
    throw new Error(`refused, nothing changed: ${reason}`);
  }
}

/**
 * Move members to the case `to`. `specs` are as `fip case move` takes them
 * (parseMemberSpec). Members are grouped by the case they are in now; each
 * group is one signed record in each log and one transaction.
 */
async function moveMembers({ to, specs, comment, actor, via = null }, creds) {
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
  const rows = new Map();
  const row = async (id) => {
    if (!rows.has(id)) rows.set(id, await readCaseRow(ddb, id));
    return rows.get(id);
  };
  const dest = await row(to);
  if (!dest || dest.kind?.S !== 'case') throw new Error(`no incident case ${to}`);
  if (dest.state?.S !== 'OPEN') {
    throw new Error(`case ${to} is ${dest.state?.S}${dest.mergedInto?.S ? ` into ${dest.mergedInto.S}` : ''}; `
      + 'members move only into open cases');
  }

  // Expand every argument into members: { member, actionId, instanceId, accountId }.
  const wanted = new Map();
  const add = (actionId, instanceId, accountId) => {
    wanted.set(memberId(actionId, instanceId), { member: memberId(actionId, instanceId), actionId, instanceId, accountId });
  };
  for (const spec of specs) {
    const s = parseMemberSpec(spec);
    if (s.kind === 'case') {
      const c = await row(s.caseId);
      if (!c || c.kind?.S !== 'case') throw new Error(`no incident case ${s.caseId}`);
      for (const m of Object.values(c.members?.M ?? {})) {
        add(m.M.actionId.S, m.M.instanceId.S, m.M.accountId?.S ?? 'unknown');
      }
      continue;
    }
    const a = await row(s.actionId);
    if (!a || a.kind?.S === 'case') throw new Error(`no isolation run ${s.actionId}`);
    const targets = targetsOfAction(a);
    if (s.kind === 'member') {
      if (!targets[s.instanceId]) throw new Error(`${s.instanceId} is not a target of ${s.actionId}`);
      add(s.actionId, s.instanceId, targets[s.instanceId]);
    } else {
      for (const [instanceId, accountId] of Object.entries(targets)) add(s.actionId, instanceId, accountId);
    }
  }
  if (!wanted.size) throw new Error('nothing to move: the arguments name no members');

  // Where each one is now, grouped by source.
  const groups = new Map();
  for (const m of wanted.values()) {
    const a = await row(m.actionId);
    const incident = a.incident?.S;
    const where = locateMember(a, m.instanceId, incident ? await row(incident) : null);
    if (where.caseId === to) continue;
    const key = where.caseId ?? '';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ ...m, recorded: where.recorded });
  }
  if (!groups.size) throw new Error(`nothing to move: every member named is already in ${to}`);

  const done = [];
  for (const [key, members] of groups) {
    const from = key || null;
    if (from) {
      const src = await row(from);
      if (src?.state?.S !== 'OPEN') throw new Error(`case ${from} is ${src?.state?.S}; members move only out of open cases`);
    }
    const listed = members.map(({ member, accountId, instanceId }) => ({ member, accountId, instanceId }));
    const data = { from, to, members: listed, comment, ...(via ? { via } : {}) };
    const written = [];
    const destRecord = await appendCaseEvent({ caseId: to, event: 'MEMBER_MOVED', actor, data }, creds);
    written.push({ caseId: to, ...destRecord });
    if (from) {
      const srcRecord = await appendCaseEvent({
        caseId: from, event: 'MEMBER_MOVED', actor,
        data: { ...data, counterpart: { caseId: to, seq: destRecord.seq, key: destRecord.key } },
      }, creds);
      written.push({ caseId: from, ...srcRecord });
    }
    for (const actionId of new Set(members.map((m) => m.actionId))) await ensureCasesMap(ddb, actionId);
    const items = moveTransaction({ table: CASE_TABLE, members, from, to, record: destRecord });
    await commitOrAbort(ddb, items, written, actor, creds);
    done.push({ from, to, members: listed.map((m) => m.member), records: written.map(({ caseId, seq }) => ({ caseId, seq })) });
  }
  return done;
}

/** Fold `from` into `into`: move every member, then make `from` an alias of `into`. */
async function mergeCase({ into, from, comment, actor }, creds) {
  if (into === from) throw new Error('a case cannot be merged into itself');
  if (!isCaseId(from)) throw new Error(`'${from}' is not an incident case id`);
  const ddb = new DynamoDBClient({ region: REGION, credentials: creds });
  const src = await readCaseRow(ddb, from);
  if (!src || src.kind?.S !== 'case') throw new Error(`no incident case ${from}`);
  if (src.state?.S !== 'OPEN') {
    throw new Error(`case ${from} is ${src.state?.S}${src.mergedInto?.S ? ` into ${src.mergedInto.S}` : ''}; only open cases merge`);
  }
  const moves = Object.keys(src.members?.M ?? {}).length
    ? await moveMembers({ to: into, specs: [from], comment, actor, via: 'merge' }, creds)
    : [];

  const tickets = src.tickets?.SS ?? [];
  const written = [];
  const out = await appendCaseEvent({
    caseId: from, event: 'MERGED', actor, data: { mergedInto: into, comment },
  }, creds);
  written.push({ caseId: from, ...out });
  const inn = await appendCaseEvent({
    caseId: into, event: 'MERGED', actor,
    data: { absorbed: from, tickets, comment, counterpart: { caseId: from, seq: out.seq, key: out.key } },
  }, creds);
  written.push({ caseId: into, ...inn });
  await commitOrAbort(ddb, mergeTransaction({ table: CASE_TABLE, into, from, tickets }), written, actor, creds);
  return { from, into, tickets, moves, records: written.map(({ caseId, seq }) => ({ caseId, seq })) };
}

// Which credential path each action needs. Member actions assume
// FipResponderRole with the external ID; evidence actions assume
// FipEvidenceRole in our own evidence account.
/**
 * ── Scalable hashing ──────────────────────────────────────────────────
 *
 * A single Lambda cannot hash a large volume. Measured ~0.4-0.6 GB/min
 * against the EBS direct APIs, so the 15-minute ceiling lands around 6-9 GB
 * of allocated data — and a 30 GiB Windows root hit Sandbox.Timedout in
 * testing. Production volumes are routinely larger than that.
 *
 * SHA-256 is inherently sequential and cannot be parallelized, so scaling
 * means changing what the digest IS. The digest is now a Merkle root over
 * fixed ranges of blocks:
 *
 *   rangeDigest = SHA256( for each block in range, ascending:
 *                           utf8("<blockIndex>:") || blockData )
 *   root        = SHA256( utf8(header) || rangeDigest[0] || rangeDigest[1] ... )
 *   header      = "fip-merkle/1 blockSize=<n> volumeSize=<n> ranges=<n>"
 *
 * Ranges are concatenated in ascending start order. Everything needed to
 * recompute this is recorded in the manifest, so a third party can verify it
 * without our tooling.
 *
 * This is NOT comparable to `sha256sum` of a restored image — but neither was
 * the previous single-pass digest, which also hashed index alongside data and
 * skipped unallocated blocks entirely. Nothing reproducible was lost.
 *
 * Block tokens are NOT passed between invocations: each range re-lists from
 * its own StartingBlockIndex, so no token lifetime is assumed.
 */
const RANGE_BLOCKS = Number(process.env.FIP_HASH_RANGE_BLOCKS ?? 4000); // ~2 GiB

async function hashPlan({ snapshotId }, creds) {
  const ebs = new EBSClient({ region: REGION, credentials: creds });
  const first = await ebs.send(new ListSnapshotBlocksCommand({
    SnapshotId: snapshotId, MaxResults: 100,
  }));
  const blockSize = first.BlockSize;
  const volumeSize = first.VolumeSize;
  // VolumeSize is in GiB; the highest possible block index bounds the ranges.
  const maxBlocks = Math.ceil((volumeSize * 1024 * 1024 * 1024) / blockSize);
  const ranges = [];
  for (let start = 0; start < maxBlocks; start += RANGE_BLOCKS) {
    ranges.push({ snapshotId, start, end: Math.min(start + RANGE_BLOCKS, maxBlocks) });
  }
  return { snapshotId, blockSize, volumeSize, rangeBlocks: RANGE_BLOCKS, ranges };
}

async function hashRange({ snapshotId, start, end }, creds) {
  const ebs = new EBSClient({ region: REGION, credentials: creds });
  const hash = createHash('sha256');
  let token, blocks = 0, bytes = 0;
  do {
    const page = await ebs.send(new ListSnapshotBlocksCommand({
      SnapshotId: snapshotId, StartingBlockIndex: start, NextToken: token,
    }));
    for (const b of page.Blocks ?? []) {
      if (b.BlockIndex < start) continue;
      if (b.BlockIndex >= end) { token = undefined; break; }
      const d = await ebs.send(new GetSnapshotBlockCommand({
        SnapshotId: snapshotId, BlockIndex: b.BlockIndex, BlockToken: b.BlockToken,
      }));
      const chunk = Buffer.from(await d.BlockData.transformToByteArray());
      hash.update(Buffer.from(`${b.BlockIndex}:`)); hash.update(chunk);
      blocks += 1; bytes += chunk.length;
    }
    if (token !== undefined) token = page.NextToken;
  } while (token);
  return { snapshotId, start, end, digest: hash.digest('hex'), blocks, bytes };
}

/** Combine range digests into the root. No AWS call, no credentials. */
async function hashCombine({ snapshotId, plan, ranges }) {
  const ordered = [...ranges].sort((a, b) => a.start - b.start);
  const header = `fip-merkle/1 blockSize=${plan.blockSize} volumeSize=${plan.volumeSize} ranges=${ordered.length}`;
  const root = createHash('sha256');
  root.update(Buffer.from(header));
  for (const r of ordered) root.update(Buffer.from(r.digest, 'hex'));
  return {
    snapshotId,
    algorithm: 'fip-merkle/1',
    header,
    sha256: root.digest('hex'),
    blockSize: plan.blockSize,
    volumeSize: plan.volumeSize,
    blocks: ordered.reduce((n, r) => n + r.blocks, 0),
    bytes: ordered.reduce((n, r) => n + r.bytes, 0),
    rangeDigests: ordered.map((r) => ({ start: r.start, end: r.end, digest: r.digest })),
  };
}

/**
 * Put a contained instance back on the security groups it had before
 * containment. Plans by default; changes nothing unless `apply` is true.
 *
 * ── Where the originals come from ─────────────────────────────────────
 * The SIGNED MANIFEST is the source of record, and its signature is checked
 * here against this installation's own signing key before it is believed.
 * The fip:original-sgs tag on each interface is a cross-check, not an
 * authority: anyone in the member account with ec2:CreateTags can edit it,
 * and FipRestorePolicy lets this role attach ANY existing group to a tagged
 * interface, because IAM cannot compare the request with the tag. So when the
 * two disagree the interface is BLOCKED rather than guessed at. Only when no
 * manifest exists (a case that failed before writing one) does the tag stand
 * alone, and the result says so.
 *
 * ── What it deliberately does not do ──────────────────────────────────
 * Auto Scaling is reported from the manifest, not undone: resuming Launch or
 * re-attaching puts capacity back from a launch template that may be the
 * compromise vector. The isolation group is left in place; it is free and
 * the next case in the VPC reuses it. fip:case-id stays on everything: it is
 * the instance's link to its evidence.
 *
 * A restore that changes anything is a custody event: it reconnects a host
 * that may still be compromised. It is recorded, signed, beside the manifest.
 */
async function loadSignedManifest(caseId, instanceId, evidenceCreds) {
  const s3 = new S3Client({ region: REGION, credentials: evidenceCreds });
  const key = `cases/${caseId}/${instanceId}/manifest.json`;
  let text;
  try {
    const o = await s3.send(new GetObjectCommand({ Bucket: EVIDENCE_BUCKET, Key: key }));
    text = await o.Body.transformToString();
  } catch (err) {
    if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) return { key, manifest: null };
    throw err;
  }
  const sig = JSON.parse(text).signature ?? {};
  const payload = Buffer.from(sig.signedPayloadBase64 ?? '', 'base64');
  const embedded = Buffer.from(sig.publicKeyDer ?? '', 'base64');

  // Origin, not just integrity: the embedded key must be OUR key.
  const ours = await new KMSClient({ region: REGION })
    .send(new GetPublicKeyCommand({ KeyId: SIGNING_KEY_ALIAS }));
  if (!embedded.equals(Buffer.from(ours.PublicKey))) {
    throw new Error(`${key} is not signed by this installation's signing key; refusing to restore from it`);
  }
  const ok = cryptoVerify('sha384', payload,
    { key: embedded, format: 'der', type: 'spki', dsaEncoding: 'der' },
    Buffer.from(sig.value ?? '', 'base64'));
  if (!ok) throw new Error(`${key} fails its signature check; refusing to restore from it`);

  // The signed bytes, not the readable copy beside them.
  return { key, manifest: JSON.parse(payload.toString('utf8')) };
}

const sameSet = (a, b) => a.length === b.length
  && [...a].sort().join(',') === [...b].sort().join(',');

async function restoreInstance(event, creds) {
  const { instanceId, apply = false, actor = null } = event;
  const ec2 = ec2For(creds);

  const d = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
  const inst = d.Reservations?.[0]?.Instances?.[0];
  if (!inst) throw new Error(`instance ${instanceId} not found`);
  const caseId = (inst.Tags ?? []).find((t) => t.Key === CASE_TAG)?.Value;
  if (!caseId) {
    throw new Error(`${instanceId} has no ${CASE_TAG} tag: FIP has not contained it, so there is nothing to restore`);
  }
  if (event.caseId && event.caseId !== caseId) {
    throw new Error(`${instanceId} belongs to case ${caseId}, not ${event.caseId}`);
  }

  const evidenceCreds = await evidenceCredentials(caseId);
  const { key: manifestKey, manifest } = await loadSignedManifest(caseId, instanceId, evidenceCreds);
  const fromManifest = new Map(
    (manifest?.containment?.originalSecurityGroups ?? []).map((o) => [o.eni, o.groups]),
  );

  const eniIds = (inst.NetworkInterfaces ?? []).map((n) => n.NetworkInterfaceId);
  const enis = eniIds.length
    ? (await ec2.send(new DescribeNetworkInterfacesCommand({ NetworkInterfaceIds: eniIds }))).NetworkInterfaces ?? []
    : [];

  const plan = [];
  for (const n of enis) {
    const eni = n.NetworkInterfaceId;
    const current = (n.Groups ?? []).map((g) => g.GroupId);
    const tagValue = (n.TagSet ?? []).find((t) => t.Key === ORIGINAL_SG_TAG)?.Value;
    const tagGroups = tagValue ? tagValue.split(',') : null;
    const recorded = fromManifest.has(eni) ? fromManifest.get(eni) : undefined;
    const row = { eni, current, tag: tagValue ?? null };

    let original;
    if (manifest) {
      if (recorded === undefined) {
        plan.push({ ...row, status: 'SKIP', reason: 'not in the signed manifest; containment did not change it' });
        continue;
      }
      if (!recorded?.length) {
        plan.push({ ...row, status: 'SKIP', reason: 'the manifest records its original groups as unknown' });
        continue;
      }
      if (tagGroups && !sameSet(tagGroups, recorded)) {
        plan.push({ ...row, original: recorded, status: 'BLOCKED',
          reason: `its ${ORIGINAL_SG_TAG} tag (${tagValue}) disagrees with the signed manifest; someone changed the tag` });
        continue;
      }
      original = recorded;
    } else {
      if (!tagGroups) {
        plan.push({ ...row, status: 'SKIP', reason: `no signed manifest and no ${ORIGINAL_SG_TAG} tag` });
        continue;
      }
      original = tagGroups;
    }

    if (sameSet(current, original)) {
      plan.push({ ...row, original, status: 'OK', reason: 'already on its original groups' });
      continue;
    }

    // Every group must still exist and be in this interface's VPC, or the
    // change fails halfway or attaches something else.
    let found = [];
    try {
      found = (await ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: original }))).SecurityGroups ?? [];
    } catch (err) {
      if (!/NotFound/i.test(err.name ?? String(err))) throw err;
    }
    const usable = found.filter((g) => g.VpcId === n.VpcId).map((g) => g.GroupId);
    const missing = original.filter((g) => !usable.includes(g));
    if (missing.length) {
      plan.push({ ...row, original, status: 'BLOCKED',
        reason: `original group(s) no longer exist in ${n.VpcId}: ${missing.join(', ')}` });
      continue;
    }
    plan.push({ ...row, original, status: 'RESTORE' });
  }

  const summary = {
    caseId, instanceId, vpcId: inst.VpcId, applied: false,
    source: manifest ? 'signed-manifest' : 'tag-only',
    manifestKey: manifest ? manifestKey : null,
    autoScaling: manifest?.containment?.autoScaling ?? null,
    plan,
  };
  if (!apply) return summary;

  const changed = [];
  for (const p of plan) {
    if (p.status !== 'RESTORE' && p.status !== 'OK') continue;
    if (p.status === 'RESTORE') {
      await ec2.send(new ModifyNetworkInterfaceAttributeCommand({
        NetworkInterfaceId: p.eni, Groups: p.original,
      }));
    }
    const after = (await ec2.send(new DescribeNetworkInterfacesCommand({ NetworkInterfaceIds: [p.eni] })))
      .NetworkInterfaces?.[0]?.Groups?.map((g) => g.GroupId) ?? [];
    p.after = after;
    if (!sameSet(after, p.original)) {
      p.result = 'FAILED';
      continue;
    }
    if (p.tag !== null) {
      // Containment trusts this tag on any later run, so leaving it would make
      // a future case record today's groups as the originals.
      await ec2.send(new DeleteTagsCommand({ Resources: [p.eni], Tags: [{ Key: ORIGINAL_SG_TAG }] }));
    }
    p.result = p.status === 'RESTORE' ? 'RESTORED' : 'TAG_CLEARED';
    if (p.status === 'RESTORE') changed.push({ eni: p.eni, from: p.current, to: p.original });
  }
  summary.applied = true;

  if (changed.length) {
    const custody = {
      schema: 'fip.custody/1',
      caseId,
      event: 'RESTORED_NETWORK',
      at: new Date().toISOString(),
      accountId: event.accountId,
      instanceId,
      interfaces: changed,
      originalsFrom: summary.source,
      manifestKey: summary.manifestKey,
      actor,
      note: 'The instance was taken off FIP isolation and put back on its original '
        + 'security groups. Auto Scaling changes made by containment, if any, were not undone.',
    };
    const envelope = await signEnvelope('custody', custody, 'custody.json');
    const key = `cases/${caseId}/custody/${custody.at.replace(/[:.]/g, '-')}-restore-${instanceId}.json`;
    await new S3Client({ region: REGION, credentials: evidenceCreds }).send(new PutObjectCommand({
      Bucket: EVIDENCE_BUCKET, Key: key,
      Body: JSON.stringify(envelope, null, 2), ContentType: 'application/json',
      ...objectLock(),
    }));
    await new DynamoDBClient({ region: REGION, credentials: evidenceCreds }).send(new UpdateItemCommand({
      TableName: CASE_TABLE,
      Key: { caseId: { S: caseId } },
      UpdateExpression: 'SET custody = list_append(if_not_exists(custody, :empty), :entry)',
      ExpressionAttributeValues: {
        ':empty': { L: [] },
        ':entry': { L: [{ M: {
          event: { S: custody.event }, at: { S: custody.at },
          instanceId: { S: instanceId }, recordKey: { S: key },
        } }] },
      },
    }));
    summary.custodyRecordKey = key;
  }
  return summary;
}

const ACTIONS = {
  tag:      { fn: tagTarget,        creds: 'member' },
  snapshot: { fn: createSnapshots,  creds: 'member' },
  status:   { fn: snapshotStatus,   creds: 'member' },
  hash:     { fn: hashSnapshot,     creds: 'member' },
  share:    { fn: shareToEvidence,  creds: 'member' },
  contain:  { fn: containInstance,  creds: 'member' },
  stop:     { fn: stopInstance,     creds: 'member' },
  hashPlan:      { fn: hashPlan,    creds: 'member' },
  hashRange:     { fn: hashRange,   creds: 'member' },
  hashCombine:   { fn: hashCombine, creds: 'none' },
  copyHashPlan:  { fn: hashPlan,    creds: 'evidence' },
  copyHashRange: { fn: hashRange,   creds: 'evidence' },
  copy:       { fn: copyToEvidence, creds: 'evidence' },
  copyStatus: { fn: copyStatus,     creds: 'evidence' },
  hashCopy:   { fn: hashSnapshot,   creds: 'evidence' },
  manifest:   { fn: writeManifest,  creds: 'evidence' },
  // Case-level actions. They act on the case row, which belongs to no single
  // member account, so they are exempt from the accountId requirement below.
  caseOpen:    { fn: caseOpen,    creds: 'evidence', caseLevel: true },
  caseSummary: { fn: caseSummary, creds: 'evidence', caseLevel: true },
  // Incident cases (fip case). Human-initiated only, like release.
  case:        { fn: caseAction,  creds: 'evidence', caseLevel: true },
  // Chain-of-custody events. Deliberately NOT reachable from the acquisition
  // state machines: evidence is released to an analysis account only when a
  // human asks for it.
  release: { fn: releaseToAnalysis, creds: 'evidence', caseLevel: true },
  // Also human-initiated only (fip restore). The operator names the instance,
  // not the case: the case id is read from the instance's own tag, so it
  // cannot be mistyped into another case's record.
  restore: { fn: restoreInstance, creds: 'member', caseFromTarget: true },
};

export const handler = async (event) => {
  const { action, accountId, caseId } = event;
  const spec = ACTIONS[action];
  if (!spec) throw new Error(`unknown action '${action}' (have: ${Object.keys(ACTIONS)})`);
  // A case-level action spans every target, so there is no one accountId to
  // name. caseId is still required: it is the key of the row being written.
  if (!caseId && !spec.caseFromTarget) throw new Error('caseId is required');
  if (spec.caseFromTarget && !event.instanceId) {
    throw new Error(`instanceId is required for action '${action}'`);
  }
  if (!spec.caseLevel && !accountId) {
    throw new Error(`accountId is required for action '${action}'`);
  }

  const creds = spec.creds === 'none'
    ? null
    : spec.creds === 'evidence'
      ? await evidenceCredentials(caseId)
      : await memberCredentials(accountId, caseId ?? `restore-${event.instanceId}`);

  const result = await spec.fn(event, creds);
  return { action, accountId: accountId ?? null, caseId: caseId ?? null, ...result };
};
