/**
 * Assertions on the decisions, not on CDK.
 *
 * Each test here corresponds to a design decision
 * that a future edit could silently undo. The Object Lock pair is the
 * point of this file: enabled on the bucket, with no default retention.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { App } = require('aws-cdk-lib');
const { Template, Match } = require('aws-cdk-lib/assertions');
const { FipCoreStack, resolveRetentionPolicy } = require('../lib/fip-core-stack');

const ENV = { account: '111111111111', region: 'us-east-1' };
const ORG = 'o-exampleorg1';

function synth(context = {}) {
  const app = new App({ context: { 'fip:orgId': ORG, ...context } });
  const stack = new FipCoreStack(app, 'TestCore', {
    env: ENV,
    orgId: context['fip:orgId'] === undefined ? ORG : context['fip:orgId'],
    orchestratorAccountId: '222222222222',
  });
  return Template.fromStack(stack);
}

describe('evidence bucket — Object Lock', () => {
  test('Object Lock is enabled on the bucket', () => {
    synth().hasResourceProperties('AWS::S3::Bucket', {
      ObjectLockEnabled: true,
    });
  });

  test('NO default retention is configured — nothing is locked by the bucket', () => {
    const buckets = synth().findResources('AWS::S3::Bucket');
    for (const [name, res] of Object.entries(buckets)) {
      const cfg = res.Properties.ObjectLockConfiguration;
      if (cfg && cfg.Rule) {
        assert.fail(
          `${name} declares a default Object Lock retention rule. Retention is ` +
          `applied per object at write time from the customer-supplied policy; ` +
          `a bucket default would lock objects during install and test. ` +
          `See manual §8.`
        );
      }
    }
  });

  test('versioning is on, which Object Lock requires', () => {
    synth().hasResourceProperties('AWS::S3::Bucket', {
      VersioningConfiguration: { Status: 'Enabled' },
    });
  });

  test('evidence bucket is retained, never deleted', () => {
    const buckets = synth().findResources('AWS::S3::Bucket');
    for (const [name, res] of Object.entries(buckets)) {
      assert.strictEqual(
        res.DeletionPolicy, 'Retain',
        `${name} must be Retain — DeletionPolicy: Delete is backwards for evidence.`
      );
    }
  });

  test('public access is blocked on every bucket', () => {
    const buckets = synth().findResources('AWS::S3::Bucket');
    for (const [name, res] of Object.entries(buckets)) {
      assert.deepStrictEqual(
        res.Properties.PublicAccessBlockConfiguration,
        {
          BlockPublicAcls: true, BlockPublicPolicy: true,
          IgnorePublicAcls: true, RestrictPublicBuckets: true,
        },
        `${name} does not block all public access.`
      );
    }
  });

  test('TLS is enforced', () => {
    synth().hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    });
  });
});

describe('evidence CMK', () => {
  test('key rotation is enabled', () => {
    synth().hasResourceProperties('AWS::KMS::Key', { EnableKeyRotation: true });
  });

  test('key policy names a principal and never uses Principal "*"', () => {
    const keys = synth().findResources('AWS::KMS::Key');
    for (const [name, res] of Object.entries(keys)) {
      for (const stmt of res.Properties.KeyPolicy.Statement) {
        assert.notStrictEqual(
          stmt.Principal, '*',
          `${name} has a wildcard principal; name the principal instead.`
        );
      }
    }
  });

  test('org condition is applied when an org ID is supplied', () => {
    const keys = synth().findResources('AWS::KMS::Key');
    const stmts = Object.values(keys)
      .flatMap((r) => r.Properties.KeyPolicy.Statement)
      .filter((s) => s.Sid === 'AllowOrchestratorUse');
    assert.strictEqual(stmts.length, 1);
    assert.strictEqual(stmts[0].Condition.StringEquals['aws:PrincipalOrgID'], ORG);
  });

  test('deploys without an org ID — FIP does not require an organization', () => {
    const app = new App({ context: {} });
    const stack = new FipCoreStack(app, 'NoOrg', {
      env: ENV, orgId: null, orchestratorAccountId: '222222222222',
    });
    const stmts = Object.values(Template.fromStack(stack).findResources('AWS::KMS::Key'))
      .flatMap((r) => r.Properties.KeyPolicy.Statement)
      .filter((s) => s.Sid === 'AllowOrchestratorUse');
    assert.strictEqual(stmts.length, 1, 'orchestrator statement must still exist');
    assert.strictEqual(
      stmts[0].Condition, undefined,
      'absent org ID must drop the condition, not fail the deployment.'
    );
  });
});

describe('retention policy resolution', () => {
  const node = (ctx) => ({ tryGetContext: (k) => (k in ctx ? ctx[k] : undefined) });

  test('install/test default locks nothing', () => {
    assert.deepStrictEqual(
      resolveRetentionPolicy(node({})),
      { productionMode: false, mode: 'NONE', days: null },
    );
  });

  test('production mode without a duration is refused', () => {
    assert.throws(
      () => resolveRetentionPolicy(node({ 'fip:productionMode': true })),
      /must be a positive integer number of days/,
    );
  });

  test('production mode with a customer duration resolves', () => {
    assert.deepStrictEqual(
      resolveRetentionPolicy(node({
        'fip:productionMode': true,
        'fip:retentionMode': 'COMPLIANCE',
        'fip:retentionDays': 2555,
      })),
      { productionMode: true, mode: 'COMPLIANCE', days: 2555 },
    );
  });

  test('an unknown retention mode is refused', () => {
    assert.throws(
      () => resolveRetentionPolicy(node({
        'fip:productionMode': true, 'fip:retentionMode': 'FOREVER',
        'fip:retentionDays': 30,
      })),
      /fip:retentionMode must be one of/,
    );
  });

  test('production mode false ignores any retention left in context', () => {
    assert.deepStrictEqual(
      resolveRetentionPolicy(node({
        'fip:productionMode': false,
        'fip:retentionMode': 'COMPLIANCE',
        'fip:retentionDays': 2555,
      })),
      { productionMode: false, mode: 'NONE', days: null },
      'a stale retention value in context must not lock test objects',
    );
  });
});

describe('releasing evidence to an analysis account', () => {
  function evidenceRoleStatements() {
    const policies = synth().findResources('AWS::IAM::Policy');
    const statements = [];
    for (const [name, res] of Object.entries(policies)) {
      if (!/EvidenceRole/i.test(name)) continue;
      statements.push(...res.Properties.PolicyDocument.Statement);
    }
    assert.ok(statements.length > 0, 'expected FipEvidenceRole statements');
    return statements;
  }

  test('a release can be made, and is scoped to case-tagged snapshots', () => {
    const release = evidenceRoleStatements().find(
      (st) => [].concat(st.Action ?? []).includes('ec2:ModifySnapshotAttribute'));
    assert.ok(release, 'FipEvidenceRole must be able to share evidence out');
    assert.ok(
      JSON.stringify(release.Condition ?? {}).includes('fip:case-id'),
      'sharing must be scoped by the case tag. Unscoped, this role could share ANY ' +
      'snapshot in the evidence account out to an arbitrary account — including one ' +
      'belonging to a different case or engagement.',
    );
  });

  test('a release can actually be WITHDRAWN', () => {
    const actions = evidenceRoleStatements()
      .flatMap((st) => [].concat(st.Action ?? []))
      .filter((a) => typeof a === 'string');
    assert.ok(
      actions.includes('kms:RetireGrant') || actions.includes('kms:RevokeGrant'),
      'A release creates a KMS grant as well as a snapshot share. Without the ability ' +
      'to retire the grant, "revoke" would remove the visible half and leave access ' +
      'that does not appear in the snapshot\'s permissions at all.',
    );
    assert.ok(actions.includes('kms:ListGrants'), 'revoke must be able to find its grants');
  });

  test('releasing still confers no power to destroy evidence', () => {
    const actions = evidenceRoleStatements()
      .filter((st) => st.Effect !== 'Deny')
      .flatMap((st) => [].concat(st.Action ?? []))
      .filter((a) => typeof a === 'string');
    for (const forbidden of [
      'ec2:DeleteSnapshot', 's3:DeleteObject', 's3:DeleteObjectVersion',
      's3:PutObjectRetention', 's3:BypassGovernanceRetention',
      's3:PutBucketObjectLockConfiguration',
    ]) {
      assert.ok(
        !actions.includes(forbidden),
        `${forbidden} is granted to FipEvidenceRole. This role lands evidence and ` +
        `releases it for examination; it must never be able to remove evidence or ` +
        `alter retention.`,
      );
    }
  });
});

describe('production retention is applied, not just recorded', () => {
  const statement = (t) => Object.values(t.findResources('AWS::IAM::Policy'))
    .flatMap((p) => p.Properties.PolicyDocument.Statement)
    .find((s) => s.Sid === 'LockEvidenceAtWriteTime');

  test('test mode grants no retention-setting at all', () => {
    assert.strictEqual(statement(synth()), undefined);
  });

  test('production mode lets the evidence role lock what it writes, in the chosen mode only', () => {
    const st = statement(synth({
      'fip:productionMode': true, 'fip:retentionMode': 'COMPLIANCE', 'fip:retentionDays': 30,
    }));
    assert.ok(st, 'without s3:PutObjectRetention a PUT carrying Object Lock headers is denied');
    assert.strictEqual(st.Action, 's3:PutObjectRetention');
    assert.deepStrictEqual(st.Condition, { StringEquals: { 's3:object-lock-mode': 'COMPLIANCE' } });
  });
});

describe('product tags', () => {
  test('the stack\'s resources carry application=fipv2 and fip:class=infrastructure', () => {
    const t = synth();
    const bucket = Object.values(t.findResources('AWS::S3::Bucket'))[0];
    const tags = Object.fromEntries(bucket.Properties.Tags.map((x) => [x.Key, x.Value]));
    assert.strictEqual(tags.application, 'fipv2');
    assert.strictEqual(tags['fip:class'], 'infrastructure');
    assert.strictEqual(tags['fip:component'], 'core');
  });
});
