/**
 * The member-account payload is the part that lands in someone else's
 * account, so what it CANNOT do matters more than what it can.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');
const {
  FipMemberStack, INVENTORY_ACTIONS, DELIBERATELY_EXCLUDED, CASE_TAG, ISOLATION_TAG,
  ORIGINAL_SG_TAG,
} = require('../lib/fip-member-stack');

const sids = (t) => Object.values(t.findResources('AWS::IAM::Policy'))
  .flatMap((p) => p.Properties.PolicyDocument.Statement);

const ORG = 'o-exampleorg1';

function synth(orgId = ORG) {
  const app = new App();
  const stack = new FipMemberStack(app, 'TestMember', {
    env: { region: 'us-east-1' }, orgId,
  });
  return Template.fromStack(stack);
}

describe('FipInventoryRole', () => {
  test('attaches no managed policies — never AdministratorAccess', () => {
    const roles = synth().findResources('AWS::IAM::Role');
    for (const [name, res] of Object.entries(roles)) {
      const managed = res.Properties.ManagedPolicyArns || [];
      assert.deepStrictEqual(
        managed, [],
        `${name} attaches managed policies (${JSON.stringify(managed)}). A role ` +
        `that reaches into member accounts gets inline, scoped policy only.`
      );
    }
  });

  test('the inventory statement grants only read-only actions', () => {
    const stmts = Object.values(synth().findResources('AWS::IAM::Policy'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement)
      .filter((s) => s.Sid === 'FipReadOnlyInventory');
    assert.strictEqual(stmts.length, 1, 'expected exactly one inventory statement');

    for (const action of stmts[0].Action) {
      assert.ok(
        /^[a-z0-9-]+:(Describe|List|Get)/.test(action),
        `"${action}" is not read-only. FipInventoryRole is assumed constantly and ` +
        `must be incapable of changing anything; mutating permissions belong to ` +
        `FipResponderRole.`
      );
      assert.notStrictEqual(action, '*', 'wildcard action in the inventory role');
    }
  });

  test('every enumerated action is read-only', () => {
    for (const action of INVENTORY_ACTIONS) {
      assert.ok(
        /:(Describe|List|Get)/.test(action),
        `INVENTORY_ACTIONS contains a non-read-only action: ${action}`,
      );
    }
  });

  test('assume-role requires an external ID', () => {
    const roles = synth().findResources('AWS::IAM::Role');
    const stmts = Object.values(roles)
      .flatMap((r) => r.Properties.AssumeRolePolicyDocument.Statement);
    assert.ok(
      stmts.every((s) => s.Condition?.StringEquals?.['sts:ExternalId'] !== undefined),
      'every trust statement must require sts:ExternalId',
    );
  });

  test('org condition is the OrganizationId parameter, on every trust statement', () => {
    const t = synth();
    const stmts = Object.values(t.findResources('AWS::IAM::Role'))
      .flatMap((r) => r.Properties.AssumeRolePolicyDocument.Statement);
    assert.ok(stmts.length > 0);
    for (const s of stmts) {
      assert.deepStrictEqual(s.Condition.StringEquals['aws:PrincipalOrgID'], {
        'Fn::If': ['HasOrganization', { Ref: 'OrganizationId' }, { Ref: 'AWS::NoValue' }],
      });
      assert.ok(
        s.Condition.StringEquals['sts:ExternalId'] !== undefined,
        'external ID must stay whether or not there is an organization',
      );
    }
    t.hasCondition('HasOrganization', {
      'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'OrganizationId' }, 'none'] }],
    });
  });

  test('OrganizationId has no default, so a deploy that omits it fails', () => {
    const params = synth().toJSON().Parameters;
    assert.ok(params.OrganizationId, 'the parameter exists');
    assert.strictEqual(params.OrganizationId.Default, undefined);
    const re = new RegExp(params.OrganizationId.AllowedPattern);
    assert.ok(re.test('o-exampleorg1') && re.test('none'));
    assert.ok(!re.test('') && !re.test('None') && !re.test('o-'));
  });

  test('the template is the same whatever orgId is passed: no install baked in', () => {
    assert.deepStrictEqual(synth(ORG).toJSON(), synth(null).toJSON());
  });

  test('orchestrator account is a deploy-time parameter, not baked in', () => {
    synth().hasParameter('OrchestratorAccountId', {
      AllowedPattern: '^[0-9]{12}$',
    });
  });
});


describe('FipResponderRole', () => {
  const roles = () => Object.values(synth().findResources('AWS::IAM::Role'));
  const boundaryDenies = () => Object.values(synth().findResources('AWS::IAM::ManagedPolicy'))
    .flatMap((m) => m.Properties.PolicyDocument.Statement)
    .filter((s) => s.Effect === 'Deny')
    .flatMap((s) => s.Action);

  test('carries a permissions boundary', () => {
    const r = roles().find((x) => x.Properties.RoleName === 'FipResponderRole');
    assert.ok(r, 'FipResponderRole not found');
    assert.ok(
      r.Properties.PermissionsBoundary,
      '\u00a76.7 requires the responder be unable to escalate even if its own policy ' +
      'is later edited by someone with iam:PutRolePolicy in the member account.'
    );
  });

  test('the boundary denies privilege escalation', () => {
    const d = boundaryDenies();
    for (const a of ['iam:*', 'organizations:*', 'account:*']) {
      assert.ok(d.includes(a), `boundary must explicitly deny ${a}`);
    }
  });

  test('the boundary denies destroying evidence or hosts', () => {
    const d = boundaryDenies();
    for (const a of DELIBERATELY_EXCLUDED) {
      assert.ok(d.includes(a),
        `${a} must be denied by the boundary. FIP acquires and contains; it must ` +
        `never terminate a host or delete evidence.`);
    }
  });

  test('never grants terminate or snapshot deletion in any role policy', () => {
    const actions = sids(synth())
      .flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
    for (const f of ['ec2:TerminateInstances', 'ec2:DeleteSnapshot']) {
      assert.ok(!actions.includes(f),
        `${f} appears in a role policy. Purge is \u00a76.11 (dual authorization, separate ` +
        `path); terminating hosts is the customer's action, not FIP's.`);
    }
  });

  test('destructive statements are scoped by the case tag', () => {
    for (const sid of ['HashAndTransferTaggedEvidence', 'ContainTaggedInstances']) {
      const st = sids(synth()).find((s) => s.Sid === sid);
      assert.ok(st, `statement ${sid} missing`);
      assert.ok(st.Condition?.StringLike?.[`aws:ResourceTag/${CASE_TAG}`] !== undefined,
        `${sid} must be scoped by aws:ResourceTag/${CASE_TAG}`);
    }
  });

  test('snapshots must be born tagged', () => {
    const st = sids(synth()).find((s) => s.Sid === 'CreateTaggedSnapshots');
    assert.ok(st.Condition?.StringLike?.[`aws:RequestTag/${CASE_TAG}`] !== undefined,
      'snapshot creation must require a case tag at request time — that is what makes ' +
      'every later statement scopeable.');
  });

  // Regression test for a bug found by walking a real acquisition by hand.
  // ec2:CreateSnapshots is authorized separately against the
  // instance, each volume, and each created snapshot. aws:RequestTag exists ONLY
  // in the created-snapshot evaluations, so requiring it on the source resources
  // denies the whole call before a snapshot is ever considered. Policy simulation
  // does not model multi-resource actions and did not catch this.
  test('source-resource acquisition is scoped by ResourceTag, never RequestTag', () => {
    const st = sids(synth()).find((s) => s.Sid === 'AcquireFromTaggedSources');
    assert.ok(st, 'AcquireFromTaggedSources statement missing');

    const res = Array.isArray(st.Resource) ? st.Resource : [st.Resource];
    const flat = JSON.stringify(res);
    assert.ok(flat.includes('instance/*') && flat.includes('volume/*'),
      'source statement must target the instance and volume ARNs');

    assert.ok(st.Condition?.StringLike?.[`aws:ResourceTag/${CASE_TAG}`] !== undefined,
      'source resources must be scoped by aws:ResourceTag — they already carry the tag');
    assert.strictEqual(
      st.Condition?.StringLike?.[`aws:RequestTag/${CASE_TAG}`], undefined,
      'aws:RequestTag does not exist when CreateSnapshots is evaluated against the ' +
      'instance or a volume. Requiring it here denies every acquisition.');
  });

  test('created-snapshot statement does not target source resources', () => {
    const st = sids(synth()).find((s) => s.Sid === 'CreateTaggedSnapshots');
    const flat = JSON.stringify(Array.isArray(st.Resource) ? st.Resource : [st.Resource]);
    assert.ok(flat.includes('snapshot/*'), 'must target snapshot ARNs');
    assert.ok(!flat.includes('instance/*') && !flat.includes('volume/*'),
      'the RequestTag-scoped statement must not cover source resources, or it ' +
      'reintroduces the same denial.');
  });

  test('tagging is limited to fip: keys and the product tag', () => {
    const st = sids(synth()).find((s) => s.Sid === 'TagFipArtifactsOnly');
    assert.deepStrictEqual(
      st.Condition?.['ForAllValues:StringLike']?.['aws:TagKeys'], ['fip:*', 'application'],
      'CreateTags cannot be scoped by the tag it is about to set, so it is scoped by ' +
      'tag KEY — this role must never rewrite anyone else\'s tags.');
    assert.deepStrictEqual(
      st.Condition?.StringEqualsIfExists, { 'aws:RequestTag/application': 'fipv2' },
      'the product tag may carry only FIP\'s own value, or the role could relabel ' +
      'a customer resource as ours and bring it into reach of a cleanup.');
  });

  test('every resource the stack creates carries the product tags', () => {
    const t = synth();
    const role = Object.values(t.findResources('AWS::IAM::Role'))
      .find((x) => x.Properties.RoleName === 'FipInventoryRole');
    const tags = Object.fromEntries(role.Properties.Tags.map((x) => [x.Key, x.Value]));
    assert.deepStrictEqual(
      { application: tags.application, class: tags['fip:class'], component: tags['fip:component'] },
      { application: 'fipv2', class: 'infrastructure', component: 'member' });
  });

  test('responder is gated behind the DeployResponderRole condition', () => {
    const t = synth();
    t.hasParameter('DeployResponderRole', { AllowedValues: ['Yes', 'No'] });
    const r = Object.values(t.findResources('AWS::IAM::Role'))
      .find((x) => x.Properties.RoleName === 'FipResponderRole');
    assert.strictEqual(r.Condition, 'ResponderEnabled',
      'responder must be conditional so inventory can land alone at retainer signing.');
  });

  test('inventory stays unconditional', () => {
    const inv = Object.values(synth().findResources('AWS::IAM::Role'))
      .find((x) => x.Properties.RoleName === 'FipInventoryRole');
    assert.strictEqual(inv.Condition, undefined,
      'inventory is the baseline capability and must deploy unconditionally.');
  });
});


describe('isolation security group', () => {
  // Same multi-resource trap as ec2:CreateSnapshots: CreateSecurityGroup is
  // authorized against the VPC it is created in AND the group being created.
  // aws:RequestTag exists only for the latter.
  test('VPC-side creation carries no RequestTag condition', () => {
    const st = sids(synth()).find((s) => s.Sid === 'CreateIsolationSgInAnyVpc');
    assert.ok(st, 'CreateIsolationSgInAnyVpc missing');
    assert.ok(JSON.stringify(st.Resource).includes('vpc/*'), 'must target the VPC ARN');
    assert.strictEqual(st.Condition, undefined,
      'requiring aws:RequestTag on the VPC evaluation denies every creation — ' +
      'the same bug that broke CreateSnapshots on 2026-09-18');
  });

  test('group-side creation must be born tagged fip:isolation', () => {
    const st = sids(synth()).find((s) => s.Sid === 'CreateIsolationSgBornTagged');
    assert.ok(JSON.stringify(st.Resource).includes('security-group/*'));
    assert.ok(st.Condition?.StringLike?.[`aws:RequestTag/${ISOLATION_TAG}`] !== undefined,
      'the group must be born tagged, which is what scopes rule removal afterwards');
  });

  test('rule removal is confined to FIP’s own isolation groups', () => {
    const st = sids(synth()).find((s) => s.Sid === 'StripRulesFromOwnIsolationSg');
    assert.ok(st.Condition?.StringLike?.[`aws:ResourceTag/${ISOLATION_TAG}`] !== undefined,
      'this role must never be able to strip rules from a customer security group');
  });

  test('applying isolation is scoped to interfaces this case tagged', () => {
    const st = sids(synth()).find((s) => s.Sid === 'ApplyIsolationToTaggedInterfaces');
    assert.ok(st.Condition?.StringLike?.[`aws:ResourceTag/${CASE_TAG}`] !== undefined);
    assert.ok(JSON.stringify(st.Resource).includes('network-interface/*'));
  });

  test('CreateSecurityGroup is no longer denied by the boundary', () => {
    const denies = Object.values(synth().findResources('AWS::IAM::ManagedPolicy'))
      .flatMap((m) => m.Properties.PolicyDocument.Statement)
      .filter((s) => s.Effect === 'Deny').flatMap((s) => s.Action);
    assert.ok(!denies.includes('ec2:CreateSecurityGroup'),
      'the boundary denied what the role now needs — granting and denying the ' +
      'same action silently produces no capability at all');
  });

  test('terminate and snapshot deletion are STILL denied', () => {
    const denies = Object.values(synth().findResources('AWS::IAM::ManagedPolicy'))
      .flatMap((m) => m.Properties.PolicyDocument.Statement)
      .filter((s) => s.Effect === 'Deny').flatMap((s) => s.Action);
    for (const a of ['ec2:TerminateInstances', 'ec2:DeleteSnapshot']) {
      assert.ok(denies.includes(a), `${a} must remain denied`);
    }
  });
});

describe('FipRestorePolicy (fip restore)', () => {
  const restorePolicy = () => Object.values(synth().findResources('AWS::IAM::Policy'))
    .find((p) => p.Properties.PolicyName === 'FipRestorePolicy');

  test('is deployed only when the responder is and AllowRestore is Yes', () => {
    const t = synth();
    const p = restorePolicy();
    assert.ok(p, 'FipRestorePolicy missing');
    assert.strictEqual(p.Condition, 'RestoreEnabled');
    const cond = t.toJSON().Conditions.RestoreEnabled['Fn::And'];
    assert.ok(JSON.stringify(cond).includes('ResponderEnabled'));
    assert.ok(JSON.stringify(cond).includes('AllowRestore'));
    assert.strictEqual(t.toJSON().Parameters.AllowRestore.Default, 'Yes');
  });

  test('the untagged-group allowance covers security groups and nothing else', () => {
    const st = restorePolicy().Properties.PolicyDocument.Statement
      .find((s) => s.Sid === 'AttachOriginalGroupsOnRestore');
    assert.deepStrictEqual([].concat(st.Action), ['ec2:ModifyNetworkInterfaceAttribute']);
    const res = JSON.stringify(st.Resource);
    assert.ok(res.includes(':security-group/*'), res);
    assert.ok(!res.includes('network-interface') && !res.includes('instance/'),
      'interfaces and instances must still need fip:case-id, via the isolation statement');
  });

  test('tag deletion is confined to fip:original-sgs on tagged interfaces', () => {
    const st = restorePolicy().Properties.PolicyDocument.Statement
      .find((s) => s.Sid === 'ClearOriginalGroupsTagOnly');
    assert.deepStrictEqual([].concat(st.Action), ['ec2:DeleteTags']);
    assert.ok(st.Condition.StringLike[`aws:ResourceTag/${CASE_TAG}`] !== undefined);
    assert.deepStrictEqual(st.Condition['ForAllValues:StringEquals']['aws:TagKeys'],
      [ORIGINAL_SG_TAG]);
    // Without this, DeleteTags with no keys (which deletes every tag) passes
    // the ForAllValues test vacuously.
    assert.strictEqual(st.Condition.Null['aws:TagKeys'], 'false');
  });

  test('the boundary admits DeleteTags, or the policy would grant nothing', () => {
    const allow = Object.values(synth().findResources('AWS::IAM::ManagedPolicy'))
      .flatMap((m) => m.Properties.PolicyDocument.Statement)
      .find((s) => s.Sid === 'CeilingAllow');
    assert.ok([].concat(allow.Action).includes('ec2:DeleteTags'));
  });
});
