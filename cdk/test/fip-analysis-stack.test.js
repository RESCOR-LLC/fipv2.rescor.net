/**
 * Assertions on the decisions, not on CDK.
 *
 * This file exists to stop a jump-host tier growing here: bastions in public
 * subnets, an SSH private key passed as a CloudFormation parameter, or
 * SSH/RDP ingress behind a CIDR allowlist. Every test here guards one of the
 * properties that rule those out, and each guards against an edit that
 * would look entirely reasonable in review:
 *
 *   "add a NAT gateway so we can yum update"      -> breaks the egress control
 *   "add an ingress rule so I can RDP in"          -> rebuilds the bastion
 *   "add a key pair, just in case SSM is down"     -> rebuilds the key handling
 *
 * The egress rule on the workstation is deliberately open, which is only safe
 * BECAUSE there is no route off the VPC. So the route assertions are not
 * belt-and-braces — they are the actual control.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');
const { FipAnalysisStack } = require('../lib/fip-analysis-stack');

const EVIDENCE = '111111111111';

function synth(props = {}) {
  const app = new App();
  const stack = new FipAnalysisStack(app, 'TestAnalysis', {
    // Account-agnostic on purpose: an env-specific stack with a VPC forces a
    // context lookup for availability zones, which needs credentials in the
    // target account at synth time. The analysis account may belong to a
    // third-party examiner, so that cannot be required.
    env: { region: 'us-east-1' },
    evidenceAccountId: EVIDENCE,
    ...props,
  });
  return Template.fromStack(stack);
}

describe('no bastion — a jump-host tier must not grow here', () => {
  test('there is no internet gateway', () => {
    synth().resourceCountIs('AWS::EC2::InternetGateway', 0);
    synth().resourceCountIs('AWS::EC2::VPCGatewayAttachment', 0);
  });

  test('there is no NAT gateway and no elastic IP', () => {
    synth().resourceCountIs('AWS::EC2::NatGateway', 0);
    synth().resourceCountIs('AWS::EC2::EIP', 0);
  });

  test('there is NO ROUTE off the VPC at all', () => {
    const routes = synth().findResources('AWS::EC2::Route');
    assert.deepStrictEqual(
      Object.keys(routes), [],
      'The workstation security group allows all egress, and that is only safe ' +
      'because no route exists to egress along. A route here silently converts ' +
      'an open egress rule from harmless into a path out for whatever is on the ' +
      'disk image being examined.',
    );
  });

  test('no subnet assigns public IPs', () => {
    const subnets = synth().findResources('AWS::EC2::Subnet');
    assert.ok(Object.keys(subnets).length > 0, 'expected subnets');
    for (const [name, res] of Object.entries(subnets)) {
      assert.notStrictEqual(
        res.Properties.MapPublicIpOnLaunch, true,
        `${name} assigns public IPs on launch`,
      );
    }
  });

  test('the workstation security group has NO ingress rules', () => {
    const groups = synth().findResources('AWS::EC2::SecurityGroup');
    const workstation = Object.entries(groups).find(
      ([, res]) => /Examiner workstation/.test(res.Properties.GroupDescription ?? ''),
    );
    assert.ok(workstation, 'expected a workstation security group');
    const ingress = workstation[1].Properties.SecurityGroupIngress;
    assert.ok(
      ingress === undefined || ingress.length === 0,
      'Session Manager is outbound-initiated: the agent dials the endpoints and ' +
      'nothing dials in. An ingress rule here is a bastion by another name — ' +
      'a CIDR allowlist in front of SSH or RDP is still an open door.',
    );
  });

  test('no separate ingress resources sneak a rule in', () => {
    synth().resourceCountIs('AWS::EC2::SecurityGroupIngress', 0);
  });

  test('the workstation has NO key pair', () => {
    const instances = synth().findResources('AWS::EC2::Instance');
    assert.ok(Object.keys(instances).length > 0, 'expected an instance');
    for (const [name, res] of Object.entries(instances)) {
      assert.ok(
        !('KeyName' in res.Properties),
        `${name} declares a KeyName. There is no SSH listener to use it on, and ` +
        `taking a PRIVATE key as a CloudFormation parameter puts PEM content in ` +
        `template history. No key pair at all is the fix.`,
      );
    }
  });

  test('no CloudFormation parameter ever carries key material', () => {
    const params = synth().toJSON().Parameters ?? {};
    for (const name of Object.keys(params)) {
      assert.ok(
        !/(^|[^a-z])(key|ssh|secret|password|pem)/i.test(name),
        `parameter ${name} looks like key material. Key material in a parameter ` +
        `lands in template and stack history, where NoEcho does not help.`,
      );
    }
  });
});

describe('Session Manager has what it needs', () => {
  test('all three required interface endpoints exist', () => {
    const endpoints = synth().findResources('AWS::EC2::VPCEndpoint');
    const names = Object.values(endpoints)
      .map((r) => JSON.stringify(r.Properties.ServiceName))
      .join(' ');
    for (const required of ['ssm', 'ssmmessages', 'ec2messages']) {
      assert.match(
        names, new RegExp(`\\.${required}"`),
        `the ${required} endpoint is missing. Omit any one of the three and ` +
        `sessions fail with an error that does not say which, so they are ` +
        `created and asserted together.`,
      );
    }
  });

  test('the workstation can reach the endpoints', () => {
    const groups = synth().findResources('AWS::EC2::SecurityGroup');
    const endpointSg = Object.values(groups).find(
      (res) => /SSM endpoints/.test(res.Properties.GroupDescription ?? ''),
    );
    assert.ok(endpointSg, 'expected an endpoint security group');
    const ingress = endpointSg.Properties.SecurityGroupIngress ?? [];
    assert.ok(
      ingress.some((r) => r.FromPort === 443 && r.ToPort === 443),
      'the endpoint group must accept HTTPS from inside the VPC',
    );
  });

  test('IMDSv2 is required on the workstation', () => {
    const profiles = synth().findResources('AWS::EC2::LaunchTemplate');
    const requiresV2 = Object.values(profiles).some((res) =>
      res.Properties?.LaunchTemplateData?.MetadataOptions?.HttpTokens === 'required');
    assert.ok(requiresV2, 'IMDSv2 must be required — IMDSv1 is an SSRF credential path');
  });
});

describe('the session is recorded, and the examiner cannot stop it', () => {
  test('a custom session document is used, not the account default', () => {
    synth().hasResourceProperties('AWS::SSM::Document', {
      DocumentType: 'Session',
      Name: 'FipForensicSession',
    });
  });

  test('sessions log to both S3 and CloudWatch, encrypted', () => {
    const docs = synth().findResources('AWS::SSM::Document');
    const doc = Object.values(docs)[0];
    const inputs = doc.Properties.Content.inputs;
    assert.ok(inputs.s3BucketName, 'S3 destination required');
    assert.ok(inputs.cloudWatchLogGroupName, 'CloudWatch destination required');
    assert.strictEqual(inputs.s3EncryptionEnabled, true);
    assert.strictEqual(inputs.cloudWatchEncryptionEnabled, true);
    assert.ok(inputs.kmsKeyId, 'the session channel itself must be KMS-encrypted');
  });

  test('the session log bucket has Object Lock enabled and nothing locked', () => {
    const buckets = synth().findResources('AWS::S3::Bucket');
    const sessionBucket = Object.entries(buckets).find(
      ([name]) => /^FipSessionLogs/.test(name))?.[1];
    assert.strictEqual(sessionBucket?.Properties.ObjectLockEnabled, true,
      'Object Lock must be ENABLED at creation on the session bucket');
    assert.ok(
      sessionBucket,
      'Object Lock must be ENABLED at creation: a transcript may become part of ' +
      'the record and Object Lock cannot be added to an existing bucket.',
    );
    assert.ok(
      !sessionBucket.Properties.ObjectLockConfiguration?.Rule,
      'no DEFAULT retention — enabling the capability must not lock anything, ' +
      'the same rule as the evidence bucket',
    );
  });

  test('the workstation CANNOT delete its own transcripts', () => {
    const policies = synth().findResources('AWS::IAM::Policy');
    for (const res of Object.values(policies)) {
      for (const st of res.Properties.PolicyDocument.Statement) {
        if (st.Effect === 'Deny') continue;
        for (const action of [].concat(st.Action ?? [])) {
          if (typeof action !== 'string') continue;
          assert.ok(
            !/^s3:Delete/i.test(action),
            `${action} is granted. The examiner holds a shell on the workstation and ` +
            `therefore its role, so any s3:Delete* on the session bucket lets them ` +
            `delete the transcript of the session they are in — strictly worse than ` +
            `a bastion's sshd log. CDK's grantWrite includes s3:DeleteObject*, which is why ` +
            `this grant is written out by hand instead.`,
          );
        }
      }
    }
  });

  test('the workstation can encrypt transcripts but not decrypt them', () => {
    const policies = synth().findResources('AWS::IAM::Policy');
    const workstationStatements = [];
    for (const [name, res] of Object.entries(policies)) {
      if (!/Workstation/i.test(name)) continue;
      workstationStatements.push(...res.Properties.PolicyDocument.Statement);
    }
    assert.ok(workstationStatements.length > 0, 'expected workstation policy statements');
    const onSessionKey = (st) => /FipSessionLogKey/.test(JSON.stringify(st.Resource ?? ''));
    const actions = workstationStatements
      .filter((st) => st.Effect !== 'Deny' && onSessionKey(st))
      .flatMap((st) => [].concat(st.Action ?? []))
      .filter((a) => typeof a === 'string');
    assert.ok(actions.some((a) => a === 'kms:Encrypt'), 'must be able to encrypt');
    assert.ok(
      !actions.includes('kms:Decrypt'),
      'kms:Decrypt on the session key is not needed to WRITE a transcript, and ' +
      'granting it would let the examiner read back other examiners\' sessions.',
    );
  });

  test('the workstation has termination protection', () => {
    const instances = synth().findResources('AWS::EC2::Instance');
    for (const [name, res] of Object.entries(instances)) {
      assert.strictEqual(
        res.Properties.DisableApiTermination, true,
        `${name} has no termination protection. Note for future edits: setting this ` +
        `with addPropertyOverride renders correctly but is INVISIBLE to cdk-nag, ` +
        `which reads the construct attribute — set the L1 property instead.`,
      );
    }
  });

  test('the endpoint group has exactly one literal ingress rule', () => {
    const groups = synth().findResources('AWS::EC2::SecurityGroup');
    const endpointSg = Object.values(groups).find(
      (res) => /SSM endpoints/.test(res.Properties.GroupDescription ?? ''));
    assert.ok(endpointSg, 'expected an endpoint security group');
    const ingress = endpointSg.Properties.SecurityGroupIngress ?? [];
    assert.strictEqual(
      ingress.length, 1,
      'Interface endpoints default to open: true, which adds a SECOND rule sourced ' +
      'from an Fn::GetAtt of the VPC CIDR. cdk-nag cannot resolve an intrinsic, so ' +
      'its open-ingress rule throws instead of evaluating — a check that silently ' +
      'does not run. Pass open: false and declare the rule literally.',
    );
    assert.strictEqual(
      typeof ingress[0].CidrIp, 'string',
      'the CIDR must be a literal so cdk-nag can actually evaluate it',
    );
    assert.notStrictEqual(ingress[0].CidrIp, '0.0.0.0/0');
  });

  test('the examiner is denied every way of altering the audit trail', () => {
    const policies = synth().findResources('AWS::IAM::Policy');
    const denies = [];
    for (const res of Object.values(policies)) {
      for (const st of res.Properties.PolicyDocument.Statement) {
        if (st.Effect === 'Deny') denies.push(...[].concat(st.Action ?? []));
      }
    }
    for (const action of [
      'ssm:UpdateDocument', 'ssm:UpdateDocumentDefaultVersion',
      's3:DeleteObjectVersion', 'logs:DeleteLogGroup', 'kms:ScheduleKeyDeletion',
    ]) {
      assert.ok(
        denies.includes(action),
        `${action} is not denied to the examiner. An examiner who can rewrite the ` +
        `session document, delete a transcript version or disable the log key can ` +
        `work unrecorded, which is worse than a bastion rather than better.`,
      );
    }
  });

  test('StartSession is pinned to one instance AND the logged document', () => {
    const policies = synth().findResources('AWS::IAM::Policy');
    let found = null;
    for (const res of Object.values(policies)) {
      for (const st of res.Properties.PolicyDocument.Statement) {
        if ([].concat(st.Action ?? []).includes('ssm:StartSession')) found = st;
      }
    }
    assert.ok(found, 'expected an ssm:StartSession grant');
    const resources = JSON.stringify(found.Resource);
    assert.match(
      resources, /instance\//,
      'must name the instance — the document alone would allow a session on any ' +
      'instance in the account',
    );
    assert.match(
      resources, /document\//,
      'must name the document — the instance alone would allow an UNLOGGED session ' +
      'using the account default document',
    );
  });
});

describe('it does not impose anything on the customer', () => {
  test('the account-level SSM-SessionManagerRunShell document is NOT overwritten', () => {
    const docs = synth().findResources('AWS::SSM::Document');
    for (const res of Object.values(docs)) {
      assert.notStrictEqual(
        res.Properties.Name, 'SSM-SessionManagerRunShell',
        'Overwriting the account default changes every unrelated session in the ' +
        'account and collides with a customer who already manages it. FIP does ' +
        'not override what the customer chooses.',
      );
    }
  });

  test('deploys with no examiner principals named', () => {
    assert.doesNotThrow(
      () => synth({ examinerPrincipalArns: [] }),
      'the workstation must be deployable before examiners are engaged — their ' +
      'ARNs are often not known until there is an incident',
    );
  });

  test('named examiner principals land in the trust policy', () => {
    const arn = 'arn:aws:iam::999988887777:role/OutsideExaminer';
    const roles = synth({ examinerPrincipalArns: [arn] })
      .findResources('AWS::IAM::Role');
    const trust = JSON.stringify(Object.values(roles).map((r) => r.Properties.AssumeRolePolicyDocument));
    assert.ok(
      trust.includes(arn),
      'A third-party examiner is outside the organization by definition, so the ' +
      'trust must name their ARN. aws:PrincipalOrgID cannot carry this boundary.',
    );
  });

  test('everything durable is retained, never deleted', () => {
    const template = synth().toJSON();
    for (const [name, res] of Object.entries(template.Resources)) {
      if (!['AWS::S3::Bucket', 'AWS::KMS::Key', 'AWS::Logs::LogGroup'].includes(res.Type)) continue;
      assert.strictEqual(
        res.DeletionPolicy, 'Retain',
        `${name} (${res.Type}) is not retained. Session transcripts and their key ` +
        `may be part of the record.`,
      );
    }
  });
});

describe('the examiner can use released evidence, and only use it', () => {
  function examinerActions() {
    const policies = synth().findResources('AWS::IAM::Policy');
    const allow = [];
    for (const [name, res] of Object.entries(policies)) {
      if (!/Examiner/i.test(name)) continue;
      for (const st of res.Properties.PolicyDocument.Statement) {
        if (st.Effect === 'Deny') continue;
        allow.push(...[].concat(st.Action ?? []));
      }
    }
    return allow.filter((a) => typeof a === 'string');
  }

  test('can turn a released snapshot into a mounted volume', () => {
    const actions = examinerActions();
    for (const needed of ['ec2:CreateVolume', 'ec2:AttachVolume', 'ec2:DescribeSnapshots']) {
      assert.ok(actions.includes(needed), `${needed} is required to examine evidence`);
    }
  });

  test('cannot destroy evidence', () => {
    const actions = examinerActions();
    for (const forbidden of ['ec2:DeleteSnapshot', 'ec2:DeleteVolume']) {
      assert.ok(
        !actions.includes(forbidden),
        `${forbidden} is granted. A snapshot share confers no delete, but this role ` +
        `must not request one either — an examiner is given evidence to read.`,
      );
    }
  });

  test('cannot manufacture something that looks like evidence', () => {
    const actions = examinerActions();
    for (const forbidden of ['ec2:CreateSnapshot', 'ec2:CreateSnapshots']) {
      assert.ok(
        !actions.includes(forbidden),
        `${forbidden} is granted. A snapshot taken in the analysis account has no ` +
        `provenance and no signed manifest, yet would sit alongside real evidence.`,
      );
    }
  });

  test('evidence work is pinned to this region', () => {
    const policies = synth().findResources('AWS::IAM::Policy');
    let volumeStatement = null;
    for (const [name, res] of Object.entries(policies)) {
      if (!/Examiner/i.test(name)) continue;
      for (const st of res.Properties.PolicyDocument.Statement) {
        if ([].concat(st.Action ?? []).includes('ec2:CreateVolume')) volumeStatement = st;
      }
    }
    assert.ok(volumeStatement, 'expected an ec2:CreateVolume grant');
    assert.ok(
      JSON.stringify(volumeStatement.Condition ?? {}).includes('aws:RequestedRegion'),
      'a volume created in another region would sit outside the flow logs, session ' +
      'transcripts and endpoint boundary this account establishes',
    );
  });
});

describe('results leave over the S3 endpoint, append-only', () => {
  function resultsBucket(t = synth()) {
    const found = Object.entries(t.findResources('AWS::S3::Bucket'))
      .find(([name]) => /^FipResults/.test(name));
    assert.ok(found, 'expected a results bucket');
    return found;
  }
  function statementsOf(t, rolePattern) {
    const out = [];
    for (const [name, res] of Object.entries(t.findResources('AWS::IAM::Policy'))) {
      if (rolePattern.test(name)) out.push(...res.Properties.PolicyDocument.Statement);
    }
    return out;
  }

  test('the results bucket has Object Lock, KMS, and nothing locked by default', () => {
    const [, bucket] = resultsBucket();
    assert.strictEqual(bucket.Properties.ObjectLockEnabled, true,
      'results may become part of the record; Object Lock cannot be added later');
    assert.ok(!bucket.Properties.ObjectLockConfiguration?.Rule, 'no default retention');
    const sse = bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0];
    assert.strictEqual(sse.ServerSideEncryptionByDefault.SSEAlgorithm, 'aws:kms');
    assert.match(JSON.stringify(sse), /FipResultsKey/,
      'results need their own key: a reader must not be able to decrypt transcripts');
  });

  test('writes are refused unless they come through the VPC S3 endpoint', () => {
    const t = synth();
    const [name] = resultsBucket(t);
    const policy = Object.values(t.findResources('AWS::S3::BucketPolicy'))
      .find((p) => JSON.stringify(p.Properties.Bucket).includes(name));
    assert.ok(policy, 'expected a results bucket policy');
    const deny = policy.Properties.PolicyDocument.Statement.find(
      (st) => st.Effect === 'Deny' && [].concat(st.Action).includes('s3:PutObject'));
    assert.ok(deny, 'expected a Deny on s3:PutObject');
    assert.match(JSON.stringify(deny.Condition), /aws:SourceVpce.*S3Endpoint/,
      'a result is only worth something if it came from the logged workstation');
  });

  test('the workstation can write results but not read or delete them', () => {
    const t = synth();
    const allow = statementsOf(t, /Workstation/).filter((st) => st.Effect !== 'Deny');
    const onResults = allow.filter((st) => /FipResults[0-9A-F]/.test(JSON.stringify(st.Resource)));
    const actions = onResults.flatMap((st) => [].concat(st.Action));
    assert.ok(actions.includes('s3:PutObject'), 'must be able to write results');
    for (const forbidden of ['s3:GetObject', 's3:DeleteObject', 's3:DeleteObjectVersion']) {
      assert.ok(!actions.includes(forbidden), `${forbidden} on results is granted`);
    }
  });

  test('the workstation\'s kms:Decrypt on the results key is confined to S3', () => {
    const decrypt = statementsOf(synth(), /Workstation/).filter(
      (st) => st.Effect !== 'Deny' && [].concat(st.Action).includes('kms:Decrypt'));
    for (const st of decrypt) {
      assert.match(JSON.stringify(st.Resource), /FipResultsKey/,
        'the only Decrypt the workstation holds is on the results key');
      assert.ok(st.Condition?.StringEquals?.['kms:ViaService'],
        'Decrypt must be confined to S3 assembling a multipart upload');
    }
  });

  test('readers read, and are denied every way of altering results', () => {
    const t = synth();
    const st = statementsOf(t, /ResultsReader/);
    const allow = st.filter((s) => s.Effect !== 'Deny').flatMap((s) => [].concat(s.Action));
    const deny = st.filter((s) => s.Effect === 'Deny').flatMap((s) => [].concat(s.Action));
    assert.ok(allow.includes('s3:GetObject'));
    assert.ok(allow.includes('kms:Decrypt'));
    for (const a of ['s3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion', 's3:BypassGovernanceRetention']) {
      assert.ok(!allow.includes(a), `${a} is granted to readers`);
      assert.ok(deny.includes(a), `${a} is not denied to readers`);
    }
  });

  test('named results readers land in the trust policy', () => {
    const arn = 'arn:aws:iam::999988887777:role/OutsideReader';
    const roles = synth({ resultsReaderPrincipalArns: [arn] }).findResources('AWS::IAM::Role');
    const reader = Object.entries(roles).find(([name]) => /ResultsReader/.test(name));
    assert.ok(reader, 'expected a results reader role');
    assert.ok(JSON.stringify(reader[1].Properties.AssumeRolePolicyDocument).includes(arn));
  });
});
