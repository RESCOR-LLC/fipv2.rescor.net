/**
 * FipAnalysisStack — where an examiner actually works. Deploys to the ANALYSIS
 * account, which MAY BE OUTSIDE YOUR ORGANIZATION: third-party forensic
 * examiners are granted access to it, and the holder may differ per case.
 *
 * ── No jump host ──────────────────────────────────────────────────────
 * The usual way to reach an analysis host is a bastion in a public subnet, an
 * SSH key, and SSH or RDP ingress behind a CIDR allowlist: a standing
 * internet-reachable host, a key to manage, and an allowlist as the only
 * control.
 *
 * None of that is needed. Session Manager reaches an instance that has NO
 * public IP, NO inbound rules and NO route to the internet, over three
 * interface endpoints. What replaces the bastion is an IAM permission, so
 * examiner access is governed by the same control plane as the rest of FIP
 * and logged to the same standard.
 *
 * Deliberately NOT a bastion, NOT a key pair, NOT an ingress rule. If you
 * find yourself adding any of the three, something else is wrong.
 *
 * ── A bastion is authentication; the real control is authorization ────
 * The thing that keeps evidence safe is that only named principals can reach
 * it. That is the evidence CMK key policy and the snapshot share, not a host
 * anyone has to log into. This stack provides the WORKSTATION; the evidence
 * delivery path into it is the next increment.
 *
 * ── Cost, stated plainly ──────────────────────────────────────────────
 * Three interface endpoints bill hourly whether or not anyone is working, and
 * so does the workstation. This stack is opt-in precisely because of that:
 * deploy it when you have something to analyze. Stopping the workstation
 * between engagements is expected and safe — Session Manager reconnects when
 * it starts again, with no key or address to re-establish.
 *
 * Manual: docs/MANUAL.md §10
 */

const { Stack, CfnOutput, RemovalPolicy, Duration, Tags } = require('aws-cdk-lib');
const ec2 = require('aws-cdk-lib/aws-ec2');
const iam = require('aws-cdk-lib/aws-iam');
const kms = require('aws-cdk-lib/aws-kms');
const s3 = require('aws-cdk-lib/aws-s3');
const logs = require('aws-cdk-lib/aws-logs');
const ssm = require('aws-cdk-lib/aws-ssm');
const { tagStack } = require('./fip-tags');

/** Instance type for the examiner workstation. Overridable; the default is
 *  sized for mounting and triaging a few volumes, not for carving at speed. */
const DEFAULT_INSTANCE_TYPE = 'm6i.xlarge';

/**
 * Stated explicitly rather than taking CDK's 10.0.0.0/16 default, for two
 * reasons. An unusual range is less likely to collide if this VPC is ever
 * peered with a customer's. And a literal CIDR can be used directly in the
 * endpoint ingress rule, where `vpc.vpcCidrBlock` resolves to an Fn::GetAtt
 * that cdk-nag cannot evaluate — so the rule that checks for 0.0.0.0/0
 * ingress silently fails to run rather than passing.
 */
const VPC_CIDR = '10.80.0.0/16';

class FipAnalysisStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    tagStack(this, 'analysis');  // application=fipv2 and fip:class (lib/fip-tags.js)

    const {
      evidenceAccountId,
      orgId = null,
      instanceType = DEFAULT_INSTANCE_TYPE,
      // Examiner principals. ARNs, because this account may be outside the
      // organization and held by a third party — aws:PrincipalOrgID cannot
      // carry the trust on that path. Empty is valid: deploy the
      // workstation first, name the examiners when you engage them.
      examinerPrincipalArns = [],
      // Who may READ examination results, from outside the VPC. ARNs for the
      // same reason as the examiners. Empty is valid: name them when the
      // results are wanted.
      resultsReaderPrincipalArns = [],
    } = props;

    // ── Network: private, and that is the whole design ────────────────
    // No public subnets, no internet gateway, no NAT. natGateways: 0 is not
    // a cost saving that happens to be secure; it is the control. There is
    // no route by which this workstation can reach the internet, so a disk
    // image being examined cannot phone home if something on it runs.
    const vpc = new ec2.Vpc(this, 'FipAnalysisVpc', {
      ipAddresses: ec2.IpAddresses.cidr(VPC_CIDR),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{
        name: 'Isolated',
        // PRIVATE_ISOLATED, not PRIVATE_WITH_EGRESS: egress would reintroduce
        // exactly the path we are removing.
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        cidrMask: 24,
      }],
      // An examiner needs to resolve the endpoint DNS names below.
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // Flow logs: an examiner workstation should be able to prove what it
    // talked to. With no internet route the answer should be "the endpoints
    // and nothing else", and this is what demonstrates it.
    const flowLogGroup = new logs.LogGroup(this, 'FipAnalysisFlowLogs', {
      logGroupName: '/fip/analysis/vpc-flow-logs',
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    vpc.addFlowLog('FlowLogs', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogGroup),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    // ── The three endpoints Session Manager needs, and no more ────────
    // ssm        — the control channel the agent registers on
    // ssmmessages— the actual session data plane
    // ec2messages— the agent's legacy message channel, still required
    //
    // Omit any one and the session fails with a message that does not say
    // which, so they are created together and named.
    // ASCII only in GroupDescription. CloudFormation validates it against
    // ^([a-z,A-Z,0-9,. _\-:/()#,@[\]+=&;{}!$*])*$ — an em dash fails the
    // pattern, and the failure arrives as a synth warning rather than an
    // error, so it would otherwise reach a deployment before anyone noticed.
    const endpointSecurityGroup = new ec2.SecurityGroup(this, 'FipEndpointSg', {
      vpc,
      description: 'HTTPS from inside the analysis VPC to the SSM endpoints',
      allowAllOutbound: false,
    });
    endpointSecurityGroup.addIngressRule(
      // The literal, not vpc.vpcCidrBlock — see VPC_CIDR above. An Fn::GetAtt
      // here makes cdk-nag's "no 0.0.0.0/0 ingress" rule throw instead of
      // evaluating, which is a worse outcome than either pass or fail.
      ec2.Peer.ipv4(VPC_CIDR),
      ec2.Port.tcp(443),
      'HTTPS from within the VPC only, never from outside it',
    );

    for (const [name, service] of [
      ['Ssm', ec2.InterfaceVpcEndpointAwsService.SSM],
      ['SsmMessages', ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES],
      ['Ec2Messages', ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES],
      // The session document streams to CloudWatch Logs and requires the
      // group to be encrypted. With no route to Logs the agent cannot check
      // that, and refuses every session as "encryption is not set up".
      ['Logs', ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
    ]) {
      vpc.addInterfaceEndpoint(`${name}Endpoint`, {
        service,
        privateDnsEnabled: true,
        securityGroups: [endpointSecurityGroup],
        subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
        // `open` DEFAULTS TO TRUE, which adds a second ingress rule sourced
        // from vpc.vpcCidrBlock — an Fn::GetAtt. The rule is harmless but the
        // Fn::GetAtt is not: cdk-nag's "no open ingress" check cannot resolve
        // an intrinsic, so it THROWS rather than evaluating, and the finding
        // arrives as a validation-failure warning instead of a pass. One
        // explicit literal rule, declared above, is the whole intent.
        open: false,
      });
    }

    // Session logs go to S3 and KMS is reached for the volume keys. Gateway
    // endpoints are free, so these cost nothing to add and failing to add
    // them is a confusing outage rather than a bill.
    const s3Endpoint = vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });
    vpc.addInterfaceEndpoint('KmsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.KMS,
      privateDnsEnabled: true,
      securityGroups: [endpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      open: false,
    });

    // ── Session audit trail ───────────────────────────────────────────
    // A bastion would produce sshd logs on a host the examiner controls.
    // This produces a keystroke-level transcript in a bucket the examiner
    // cannot delete from, encrypted under a key they do not administer.
    const sessionKey = new kms.Key(this, 'FipSessionLogKey', {
      alias: 'alias/fip-analysis-session-logs',
      description: 'Encrypts Session Manager transcripts for FIP analysis sessions',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // A SEPARATE key for the session channel. Session Manager encrypts the
    // channel under the document's kmsKeyId: the person starting the session
    // needs kms:GenerateDataKey on it and the instance needs kms:Decrypt.
    // Giving the workstation Decrypt on the transcript key would let an
    // examiner read back every other session's transcript, so the channel
    // gets its own key, which encrypts nothing at rest.
    const channelKey = new kms.Key(this, 'FipSessionChannelKey', {
      alias: 'alias/fip-analysis-session-channel',
      description: 'Encrypts the Session Manager channel for FIP analysis sessions (nothing at rest)',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // Access logs for the session log bucket. No Object Lock here: a locked
    // access-log bucket is a recursive dependency and a cost trap, and access
    // logs are not evidence. Same reasoning as the evidence bucket's.
    const sessionAccessLogs = new s3.Bucket(this, 'FipSessionAccessLogs', {
      bucketName: `fip-analysis-session-logs-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const sessionLogBucket = new s3.Bucket(this, 'FipSessionLogs', {
      bucketName: `fip-analysis-sessions-${this.account}-${this.region}`,
      serverAccessLogsBucket: sessionAccessLogs,
      serverAccessLogsPrefix: 'session-bucket-access/',
      // Object Lock enabled at creation, nothing locked by default — the
      // standing rule for every new FIP bucket. A session transcript may
      // become part of the record, and Object Lock cannot be added later.
      objectLockEnabled: true,
      versioned: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: sessionKey,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // The session document sets cloudWatchEncryptionEnabled, and Session
    // Manager refuses to start a session unless the log group really is
    // KMS-encrypted. CloudWatch Logs uses the key itself, so the key policy
    // must allow the service, confined to this one log group.
    const sessionLogGroupName = '/fip/analysis/sessions';
    sessionKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'CloudWatchLogsEncryptsSessionLogGroup',
      principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
      resources: ['*'],
      conditions: {
        ArnEquals: {
          'kms:EncryptionContext:aws:logs:arn':
            `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:${sessionLogGroupName}`,
        },
      },
    }));

    const sessionLogGroup = new logs.LogGroup(this, 'FipSessionLogGroup', {
      logGroupName: sessionLogGroupName,
      encryptionKey: sessionKey,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // A CUSTOM session document, not the account-level
    // SSM-SessionManagerRunShell. Overwriting the account default would
    // change how every unrelated session in this account behaves, which is
    // precisely the kind of imposition FIP avoids — and it would collide with
    // a customer who already manages that document. Examiners name this one:
    //
    //   aws ssm start-session --document-name FipForensicSession --target <id>
    //
    // Setting it as the account default is the customer's call, and the
    // manual says how.
    const sessionDocument = new ssm.CfnDocument(this, 'FipForensicSessionDocument', {
      name: 'FipForensicSession',
      documentType: 'Session',
      documentFormat: 'JSON',
      updateMethod: 'NewVersion',
      content: {
        schemaVersion: '1.0',
        description: 'FIP forensic analysis session — logged to S3 and CloudWatch, encrypted in transit',
        sessionType: 'Standard_Stream',
        inputs: {
          s3BucketName: sessionLogBucket.bucketName,
          s3KeyPrefix: 'sessions/',
          s3EncryptionEnabled: true,
          cloudWatchLogGroupName: sessionLogGroup.logGroupName,
          cloudWatchEncryptionEnabled: true,
          cloudWatchStreamingEnabled: true,
          // Encrypts the session channel itself, so the transcript is
          // protected in flight and not merely at rest. The channel key,
          // not the transcript key: see FipSessionChannelKey.
          kmsKeyId: channelKey.keyId,
          // No shell profile commands. Anything injected here would run
          // before the examiner's first keystroke and would not appear in
          // their transcript as something they did.
          runAsEnabled: false,
          idleSessionTimeout: '20',
        },
      },
    });

    // ── The workstation ───────────────────────────────────────────────
    // No key pair. Not "a key pair we generate safely" — none at all. There
    // is no SSH listener to use it on, and a key in CloudFormation would sit
    // in stack history.
    const workstationRole = new iam.Role(this, 'FipAnalysisWorkstationRole', {
      roleName: 'FipAnalysisWorkstation',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'Examiner workstation. Session Manager only; no inbound anything.',
      managedPolicies: [
        // The one managed policy FIP uses, and the reason it is acceptable:
        // FIP uses no managed policies on roles that reach INTO member
        // accounts. This role reaches nowhere — it lets the SSM agent on this
        // instance register and carry a session. It is also the policy AWS
        // documents for exactly this, and hand-rolling it would drift.
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    // NOT grantWrite. CDK's grantWrite expands to include s3:DeleteObject* —
    // which would let the examiner, who has a shell on this instance and
    // therefore its role, delete the transcript of the session they are in.
    // That is strictly worse than a bastion, not better. Append only.
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'WriteSessionTranscriptsAppendOnly',
      actions: [
        's3:PutObject',
        // Session Manager checks the bucket's encryption settings before it
        // will stream to S3, and fails opaquely without this.
        's3:GetEncryptionConfiguration',
      ],
      resources: [
        sessionLogBucket.bucketArn,
        `${sessionLogBucket.bucketArn}/sessions/*`,
      ],
    }));
    // Encrypt only. kms:Decrypt is not needed to WRITE a transcript, and the
    // examiner should not be able to read back other sessions.
    sessionKey.grant(
      workstationRole,
      'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey',
    );
    sessionLogGroup.grantWrite(workstationRole);
    // The instance's half of the channel encryption.
    channelKey.grant(workstationRole, 'kms:Decrypt');
    // The agent checks that the session log group is encrypted before it
    // starts a session, with DescribeLogGroups. Denied, it reports the group
    // as unencrypted and refuses the session. A list call: log-group:* only.
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ConfirmSessionLogGroupEncryption',
      actions: ['logs:DescribeLogGroups'],
      resources: [`arn:${this.partition}:logs:${this.region}:${this.account}:log-group:*`],
    }));

    const workstationSecurityGroup = new ec2.SecurityGroup(this, 'FipWorkstationSg', {
      vpc,
      description: 'Examiner workstation. NO ingress; Session Manager is outbound-initiated.',
      // NO INGRESS RULES ARE ADDED ANYWHERE IN THIS STACK. The agent dials
      // out to the endpoints; nothing dials in. A future edit that needs an
      // ingress rule here is reintroducing the bastion.
      //
      // Egress is open, and the reason is worth being explicit about rather
      // than appearing to be laziness: THE ROUTE TABLE IS THE CONTROL. These
      // subnets are PRIVATE_ISOLATED with natGateways: 0, so there is no
      // route to the internet to egress along — only the endpoints. Pinning
      // egress to the endpoint security group would also need the S3 gateway
      // endpoint's prefix list, which is not exposed as a resource attribute,
      // so the alternative is a lookup that can silently resolve to the wrong
      // thing. An honest open rule over a definitively closed route beats a
      // clever rule over a route nobody checked.
      //
      // The corollary, which matters more than the rule: IF ANYONE ADDS A NAT
      // GATEWAY OR AN INTERNET GATEWAY TO THIS VPC, THIS STOPS BEING SAFE.
      // test/fip-analysis-stack.test.js asserts neither exists.
      allowAllOutbound: true,
    });

    const workstation = new ec2.Instance(this, 'FipAnalysisWorkstation', {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      instanceType: new ec2.InstanceType(instanceType),
      // Resolved from the SSM public parameter at deploy time rather than a
      // pinned AMI id: a pinned id rots and is region-specific, and a stale
      // forensic workstation is a workstation missing tool updates.
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      role: workstationRole,
      securityGroup: workstationSecurityGroup,
      // No keyName. Intentional and load-bearing.
      requireImdsv2: true,
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(100, {
          encrypted: true,
          volumeType: ec2.EbsDeviceVolumeType.GP3,
          deleteOnTermination: true,
        }),
      }],
      detailedMonitoring: false,
      userData: ec2.UserData.custom([
        '#!/bin/bash',
        'set -euo pipefail',
        '# The SSM agent ships in AL2023; make sure it is running rather than',
        '# installing it, so this stays correct if the AMI changes.',
        'systemctl enable --now amazon-ssm-agent',
        '# Read-only forensic tooling. Deliberately minimal: what an examiner',
        '# needs is theirs to choose, and a long package list here is a',
        '# maintenance burden plus an opinion FIP has no business holding.',
        'dnf install -y --quiet sleuthkit xfsprogs || true',
        '# Never mount evidence read-write by accident.',
        'printf \'%s\\n\' "# FIP: mount evidence volumes read-only, e.g." \\',
        '  "#   mount -o ro,noexec,nodev,noload /dev/nvme1n1p1 /mnt/evidence" \\',
        '  > /etc/motd',
      ].join('\n')),
    });

    Tags.of(workstation).add('fip:role', 'analysis-workstation');

    // Termination protection. Not exposed by the L2 construct, so set on the
    // L1 PROPERTY rather than with addPropertyOverride. Both render the same
    // template, but an override is invisible to cdk-nag, which inspects the
    // construct attribute — so the override looked correct, deployed
    // correctly, and left AwsSolutions-EC29 failing with no way to tell that
    // the protection was actually on.
    //
    // An examiner mid-examination with evidence volumes attached is exactly
    // where an accidental terminate costs real work, and unlike the evidence
    // itself the workstation's local state is not reconstructible.
    workstation.instance.disableApiTermination = true;

    // ── Examiner access — an IAM permission, not a host ───────────────
    // This is the whole replacement for the jump host. An examiner holding
    // this role can open a session on the workstation and nothing else; they
    // cannot reach the evidence account, cannot alter the session log, and
    // cannot change the audit configuration.
    const examinerRole = new iam.Role(this, 'FipExaminerRole', {
      roleName: 'FipExaminer',
      description: 'Opens a logged Session Manager session on the analysis workstation. No other access.',
      assumedBy: examinerPrincipalArns.length
        ? new iam.CompositePrincipal(
          ...examinerPrincipalArns.map((arn) => new iam.ArnPrincipal(arn)),
        )
        // Self-trust placeholder: a role with no trusted principal cannot be
        // created, and guessing a principal would be worse. Name your
        // examiners with fip:examinerPrincipalArns, or edit the trust policy
        // when you engage them. Documented in the manual.
        : new iam.AccountPrincipal(this.account),
      maxSessionDuration: Duration.hours(8),
    });

    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'StartLoggedSessionOnWorkstationOnly',
      actions: ['ssm:StartSession'],
      // Pinned to this one instance AND this one document. Either alone is
      // insufficient: the instance alone would let an examiner start an
      // UNLOGGED session with the default document, and the document alone
      // would let them open a session on any instance in the account.
      resources: [
        `arn:${this.partition}:ec2:${this.region}:${this.account}:instance/${workstation.instanceId}`,
        `arn:${this.partition}:ssm:${this.region}:${this.account}:document/${sessionDocument.name}`,
      ],
    }));
    // The client's half of the channel encryption: without it the session
    // fails at the handshake. On the channel key only, never the transcript key.
    channelKey.grant(examinerRole, 'kms:GenerateDataKey');

    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ManageOwnSessionsOnly',
      actions: ['ssm:TerminateSession', 'ssm:ResumeSession'],
      // ${aws:username} is not available for assumed roles, so AWS scopes
      // these by the session id suffix instead. This is the documented form.
      resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:session/\${aws:userid}-*`],
    }));

    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'DescribeToFindTheWorkstation',
      actions: [
        'ec2:DescribeInstances',
        'ssm:DescribeInstanceInformation',
        'ssm:DescribeSessions',
        'ssm:GetConnectionStatus',
      ],
      // None of these support resource-level permissions.
      resources: ['*'],
    }));

    // Using released evidence. The evidence account shares a snapshot and
    // issues a KMS grant; these are the permissions needed on THIS side to
    // turn that into a mounted volume.
    //
    // Note what is NOT here: ec2:DeleteSnapshot (the examiner must not be able
    // to destroy evidence, and the share confers no delete anyway) and
    // ec2:CreateSnapshot (a new snapshot taken here would have no provenance
    // and no manifest, and would look like evidence).
    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'TurnReleasedEvidenceIntoAVolume',
      actions: [
        'ec2:CreateVolume',
        'ec2:AttachVolume',
        'ec2:DetachVolume',
        'ec2:DescribeVolumes',
        'ec2:DescribeSnapshots',
        'ec2:CreateTags',
      ],
      // Volumes created here do not exist yet, and the snapshots are owned by
      // the evidence account, so neither is scopeable by ARN at deploy time.
      resources: ['*'],
      conditions: {
        // Region-pinned at least: a volume created in another region would be
        // outside the audit boundary this account establishes.
        StringEquals: { 'aws:RequestedRegion': this.region },
      },
    }));

    // The KMS half of the same step. A volume made from a snapshot shared by
    // another account cannot stay under that account's key: EBS re-encrypts
    // it into this account's EBS key, calling ReEncryptFrom on the forensic
    // key as the examiner. The release grant allows it on the evidence side;
    // a cross-account key also needs it allowed here, on the caller's side.
    // Only through EC2, so the examiner cannot call KMS on evidence directly.
    // ReEncryptFrom moves ciphertext OUT of the forensic key, never into it.
    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadReleasedEvidenceKeyThroughEbs',
      actions: ['kms:Decrypt', 'kms:DescribeKey', 'kms:ReEncryptFrom'],
      resources: [`arn:${this.partition}:kms:${this.region}:${evidenceAccountId}:key/*`],
      conditions: {
        StringEquals: { 'kms:ViaService': `ec2.${this.region}.amazonaws.com` },
      },
    }));

    // An examiner must never be able to quietly stop being recorded.
    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'NeverAlterTheAuditTrail',
      effect: iam.Effect.DENY,
      actions: [
        'ssm:CreateDocument', 'ssm:UpdateDocument', 'ssm:DeleteDocument',
        'ssm:UpdateDocumentDefaultVersion',
        's3:DeleteObject', 's3:DeleteObjectVersion',
        's3:PutBucketLogging', 's3:PutLifecycleConfiguration',
        'logs:DeleteLogGroup', 'logs:DeleteLogStream', 'logs:PutRetentionPolicy',
        'kms:DisableKey', 'kms:ScheduleKeyDeletion',
      ],
      resources: ['*'],
    }));

    // ── Results out ───────────────────────────────────────────────────
    // The VPC has no route off it, so findings leave the same way the session
    // transcripts do: over the S3 gateway endpoint, into a bucket the examiner
    // can add to but not alter. Readers sit outside the VPC and only read.
    //
    // Deliberately NOT a results snapshot. The examiner role cannot create
    // snapshots (a snapshot made here would look like evidence and have no
    // manifest), and a results path must not reopen that.
    //
    // Its own key, not the session key: a results reader must be able to
    // decrypt results without being able to decrypt session transcripts.
    const resultsKey = new kms.Key(this, 'FipResultsKey', {
      alias: 'alias/fip-analysis-results',
      description: 'Encrypts examination results written from the FIP analysis workstation',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const resultsBucket = new s3.Bucket(this, 'FipResults', {
      bucketName: `fip-analysis-results-${this.account}-${this.region}`,
      serverAccessLogsBucket: sessionAccessLogs,
      serverAccessLogsPrefix: 'results-bucket-access/',
      // Object Lock enabled at creation, nothing locked by default: the
      // standing rule for every FIP bucket. Results may become part of the
      // record, and Object Lock cannot be added later. Versioning (required
      // by Object Lock) means an overwrite keeps the earlier version.
      objectLockEnabled: true,
      versioned: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: resultsKey,
      bucketKeyEnabled: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // Writes arrive ONLY through this VPC's S3 endpoint. A results object is
    // worth something because it came from the logged workstation; a write
    // from anywhere else, even by an administrator, would break that claim.
    resultsBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'WritesOnlyFromTheAnalysisVpc',
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject'],
      resources: [resultsBucket.arnForObjects('*')],
      conditions: { StringNotEquals: { 'aws:SourceVpce': s3Endpoint.vpcEndpointId } },
    }));

    // Append only, as with the transcripts: no delete, no read-back. The
    // examiner holds a shell on the workstation and therefore this role.
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'WriteResultsAppendOnly',
      actions: ['s3:PutObject'],
      resources: [resultsBucket.arnForObjects('results/*')],
    }));
    resultsKey.grant(workstationRole, 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey');
    // A multipart upload under SSE-KMS needs kms:Decrypt to assemble the
    // parts, and `aws s3 cp` switches to multipart above 8 MB. Confined to S3
    // acting on this bucket, and the role has no s3:GetObject here, so it
    // still cannot read a result back.
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AssembleMultipartResultsOnly',
      actions: ['kms:Decrypt'],
      resources: [resultsKey.keyArn],
      conditions: {
        StringEquals: { 'kms:ViaService': `s3.${this.region}.amazonaws.com` },
        // The bucket ARN with an S3 Bucket Key, the object ARN without one.
        StringLike: {
          'kms:EncryptionContext:aws:s3:arn': [
            resultsBucket.bucketArn, resultsBucket.arnForObjects('results/*'),
          ],
        },
      },
    }));

    const resultsReaderRole = new iam.Role(this, 'FipResultsReaderRole', {
      roleName: 'FipResultsReader',
      description: 'Reads examination results from outside the analysis VPC. Read only.',
      assumedBy: resultsReaderPrincipalArns.length
        ? new iam.CompositePrincipal(
          ...resultsReaderPrincipalArns.map((arn) => new iam.ArnPrincipal(arn)),
        )
        // Self-trust placeholder, as for the examiner role.
        : new iam.AccountPrincipal(this.account),
      maxSessionDuration: Duration.hours(1),
    });
    resultsReaderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadResults',
      actions: ['s3:GetObject', 's3:GetObjectVersion', 's3:GetObjectRetention', 's3:GetObjectLegalHold'],
      resources: [resultsBucket.arnForObjects('results/*')],
    }));
    resultsReaderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ListResults',
      actions: ['s3:ListBucket', 's3:ListBucketVersions'],
      resources: [resultsBucket.bucketArn],
    }));
    resultsKey.grantDecrypt(resultsReaderRole);
    resultsReaderRole.addToPolicy(new iam.PolicyStatement({
      sid: 'NeverAlterResults',
      effect: iam.Effect.DENY,
      actions: [
        's3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion',
        's3:PutObjectRetention', 's3:PutObjectLegalHold', 's3:BypassGovernanceRetention',
        's3:PutBucketPolicy', 's3:PutLifecycleConfiguration',
        'kms:DisableKey', 'kms:ScheduleKeyDeletion',
      ],
      resources: ['*'],
    }));

    // ── Tools in ──────────────────────────────────────────────────────
    // An examiner, often a third party, brings their own tools. The VPC has
    // no route out, so tools come in the way results go out: over the S3
    // endpoint. Two sources:
    //
    //   1. The Amazon Linux package repositories, which AWS serves from S3:
    //      `sudo dnf install <package>` works on the workstation as is.
    //   2. This bucket, for anything else (RPMs, wheels, static binaries).
    //      The examiner uploads from OUTSIDE the VPC; the workstation can
    //      only read it.
    //
    // Writes from inside the VPC are refused, even with someone else's
    // credentials, so the tools bucket can never become a second way out.
    // Versioned, with no delete for the examiner: what was brought in, and
    // when, stays on record.
    const toolsBucket = new s3.Bucket(this, 'FipTools', {
      bucketName: `fip-analysis-tools-${this.account}-${this.region}`,
      serverAccessLogsBucket: sessionAccessLogs,
      serverAccessLogsPrefix: 'tools-bucket-access/',
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    toolsBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'NoWritesFromTheAnalysisVpc',
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion'],
      resources: [toolsBucket.arnForObjects('*')],
      conditions: { StringEquals: { 'aws:SourceVpce': s3Endpoint.vpcEndpointId } },
    }));
    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BringToolsIn',
      actions: ['s3:PutObject', 's3:GetObject'],
      resources: [toolsBucket.arnForObjects('tools/*')],
    }));
    examinerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ListTools',
      actions: ['s3:ListBucket'],
      resources: [toolsBucket.bucketArn],
    }));
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadToolsOnly',
      actions: ['s3:GetObject'],
      resources: [toolsBucket.arnForObjects('tools/*')],
    }));
    workstationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ListToolsOnly',
      actions: ['s3:ListBucket'],
      resources: [toolsBucket.bucketArn],
    }));

    // ── What the S3 endpoint reaches ──────────────────────────────────
    // Without a policy a gateway endpoint reaches EVERY bucket in S3, so
    // anyone on the workstation holding credentials from elsewhere could
    // copy data to a bucket of their own. "No route off the VPC" would be
    // untrue. The endpoint reaches this account's buckets, and reads (only)
    // the AWS-owned buckets the operating system and the SSM agent need.
    s3Endpoint.addToPolicy(new iam.PolicyStatement({
      sid: 'ThisAccountsBucketsOnly',
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:*'],
      resources: ['*'],
      conditions: { StringEquals: { 'aws:ResourceAccount': this.account } },
    }));
    s3Endpoint.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadAwsOwnedPackageAndAgentBuckets',
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:GetObject'],
      resources: [
        // Amazon Linux 2023 package repositories (dnf).
        `arn:${this.partition}:s3:::al2023-repos-${this.region}-de612dc2/*`,
        // SSM agent updates and documents (AWS's documented list).
        `arn:${this.partition}:s3:::amazon-ssm-${this.region}/*`,
        `arn:${this.partition}:s3:::amazon-ssm-packages-${this.region}/*`,
        `arn:${this.partition}:s3:::aws-ssm-${this.region}/*`,
        `arn:${this.partition}:s3:::${this.region}-birdwatcher-prod/*`,
        `arn:${this.partition}:s3:::aws-ssm-document-attachments-${this.region}/*`,
        `arn:${this.partition}:s3:::patch-baseline-snapshot-${this.region}/*`,
      ],
    }));

    new CfnOutput(this, 'ToolsBucket', {
      value: toolsBucket.bucketName,
      description: 'Examiner uploads from outside: aws s3 cp <tool> s3://<this>/tools/. Workstation reads only.',
    });
    new CfnOutput(this, 'ResultsBucket', {
      value: resultsBucket.bucketName,
      description: 'Write from the workstation: aws s3 cp <file> s3://<this>/results/<case>/ --checksum-algorithm SHA256',
    });
    new CfnOutput(this, 'ResultsReaderRoleArn', { value: resultsReaderRole.roleArn });

    new CfnOutput(this, 'WorkstationInstanceId', {
      value: workstation.instanceId,
      description: 'Connect with: aws ssm start-session --document-name FipForensicSession --target <this>',
    });
    new CfnOutput(this, 'SessionDocumentName', { value: sessionDocument.name });
    new CfnOutput(this, 'SessionLogBucket', { value: sessionLogBucket.bucketName });
    new CfnOutput(this, 'ExaminerRoleArn', { value: examinerRole.roleArn });
    new CfnOutput(this, 'AnalysisVpcId', { value: vpc.vpcId });
    new CfnOutput(this, 'EvidenceAccountId', {
      value: evidenceAccountId,
      description: 'The account that will share evidence snapshots into this one.',
    });

    this.vpc = vpc;
    this.workstation = workstation;
    this.examinerRole = examinerRole;
    this.sessionLogBucket = sessionLogBucket;
    this.resultsBucket = resultsBucket;
    this.toolsBucket = toolsBucket;
    this.orgId = orgId;
  }
}

module.exports = { FipAnalysisStack, DEFAULT_INSTANCE_TYPE };
