/**
 * FipOrchestratorStack — the acquisition control plane. Deploys to the
 * ORCHESTRATOR account, which holds no evidence and no customer data.
 *
 * Automates the member-side chain, proven first by hand: tag, snapshot, wait for completion, hash via
 * the EBS direct APIs, grant and share to the evidence account.
 *
 * ── Why the SDK calls go through a Lambda ─────────────────────────────
 * Step Functions can assume a cross-account role natively, but its Credentials
 * field carries a role ARN and nothing else — no sts:ExternalId. Our
 * FipResponderRole trust requires one, and weakening that to suit the
 * integration would give up the confused-deputy control for the
 * provider-operated deployment shape. So member-account calls go through
 * lambda/member-action, which assumes with the external ID.
 *
 * This is also the only place the scale requirements can live: idempotent
 * per-instance work, bounded retries with backoff, partial success recorded
 * rather than aborting a case.
 *
 * Manual: docs/MANUAL.md §9
 */

const { Stack, Duration, RemovalPolicy, CfnOutput } = require('aws-cdk-lib');
const iam = require('aws-cdk-lib/aws-iam');
const kms = require('aws-cdk-lib/aws-kms');
const lambda = require('aws-cdk-lib/aws-lambda');
const logs = require('aws-cdk-lib/aws-logs');
const sfn = require('aws-cdk-lib/aws-stepfunctions');
const tasks = require('aws-cdk-lib/aws-stepfunctions-tasks');
const { tagStack } = require('./fip-tags');

class FipOrchestratorStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    tagStack(this, 'orchestrator');  // application=fipv2 and fip:class (lib/fip-tags.js)

    const {
      evidenceAccountId, orgId = null, analysisAccountId = null,
      retention = { productionMode: false, mode: 'NONE', days: null },
    } = props;

    // ── Manifest signing key ───────────────────────────────────
    // Asymmetric so the signature is verifiable OUTSIDE AWS by anyone holding
    // the public key — which matters when the verifier is opposing counsel, or
    // a third-party examiner with no access to your CloudTrail.
    const signingKey = new kms.Key(this, 'FipManifestSigningKey', {
      alias: 'alias/fip-manifest-signing',
      description: 'FIP case manifest signing (ECC_NIST_P384, sign/verify only)',
      keySpec: kms.KeySpec.ECC_NIST_P384,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ── The one Lambda that touches member accounts ───────────────────
    const memberAction = new lambda.Function(this, 'FipMemberAction', {
      functionName: 'fip-member-action',
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda/member-action'),
      // Hashing streams every block of a snapshot. Generous but bounded; a
      // volume too large to hash inside 15 minutes needs the chunked design
      // noted in the README, not a bigger timeout.
      timeout: Duration.minutes(15),
      memorySize: 1024,
      environment: {
        FIP_EVIDENCE_ACCOUNT_ID: evidenceAccountId,
        FIP_EVIDENCE_BUCKET: `fip-evidence-${evidenceAccountId}-${Stack.of(this).region}`,
        FIP_CASE_TABLE: 'fip-cases',
        FIP_SIGNING_KEY_ALIAS: 'alias/fip-manifest-signing',
        FIP_EVIDENCE_KEY_ALIAS: 'alias/fip-evidence',
        // How the Lambda labels the evidence it creates (fip:class). In test
        // mode it is all `test`, which `fip cleanup` may delete.
        FIP_ENVIRONMENT: retention.productionMode ? 'production' : 'test',
        // Object Lock retention for every manifest and custody record, set
        // as each is written. NONE in test mode: nothing is locked.
        FIP_RETENTION_MODE: retention.mode,
        FIP_RETENTION_DAYS: retention.days === null ? '' : String(retention.days),
        // Optional, and absent is a supported state. The analysis account may
        // not exist yet, may be outside the organization, and may differ per
        // case — so the release action also accepts one per call, and
        // nothing in acquisition depends on this being set.
        ...(analysisAccountId ? { FIP_ANALYSIS_ACCOUNT_ID: analysisAccountId } : {}),
      },
      logGroup: new logs.LogGroup(this, 'FipMemberActionLogs', {
        logGroupName: '/aws/lambda/fip-member-action',
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN,
      }),
      description: 'Assumes FipResponderRole with external ID and performs one acquisition action',
    });

    // It may assume ONLY FipResponderRole, and only ever that role name.
    memberAction.addToRolePolicy(new iam.PolicyStatement({
      sid: 'AssumeMemberResponderRoleOnly',
      actions: ['sts:AssumeRole'],
      resources: [`arn:${Stack.of(this).partition}:iam::*:role/FipResponderRole`],
      ...(orgId ? { conditions: { StringEquals: { 'aws:ResourceOrgId': orgId } } } : {}),
    }));

    // The second credential path: into our own evidence account, to copy
    // snapshots in and write the manifest. ec2:CopySnapshot must be called in
    // the destination account, so this cannot be done with FipResponderRole.
    memberAction.addToRolePolicy(new iam.PolicyStatement({
      sid: 'AssumeEvidenceRole',
      actions: ['sts:AssumeRole'],
      resources: [`arn:${Stack.of(this).partition}:iam::${evidenceAccountId}:role/FipEvidenceRole`],
    }));

    // Signing happens HERE, in the orchestrator, not in the evidence account:
    // the orchestrator is the actor whose attestation the manifest carries,
    // and a same-account kms:Sign keeps the key out of the account that merely
    // stores the result.
    signingKey.grant(memberAction, 'kms:Sign', 'kms:GetPublicKey');

    // External IDs are issued by this account and read back per member account.
    memberAction.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadMemberExternalIds',
      actions: ['ssm:GetParameter'],
      resources: [
        `arn:${Stack.of(this).partition}:ssm:${this.region}:${this.account}:parameter/fip/member/*/external-id`,
      ],
    }));

    // ── State machine ─────────────────────────────────────────────────
    // Retry transient failures only. Retrying an AccessDenied or a malformed
    // request just burns time with backoff and fails anyway — and during an
    // incident the delay IS the cost. Permission and validation errors should
    // surface immediately so a human can fix the policy, not after three
    // exponential waits.
    const TRANSIENT_ONLY = [
      'Lambda.ServiceException', 'Lambda.AWSLambdaException',
      'Lambda.SdkClientException', 'Lambda.TooManyRequestsException',
      'States.Timeout', 'States.TaskFailed',
    ];
    const retryTransient = (task, attempts = 3, seconds = 3) => {
      task.addRetry({
        errors: TRANSIENT_ONLY,
        maxAttempts: attempts,
        interval: Duration.seconds(seconds),
        backoffRate: 2,
      });
      return task;
    };

    const tagTarget = new tasks.LambdaInvoke(this, 'TagTarget', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'tag',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
        // The whole input, so `incident` stays optional for a hand-run. The
        // Lambda returns it as $.target.incident (null when absent), which is
        // where the later states read it: that path always exists.
        request: sfn.JsonPath.objectAt('$'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.target',
    });
    retryTransient(tagTarget, 3, 2);

    // ── Containment ───────────────────────────────────────────────────
    // Always, and before acquisition. This is the "Isolation" in Forensic
    // Isolation Program: the instance's interfaces are moved to a
    // no-ingress/no-egress group and it is detached from its Auto Scaling
    // group so the ASG stops managing it.
    //
    // Contain-first stops exfiltration and lateral movement immediately, at
    // the risk that malware detecting containment wipes itself. With
    // volatile capture out of MVP scope there is nothing to lose by
    // containing first, so that is the default; the ordering becomes a
    // collectionPriority knob when memory capture lands.
    const contain = new tasks.LambdaInvoke(this, 'ContainInstance', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'contain',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
        // The whole input, so asgPolicy stays OPTIONAL. Naming
        // `$.asgPolicy` here would make a hand-run execution that omitted it
        // fail with States.Runtime; '$' always exists, and the Lambda
        // defaults it to prevent-replacement.
        request: sfn.JsonPath.objectAt('$'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.containment',
    });
    retryTransient(contain, 3, 3);

    // Stopping is optional and off by default. It is service-affecting and
    // loses instance-store data irrecoverably, so it is the caller's
    // explicit choice rather than something acquisition does on its own.
    const stopInstance = new tasks.LambdaInvoke(this, 'StopInstance', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'stop',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.stopped',
    });

    const createSnapshots = new tasks.LambdaInvoke(this, 'CreateSnapshots', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'snapshot',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
        incident: sfn.JsonPath.stringAt('$.target.incident'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.acquisition',
    });
    retryTransient(createSnapshots, 5, 5);

    // EBS direct APIs report SNAPSHOT_NOT_FOUND until the snapshot completes,
    // so hashing cannot be the first state after CreateSnapshots. Wait, then
    // poll.
    const waitForSnapshots = new sfn.Wait(this, 'WaitForSnapshots', {
      time: sfn.WaitTime.duration(Duration.seconds(20)),
    });

    const checkStatus = new tasks.LambdaInvoke(this, 'CheckSnapshotStatus', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'status',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        snapshots: sfn.JsonPath.listAt('$.acquisition.snapshots'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.snapshotStatus',
    });

    // Hashing is split into bounded ranges. One Lambda cannot hash a large
    // volume: measured ~0.4-0.6 GB/min against the EBS direct APIs, so the
    // 15-minute ceiling lands around 6-9 GB, and a 30 GiB Windows root hit
    // Sandbox.Timedout in testing. Each range re-lists from its own
    // StartingBlockIndex, so no block-token lifetime is assumed across
    // invocations, and the ranges combine into a documented Merkle root.
    const mkHashChain = (id, planAction, rangeAction) => {
      const plan = new tasks.LambdaInvoke(this, id + 'Plan', {
        lambdaFunction: memberAction,
        payload: sfn.TaskInput.fromObject({
          action: planAction,
          accountId: sfn.JsonPath.stringAt('$.accountId'),
          caseId: sfn.JsonPath.stringAt('$.caseId'),
          snapshotId: sfn.JsonPath.stringAt('$.snapshotId'),
        }),
        payloadResponseOnly: true,
        resultPath: '$.plan',
      });
      retryTransient(plan);

      const one = new tasks.LambdaInvoke(this, id + 'Range', {
        lambdaFunction: memberAction,
        payload: sfn.TaskInput.fromObject({
          action: rangeAction,
          accountId: sfn.JsonPath.stringAt('$.accountId'),
          caseId: sfn.JsonPath.stringAt('$.caseId'),
          snapshotId: sfn.JsonPath.stringAt('$.snapshotId'),
          start: sfn.JsonPath.numberAt('$.start'),
          end: sfn.JsonPath.numberAt('$.end'),
        }),
        payloadResponseOnly: true,
      });
      retryTransient(one, 3, 5);

      const ranges = new sfn.Map(this, id + 'Ranges', {
        itemsPath: '$.plan.ranges',
        maxConcurrency: 8,
        itemSelector: {
          'snapshotId.$': '$$.Map.Item.Value.snapshotId',
          'start.$': '$$.Map.Item.Value.start',
          'end.$': '$$.Map.Item.Value.end',
          'accountId.$': '$.accountId',
          'caseId.$': '$.caseId',
        },
        resultPath: '$.ranges',
      });
      ranges.itemProcessor(one);

      const combine = new tasks.LambdaInvoke(this, id + 'Combine', {
        lambdaFunction: memberAction,
        payload: sfn.TaskInput.fromObject({
          action: 'hashCombine',
          accountId: sfn.JsonPath.stringAt('$.accountId'),
          caseId: sfn.JsonPath.stringAt('$.caseId'),
          snapshotId: sfn.JsonPath.stringAt('$.snapshotId'),
          plan: sfn.JsonPath.objectAt('$.plan'),
          ranges: sfn.JsonPath.listAt('$.ranges'),
        }),
        payloadResponseOnly: true,
      });
      retryTransient(combine);

      return plan.next(ranges).next(combine);
    };

    const hashAll = new sfn.Map(this, 'HashSnapshots', {
      itemsPath: '$.acquisition.snapshots',
      maxConcurrency: 2,
      itemSelector: {
        'snapshotId.$': '$$.Map.Item.Value',
        'accountId.$': '$.accountId',
        'caseId.$': '$.caseId',
      },
      resultPath: '$.hashes',
    });
    hashAll.itemProcessor(mkHashChain('SourceHash', 'hashPlan', 'hashRange'));

    const copyToEvidence = new tasks.LambdaInvoke(this, 'CopyToEvidence', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'copy',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        snapshots: sfn.JsonPath.listAt('$.acquisition.snapshots'),
        incident: sfn.JsonPath.stringAt('$.target.incident'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.evidenceCopy',
    });
    retryTransient(copyToEvidence, 3, 5);

    const waitForCopy = new sfn.Wait(this, 'WaitForCopy', {
      time: sfn.WaitTime.duration(Duration.seconds(20)),
    });

    const checkCopy = new tasks.LambdaInvoke(this, 'CheckCopyStatus', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'copyStatus',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        copies: sfn.JsonPath.listAt('$.evidenceCopy.copies'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.copyStatus',
    });

    // Hash what is RETAINED. This is the hash of record; the earlier
    // hash of the source snapshot is a separate attestation and the two are
    // not expected to match.
    const hashCopies = new sfn.Map(this, 'HashEvidenceCopies', {
      itemsPath: '$.evidenceCopy.copies',
      maxConcurrency: 2,
      itemSelector: {
        'snapshotId.$': '$$.Map.Item.Value',
        'accountId.$': '$.accountId',
        'caseId.$': '$.caseId',
      },
      resultPath: '$.evidenceHashes',
    });
    hashCopies.itemProcessor(mkHashChain('CopyHash', 'copyHashPlan', 'copyHashRange'));

    const writeManifest = new tasks.LambdaInvoke(this, 'SignAndWriteManifest', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'manifest',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
        executionArn: sfn.JsonPath.stringAt('$$.Execution.Id'),
        target: sfn.JsonPath.objectAt('$.target'),
        containment: sfn.JsonPath.objectAt('$.containment'),
        acquisition: sfn.JsonPath.objectAt('$.acquisition'),
        hashes: sfn.JsonPath.listAt('$.hashes'),
        evidenceHashes: sfn.JsonPath.listAt('$.evidenceHashes'),
        copies: sfn.JsonPath.listAt('$.evidenceCopy.copies'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.manifest',
    });
    retryTransient(writeManifest, 3, 5);

    const copyFailed = new sfn.Fail(this, 'EvidenceCopyFailed', {
      cause: 'Evidence copy entered error state',
      error: 'FipCopyError',
    });

    const share = new tasks.LambdaInvoke(this, 'ShareToEvidence', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'share',
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        snapshots: sfn.JsonPath.listAt('$.acquisition.snapshots'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.transfer',
    });
    retryTransient(share, 3, 5);

    const failed = new sfn.Fail(this, 'AcquisitionFailed', {
      cause: 'Snapshot entered error state',
      error: 'FipSnapshotError',
    });

    // isPresent first. A Choice rule that evaluates a path which does not
    // exist raises States.Runtime and kills the execution, so a caller who
    // simply omitted stopInstance would have had the whole acquisition fail
    // on an optional field. FipCase always supplies it, but a hand-run
    // start-execution during an incident may not, and that is exactly when
    // the failure would be least welcome.
    const stopChoice = new sfn.Choice(this, 'StopRequested?')
      .when(
        sfn.Condition.and(
          sfn.Condition.isPresent('$.stopInstance'),
          sfn.Condition.booleanEquals('$.stopInstance', true),
        ),
        stopInstance.next(createSnapshots),
      )
      .otherwise(createSnapshots);

    const definition = tagTarget
      .next(contain)
      .next(stopChoice)
    createSnapshots
      .next(waitForSnapshots)
      .next(checkStatus)
      .next(new sfn.Choice(this, 'SnapshotsReady?')
        .when(sfn.Condition.booleanEquals('$.snapshotStatus.anyError', true), failed)
        .when(sfn.Condition.booleanEquals('$.snapshotStatus.allComplete', true),
          hashAll.next(share).next(copyToEvidence).next(waitForCopy).next(checkCopy)
            .next(new sfn.Choice(this, 'CopyReady?')
              .when(sfn.Condition.booleanEquals('$.copyStatus.anyError', true), copyFailed)
              .when(sfn.Condition.booleanEquals('$.copyStatus.allComplete', true),
                hashCopies.next(writeManifest).next(new sfn.Succeed(this, 'AcquisitionComplete')))
              .otherwise(waitForCopy)))
        .otherwise(waitForSnapshots));

    const stateMachine = new sfn.StateMachine(this, 'FipAcquisition', {
      stateMachineName: 'FipAcquisition',
      // Standard, not Express: Express loses execution history, and FIP makes
      // the execution history part of the acquisition record.
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: Duration.hours(6),
      tracingEnabled: true,
      logs: {
        destination: new logs.LogGroup(this, 'FipAcquisitionLogs', {
          logGroupName: '/aws/vendedlogs/states/FipAcquisition',
          retention: logs.RetentionDays.ONE_YEAR,
          removalPolicy: RemovalPolicy.RETAIN,
        }),
        level: sfn.LogLevel.ALL,
        includeExecutionData: true,
      },
    });

    // ── FipCase — the one execution a responder starts ────────────────
    //
    // FipAcquisition handles exactly one instance in one account. That is the
    // right unit of work, and the wrong unit of operation: an incident is
    // rarely one instance, and asking a responder at 3am to launch and then
    // track N executions by hand is where mistakes get made. FipCase is the
    // fan-out, so a case is one execution to start and one row to watch.
    //
    // Nested .sync executions rather than inlining the acquisition states:
    // each target keeps its own execution history, which FIP makes part of the
    // acquisition record, and a per-target history is what an examiner can
    // actually read.
    const caseOpen = new tasks.LambdaInvoke(this, 'OpenCase', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'caseOpen',
        // caseId and targets are referenced directly because a case without
        // either is meaningless — failing at the first state is correct.
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        targets: sfn.JsonPath.listAt('$.targets'),
        // The whole input, so the Lambda can read OPTIONAL fields. A path
        // reference to a field the caller omitted raises States.Runtime, so
        // `$.stopInstance` cannot be named here without making it mandatory.
        // '$' always exists.
        request: sfn.JsonPath.objectAt('$'),
        openedBy: sfn.JsonPath.stringAt('$$.Execution.Id'),
      }),
      payloadResponseOnly: true,
      // Defaults are resolved in the Lambda and read back from here. Step
      // Functions has no "default if absent" for a field, so normalizing in
      // code is the only place it can happen once rather than at every use.
      resultPath: '$.case',
    });
    retryTransient(caseOpen, 3, 2);

    const acquireTarget = new tasks.StepFunctionsStartExecution(this, 'AcquireTarget', {
      stateMachine,
      // RUN_JOB (.sync) so the Map iteration waits for the acquisition to
      // finish. Without it the case would report success the moment every
      // child was *started*.
      integrationPattern: sfn.IntegrationPattern.RUN_JOB,
      input: sfn.TaskInput.fromObject({
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        accountId: sfn.JsonPath.stringAt('$.accountId'),
        instanceId: sfn.JsonPath.stringAt('$.instanceId'),
        stopInstance: sfn.JsonPath.objectAt('$.stopInstance'),
        asgPolicy: sfn.JsonPath.stringAt('$.asgPolicy'),
        incident: sfn.JsonPath.stringAt('$.incident'),
      }),
      // No explicit execution name. A deterministic name would reject a
      // re-run of the same case id for 90 days with ExecutionAlreadyExists,
      // which an operator re-running a partially failed case would read as a
      // new failure. Duplicate acquisition is already handled downstream —
      // CreateSnapshots reuses an existing snapshot for the case and reports
      // `reused`.
      resultPath: '$.execution',
    });

    const targetAcquired = new sfn.Pass(this, 'TargetAcquired', {
      parameters: {
        ok: true,
        'accountId.$': '$.accountId',
        'instanceId.$': '$.instanceId',
        'executionArn.$': '$.execution.ExecutionArn',
      },
    });

    // The whole point of the catch: one target failing must not abort the
    // case. Evidence already collected from the other targets is kept,
    // and the failure is recorded against the case rather than lost in a
    // state machine error.
    const targetFailed = new sfn.Pass(this, 'TargetFailed', {
      parameters: {
        ok: false,
        'accountId.$': '$.accountId',
        'instanceId.$': '$.instanceId',
        'error.$': '$.failure.Error',
        'cause.$': '$.failure.Cause',
      },
    });
    acquireTarget.addCatch(targetFailed, { errors: ['States.ALL'], resultPath: '$.failure' });

    // Inline Map, not DistributedMap: a case is tens of targets at most, and
    // an inline Map keeps every child in one execution history. Concurrency
    // is capped because each target drives snapshot and hashing work of its
    // own, and an unbounded fan-out would simply move the bottleneck into
    // EBS and Lambda throttling.
    const targets = new sfn.Map(this, 'AcquireTargets', {
      itemsPath: '$.targets',
      maxConcurrency: 4,
      itemSelector: {
        'caseId.$': '$.caseId',
        'accountId.$': '$$.Map.Item.Value.accountId',
        'instanceId.$': '$$.Map.Item.Value.instanceId',
        'stopInstance.$': '$.case.stopInstance',
        'asgPolicy.$': '$.case.asgPolicy',
        // The incident case, as OpenCase checked and recorded it: null when
        // the run is standalone. Read from the normalized result, like the
        // two above, so an input that omitted it stays valid.
        'incident.$': '$.case.incident',
      },
      resultPath: '$.results',
    });
    targets.itemProcessor(acquireTarget.next(targetAcquired));

    const caseSummary = new tasks.LambdaInvoke(this, 'SummarizeCase', {
      lambdaFunction: memberAction,
      payload: sfn.TaskInput.fromObject({
        action: 'caseSummary',
        caseId: sfn.JsonPath.stringAt('$.caseId'),
        results: sfn.JsonPath.listAt('$.results'),
      }),
      payloadResponseOnly: true,
      resultPath: '$.summary',
    });
    retryTransient(caseSummary, 3, 3);

    // A case where NOTHING succeeded is a failure; a case where something did
    // is not. PARTIAL resolves to Succeed deliberately — the execution
    // finished and the evidence it gathered is real, and the per-target
    // failures are on the case row and in this execution's history. Failing
    // the whole case would invite someone to re-run it wholesale and
    // re-snapshot the targets that already worked.
    const caseComplete = new sfn.Succeed(this, 'CaseComplete');
    const caseFailed = new sfn.Fail(this, 'CaseFailed', {
      cause: 'No target in this case was acquired successfully',
      error: 'FipCaseFailed',
    });

    const caseDefinition = caseOpen
      .next(targets)
      .next(caseSummary)
      .next(new sfn.Choice(this, 'AnyTargetAcquired?')
        .when(sfn.Condition.numberGreaterThan('$.summary.succeeded', 0), caseComplete)
        .otherwise(caseFailed));

    const caseMachine = new sfn.StateMachine(this, 'FipCase', {
      stateMachineName: 'FipCase',
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromChainable(caseDefinition),
      // Longer than the child's 6h: the parent must outlive the slowest
      // target, and with maxConcurrency 4 a large case runs in waves.
      timeout: Duration.hours(24),
      tracingEnabled: true,
      logs: {
        destination: new logs.LogGroup(this, 'FipCaseLogs', {
          logGroupName: '/aws/vendedlogs/states/FipCase',
          retention: logs.RetentionDays.ONE_YEAR,
          removalPolicy: RemovalPolicy.RETAIN,
        }),
        level: sfn.LogLevel.ALL,
        includeExecutionData: true,
      },
    });

    new CfnOutput(this, 'CaseStateMachineArn', {
      value: caseMachine.stateMachineArn,
      description: 'Start HERE. Fans out over targets; one execution per case.',
    });
    new CfnOutput(this, 'StateMachineArn', {
      value: stateMachine.stateMachineArn,
      description: 'Single-target acquisition. FipCase invokes this per target.',
    });
    new CfnOutput(this, 'MemberActionFunction', { value: memberAction.functionName });
    new CfnOutput(this, 'ManifestSigningKeyArn', { value: signingKey.keyArn });

    this.stateMachine = stateMachine;
    this.caseMachine = caseMachine;
    this.memberAction = memberAction;
    this.signingKey = signingKey;
  }
}

module.exports = { FipOrchestratorStack };
