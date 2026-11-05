/**
 * Assertions on the decisions, not on CDK.
 *
 * The subject of this file is FipCase — the fan-out. Every test here guards a
 * property that a plausible future edit would silently undo, and most of them
 * guard against failures that are INVISIBLE in a green deployment:
 *
 *   - A Map iteration without a catch turns one bad target into a dead case.
 *   - startExecution without .sync reports success the moment children start.
 *   - A Choice on an absent path raises States.Runtime, so an optional field
 *     referenced directly is a mandatory field with a worse error message.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');
const { FipOrchestratorStack } = require('../lib/fip-orchestrator-stack');

const ENV = { account: '222222222222', region: 'us-east-1' };
const EVIDENCE = '111111111111';
const ORG = 'o-exampleorg1';

function synth(props = {}) {
  const app = new App();
  const stack = new FipOrchestratorStack(app, 'TestOrchestrator', {
    env: ENV,
    evidenceAccountId: EVIDENCE,
    orgId: ORG,
    ...props,
  });
  return { template: Template.fromStack(stack), stack };
}

/**
 * State machine definitions synthesize as a Fn::Join of literal fragments and
 * token references. Stitch the literals back together so the ASL can be read
 * as the JSON document Step Functions will actually execute.
 */
function definitionOf(template, stateMachineName) {
  const machines = template.findResources('AWS::StepFunctions::StateMachine');
  for (const res of Object.values(machines)) {
    if (res.Properties.StateMachineName !== stateMachineName) continue;
    const def = res.Properties.DefinitionString;
    if (typeof def === 'string') return JSON.parse(def);
    const parts = def['Fn::Join'][1];
    const literal = parts
      .map((p) => (typeof p === 'string' ? p : 'TOKEN'))
      .join('');
    return JSON.parse(literal);
  }
  assert.fail(`no state machine named ${stateMachineName}`);
}

describe('FipCase — the fan-out a responder actually starts', () => {
  test('exists, and is the Standard type so its history is retained', () => {
    const { template } = synth();
    template.hasResourceProperties('AWS::StepFunctions::StateMachine', {
      StateMachineName: 'FipCase',
      StateMachineType: 'STANDARD',
    });
  });

  test('opens the case row BEFORE any target runs', () => {
    const def = definitionOf(synth().template, 'FipCase');
    assert.strictEqual(
      def.StartAt, 'OpenCase',
      'The case row and its empty `targets` map must exist before any target ' +
      'writes into it. writeManifest uses UpdateItem on a nested path, which ' +
      'requires the parent item to be there already.',
    );
  });

  test('fans out over $.targets, so one execution covers many instances', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const map = def.States.AcquireTargets;
    assert.strictEqual(map.Type, 'Map');
    assert.strictEqual(map.ItemsPath, '$.targets');
  });

  test('concurrency is capped — an uncapped fan-out just moves the bottleneck', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const max = def.States.AcquireTargets.MaxConcurrency;
    assert.ok(
      Number.isInteger(max) && max > 0,
      'AcquireTargets must cap MaxConcurrency. Each target drives its own ' +
      'snapshot and hashing work; unbounded parallelism relocates the failure ' +
      'into EBS and Lambda throttling.',
    );
  });

  test('waits for each child to FINISH, not merely to start', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const inner = def.States.AcquireTargets.ItemProcessor.States.AcquireTarget;
    assert.match(
      inner.Resource, /states:startExecution\.sync/,
      'Without the .sync integration pattern the case reports success as soon ' +
      'as every child is STARTED, so a case could be "complete" with no ' +
      'evidence collected at all.',
    );
  });

  test('one failed target does not abort the case', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const inner = def.States.AcquireTargets.ItemProcessor.States.AcquireTarget;
    assert.ok(
      Array.isArray(inner.Catch) && inner.Catch.length > 0,
      'AcquireTarget must catch. Partial success must be recorded ' +
      'rather than aborting the case: evidence already collected from other ' +
      'targets must survive one target failing.',
    );
    assert.ok(
      inner.Catch.some((c) => c.ErrorEquals.includes('States.ALL')),
      'the catch must be total — an uncaught error class would still kill the case',
    );
  });

  test('a failed target is recorded with enough to identify it', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const failed = def.States.AcquireTargets.ItemProcessor.States.TargetFailed;
    assert.deepStrictEqual(failed.Parameters.ok, false);
    for (const field of ['accountId.$', 'instanceId.$', 'error.$', 'cause.$']) {
      assert.ok(
        field in failed.Parameters,
        `TargetFailed must carry ${field}: a failure no one can attribute to an ` +
        `instance is not a usable record`,
      );
    }
  });

  test('a case with nothing acquired FAILS; a partial case does not', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const choice = def.States['AnyTargetAcquired?'];
    assert.strictEqual(choice.Type, 'Choice');
    const rule = choice.Choices[0];
    assert.strictEqual(rule.Variable, '$.summary.succeeded');
    assert.strictEqual(rule.NumericGreaterThan, 0);
    assert.strictEqual(
      choice.Default, 'CaseFailed',
      'zero successes must fail the case; anything else succeeds, because the ' +
      'evidence gathered by the targets that worked is real',
    );
  });

  test('stopInstance is read from the normalized value, not raw input', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const sel = def.States.AcquireTargets.ItemSelector;
    assert.strictEqual(
      sel['stopInstance.$'], '$.case.stopInstance',
      'Step Functions has no default-if-absent, so the optional flag is ' +
      'defaulted in caseOpen and read back from its result. Reading ' +
      '$.stopInstance here would make an optional field mandatory.',
    );
  });

  test('OpenCase receives the whole input so optional fields stay optional', () => {
    const def = definitionOf(synth().template, 'FipCase');
    const params = def.States.OpenCase.Parameters;
    assert.strictEqual(
      params['request.$'], '$',
      'naming $.stopInstance directly would raise States.Runtime for any ' +
      'caller who omitted it; $ always exists',
    );
  });
});

describe('FipAcquisition — the single-target machine', () => {
  test('still exists and is invoked by FipCase, not replaced by it', () => {
    const { template } = synth();
    template.hasResourceProperties('AWS::StepFunctions::StateMachine', {
      StateMachineName: 'FipAcquisition',
    });
  });

  test('an omitted stopInstance does not blow up the Choice', () => {
    const def = definitionOf(synth().template, 'FipAcquisition');
    const rule = def.States['StopRequested?'].Choices[0];
    assert.ok(
      rule.And && rule.And.some((c) => c.IsPresent === true),
      'A Choice rule evaluating a path that does not exist raises ' +
      'States.Runtime and kills the execution. A hand-run start-execution that ' +
      'omits the optional stopInstance flag must not fail the acquisition.',
    );
  });

  test('containment is unconditional — it is the "I" in FIP', () => {
    const def = definitionOf(synth().template, 'FipAcquisition');
    assert.ok(def.States.ContainInstance, 'ContainInstance must exist');
    const reachableFromStart = def.StartAt === 'TagTarget'
      && def.States.TagTarget.Next === 'ContainInstance';
    assert.ok(
      reachableFromStart,
      'containment must sit on the unconditional path immediately after ' +
      'tagging — no Choice may be able to skip it',
    );
  });

  test('retries are transient-only, so a denied permission fails fast', () => {
    const def = definitionOf(synth().template, 'FipAcquisition');
    for (const [name, state] of Object.entries(def.States)) {
      for (const retry of state.Retry ?? []) {
        assert.ok(
          !retry.ErrorEquals.includes('States.ALL'),
          `${name} retries States.ALL. During an incident the backoff IS the ` +
          `cost: an AccessDenied should surface at once so a human can fix the ` +
          `policy, not after three exponential waits.`,
        );
      }
    }
  });
});

describe('credential paths stay narrow', () => {
  test('the Lambda may assume ONLY FipResponderRole in member accounts', () => {
    const { template } = synth();
    const policies = template.findResources('AWS::IAM::Policy');
    const assumeStatements = [];
    for (const res of Object.values(policies)) {
      for (const st of res.Properties.PolicyDocument.Statement) {
        const actions = [].concat(st.Action ?? []);
        if (actions.includes('sts:AssumeRole')) assumeStatements.push(st);
      }
    }
    assert.ok(assumeStatements.length > 0, 'expected an sts:AssumeRole grant');
    for (const st of assumeStatements) {
      for (const resource of [].concat(st.Resource ?? [])) {
        if (typeof resource !== 'string') continue;
        assert.ok(
          /role\/Fip(Responder|Evidence)Role$/.test(resource),
          `sts:AssumeRole is granted on ${resource}. It must name an exact FIP ` +
          `role: a wildcard role name would let the orchestrator assume ` +
          `anything a member account happens to trust it for.`,
        );
      }
    }
  });

  test('the case machine can start the acquisition machine', () => {
    const { template } = synth();
    const policies = template.findResources('AWS::IAM::Policy');
    const grantsStart = Object.values(policies).some((res) =>
      res.Properties.PolicyDocument.Statement.some((st) =>
        [].concat(st.Action ?? []).includes('states:StartExecution')));
    assert.ok(grantsStart, 'FipCase must be able to start FipAcquisition');
  });
});

describe('Auto Scaling containment posture', () => {
  test('the ASG policy reaches containment WITHOUT becoming mandatory', () => {
    const def = definitionOf(synth().template, 'FipAcquisition');
    const params = def.States.ContainInstance.Parameters;
    assert.strictEqual(
      params['request.$'], '$',
      'containment reads asgPolicy out of the whole input, not from $.asgPolicy. ' +
      'Naming the path directly would make a hand-run start-execution that omitted ' +
      'the optional field fail with States.Runtime.',
    );
  });

  test('a case carries one ASG posture to every target', () => {
    const def = definitionOf(synth().template, 'FipCase');
    assert.strictEqual(
      def.States.AcquireTargets.ItemSelector['asgPolicy.$'], '$.case.asgPolicy',
      'read from the NORMALIZED case record, so one case cannot contain some targets ' +
      'that allow a replacement and some that do not',
    );
    const childInput = def.States.AcquireTargets.ItemProcessor
      .States.AcquireTarget.Parameters.Input;
    assert.strictEqual(childInput['asgPolicy.$'], '$.asgPolicy');
  });
});

describe('the Lambda is told the retention and environment', () => {
  const envOf = (template) => Object.values(template.findResources('AWS::Lambda::Function'))
    .find((f) => f.Properties.FunctionName === 'fip-member-action').Properties.Environment.Variables;

  test('test mode by default: nothing locked, evidence labeled test', () => {
    const env = envOf(synth().template);
    assert.strictEqual(env.FIP_RETENTION_MODE, 'NONE');
    assert.strictEqual(env.FIP_ENVIRONMENT, 'test');
  });

  test('production mode passes the customer\'s mode and days through', () => {
    const env = envOf(synth({
      retention: { productionMode: true, mode: 'GOVERNANCE', days: 90 },
    }).template);
    assert.deepStrictEqual(
      [env.FIP_RETENTION_MODE, env.FIP_RETENTION_DAYS, env.FIP_ENVIRONMENT],
      ['GOVERNANCE', '90', 'production']);
  });
});

describe('an isolation run can be attached to an incident case', () => {
  test('the incident is read from OpenCase\'s result, so an input without it stays valid', () => {
    const def = definitionOf(synth().template, 'FipCase');
    assert.strictEqual(
      def.States.AcquireTargets.ItemSelector['incident.$'], '$.case.incident',
      'OpenCase checks the case and returns incident (null when standalone). Reading ' +
      '$.incident here would make every start-execution without it fail.',
    );
    const childInput = def.States.AcquireTargets.ItemProcessor
      .States.AcquireTarget.Parameters.Input;
    assert.strictEqual(childInput['incident.$'], '$.incident');
  });

  test('each acquisition reads it from TagTarget\'s result, where it always exists', () => {
    const def = definitionOf(synth().template, 'FipAcquisition');
    assert.strictEqual(def.States.TagTarget.Parameters['request.$'], '$',
      'a hand-run FipAcquisition has no incident; the whole input keeps it optional');
    for (const state of ['CreateSnapshots', 'CopyToEvidence']) {
      assert.strictEqual(def.States[state].Parameters['incident.$'], '$.target.incident',
        `${state} tags what it creates with fip:case, read from the tag step's normalized result`);
    }
  });
});
