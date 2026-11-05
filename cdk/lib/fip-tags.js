/**
 * The tags FIP puts on what it creates (manual §11).
 *
 *   application     = fipv2           everything FIP creates or launches
 *   fip:class       = infrastructure  the stacks and what they contain
 *                   | evidence        snapshots from a real case
 *                   | test            test instances, and evidence from them
 *   fip:component   = core | orchestrator | member | analysis
 *   fip:environment = test | production      set at deploy time, not here
 *
 * fip:class is the one a cleanup decides by: `fip cleanup` removes only
 * `test`, and nothing ever sweeps `evidence`.
 *
 * Only the tags that are the same in every installation are applied here,
 * because they end up in the committed member template. fip:environment and
 * any tags the customer adds are stack tags, passed by `fip deploy`.
 *
 * The customer's own instance is never tagged application=fipv2. A contained
 * host carries only fip:case-id, so no sweep by product tag can reach it.
 *
 * The member-action Lambda repeats these names: it is packaged on its own and
 * cannot require this file.
 */

const { Tags } = require('aws-cdk-lib');

const APPLICATION_TAG = 'application';
const APPLICATION = 'fipv2';
const CLASS_TAG = 'fip:class';
const COMPONENT_TAG = 'fip:component';
const ENVIRONMENT_TAG = 'fip:environment';

function tagStack(stack, component) {
  Tags.of(stack).add(APPLICATION_TAG, APPLICATION);
  Tags.of(stack).add(CLASS_TAG, 'infrastructure');
  Tags.of(stack).add(COMPONENT_TAG, component);
}

module.exports = {
  APPLICATION_TAG, APPLICATION, CLASS_TAG, COMPONENT_TAG, ENVIRONMENT_TAG, tagStack,
};
