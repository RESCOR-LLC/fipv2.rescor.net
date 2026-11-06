/**
 * Whole-case release state and the close guard.
 *
 * Share state is replayed from custody entries, because a share is per
 * snapshot: a revoke removes the account whichever release added it, and
 * the state follows a member into whatever case holds it. The close guard
 * refuses on anything still contained, still shared, or unknown.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const load = () => import(path.join(__dirname, '..', 'lambda', 'member-action', 'case-log.mjs'));

const I1 = 'i-0aaaaaaaaaaaaaaaa';
const I2 = 'i-0bbbbbbbbbbbbbbbb';
const X = '333333333333';
const Y = '444444444444';
const rel = (account, instances) => ({ event: 'RELEASED_TO_ANALYSIS', analysisAccountId: account, instances });
const rev = (account, instances) => ({ event: 'REVOKED_FROM_ANALYSIS', analysisAccountId: account, instances });

describe('who can open each member\'s evidence', () => {
  test('a release of the whole run, from before cases, covers every target', async () => {
    const { shareState } = await load();
    assert.deepStrictEqual(shareState([rel(X, null)], [I1, I2]), { [I1]: [X], [I2]: [X] });
  });

  test('a case release covers only the members it names', async () => {
    const { shareState } = await load();
    assert.deepStrictEqual(shareState([rel(X, [I1])], [I1, I2]), { [I1]: [X], [I2]: [] });
  });

  test('a revoke removes the account whichever release added it', async () => {
    const { shareState } = await load();
    const s = shareState([rel(X, null), rel(Y, [I2]), rev(X, [I2])], [I1, I2]);
    assert.deepStrictEqual(s, { [I1]: [X], [I2]: [Y] },
      'the case revoke of I2 ends X\'s access to I2 even though a run-wide release granted it');
  });

  test('order matters: release after revoke is shared again', async () => {
    const { shareState } = await load();
    assert.deepStrictEqual(shareState([rel(X, [I1]), rev(X, [I1]), rel(X, [I1])], [I1]), { [I1]: [X] });
    assert.deepStrictEqual(shareState([rel(X, [I1]), rel(X, [I1]), rev(X, [I1])], [I1]), { [I1]: [] });
  });

  test('restore records and unknown entries do not change shares', async () => {
    const { shareState } = await load();
    assert.deepStrictEqual(shareState([{ event: 'RESTORED' }, rel(undefined, null)], [I1]), { [I1]: [] });
  });

  test('custody entries are read from the row, with and without instances', async () => {
    const { custodyOf } = await load();
    const row = { custody: { L: [
      { M: { event: { S: 'RELEASED_TO_ANALYSIS' }, analysisAccountId: { S: X } } },
      { M: { event: { S: 'REVOKED_FROM_ANALYSIS' }, analysisAccountId: { S: X }, instances: { SS: [I1] } } },
    ] } };
    assert.deepStrictEqual(custodyOf(row).map((e) => e.instances), [null, [I1]]);
  });
});

describe('closing', () => {
  const m = (over) => ({ member: `fip-1/${I1}`, contained: false, sharedTo: [], ...over });

  test('restored, unshared members let a case close', async () => {
    const { closeBlockers } = await load();
    assert.deepStrictEqual(closeBlockers([m(), m({ member: `fip-1/${I2}` })]), []);
  });

  test('a contained host, a share, or a host that could not be checked each blocks', async () => {
    const { closeBlockers } = await load();
    const b = closeBlockers([
      m({ contained: true }),
      m({ member: 'fip-2/i-1', sharedTo: [X] }),
      m({ member: 'fip-3/i-1', contained: null, containmentError: 'AccessDenied' }),
    ]);
    assert.strictEqual(b.length, 3);
    assert.match(b[0], /still contained/);
    assert.match(b[1], /shared to 333333333333/);
    assert.match(b[2], /could not be checked \(AccessDenied\)/);
  });

  test('an empty case closes', async () => {
    const { closeBlockers } = await load();
    assert.deepStrictEqual(closeBlockers([]), []);
  });

  test('each state-changing event needs the case in the right state', async () => {
    const { REQUIRED_STATE, CASE_EVENTS } = await load();
    assert.strictEqual(REQUIRED_STATE.CLOSED, 'OPEN');
    assert.strictEqual(REQUIRED_STATE.REOPENED, 'CLOSED');
    assert.strictEqual(REQUIRED_STATE.RELEASED, 'OPEN', 'a closed case releases nothing; reopen it first');
    assert.strictEqual(REQUIRED_STATE.REVOKED, undefined, 'withdrawing access is always allowed');
    for (const e of Object.keys(REQUIRED_STATE)) assert.ok(CASE_EVENTS.has(e), e);
  });

  test('release, revoke, close and reopen replay only the log head', async () => {
    const { rowUpdateFor } = await load();
    for (const event of ['RELEASED', 'REVOKED', 'CLOSED', 'REOPENED']) {
      const u = rowUpdateFor({ event, seq: 3, at: 't', members: ['x'], tickets: ['T'] }, 'h');
      assert.doesNotMatch(u.UpdateExpression, /members|tickets|state/i, event);
    }
  });
});
