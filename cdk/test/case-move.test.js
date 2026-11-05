/**
 * Moving and merging: the transactions that change which case lists a member.
 *
 * The property that matters is what happens when the world changed between
 * reading and writing: two responders moving the same host, a move into a
 * case that closed or merged meanwhile. So the transactions are run against
 * a small in-memory table that evaluates exactly the condition and update
 * forms they use, all-or-nothing, as DynamoDB does.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const load = () => import(path.join(__dirname, '..', 'lambda', 'member-action', 'case-log.mjs'));

const TABLE = 'fip-cases';
const A = 'case-20261105T100000Z-aaaaaa';
const B = 'case-20261105T110000Z-bbbbbb';
const C = 'case-20261105T120000Z-cccccc';
const RUN = 'fip-20261105T090000Z-111111';
const LEGACY = 'fip-20261104T090000Z-222222';
const I1 = 'i-0aaaaaaaaaaaaaaaa';
const I2 = 'i-0bbbbbbbbbbbbbbbb';

// ── A tiny DynamoDB, for the expression forms the transactions use ──────
function segments(p, names) {
  return p.split('.').map((s) => (s.startsWith('#') ? names[s] : s));
}
function getPath(item, p, names) {
  let cur = { M: item };
  for (const s of segments(p, names)) {
    cur = cur?.M?.[s];
    if (cur === undefined) return undefined;
  }
  return cur;
}
function setPath(item, p, names, value) {
  const segs = segments(p, names);
  let cur = { M: item };
  for (const s of segs.slice(0, -1)) {
    cur = cur.M[s];
    if (!cur?.M) throw new Error(`ValidationException: parent of ${p} does not exist`);
  }
  cur.M[segs.at(-1)] = value;
}
function removePath(item, p, names) {
  const segs = segments(p, names);
  let cur = { M: item };
  for (const s of segs.slice(0, -1)) cur = cur?.M?.[s];
  if (cur?.M) delete cur.M[segs.at(-1)];
}
function atom(item, t, names, values) {
  let m;
  if ((m = t.match(/^attribute_exists\((.+)\)$/))) return getPath(item, m[1], names) !== undefined;
  if ((m = t.match(/^attribute_not_exists\((.+)\)$/))) return getPath(item, m[1], names) === undefined;
  if ((m = t.match(/^size\((.+)\) = (:\w+)$/))) {
    const v = getPath(item, m[1], names);
    const size = v?.M ? Object.keys(v.M).length : v?.SS ? v.SS.length : v?.S ? v.S.length : 0;
    return String(size) === values[m[2]].N;
  }
  if ((m = t.match(/^(\S+) = (:\w+)$/))) {
    return JSON.stringify(getPath(item, m[1], names)) === JSON.stringify(values[m[2]]);
  }
  throw new Error(`test table cannot evaluate '${t}'`);
}
function holds(item, expr, names, values) {
  return expr.split(' AND ').every((term) => {
    const t = term.replace(/^\((.*)\)$/, '$1');
    return t.split(' OR ').some((o) => atom(item, o.trim(), names, values));
  });
}
function apply(item, expr, names, values) {
  const [, verb, rest] = expr.match(/^(SET|REMOVE|ADD) (.*)$/);
  for (const part of rest.split(', ')) {
    if (verb === 'SET') {
      const [p, v] = part.split(' = ');
      setPath(item, p, names, structuredClone(values[v]));
    } else if (verb === 'REMOVE') {
      removePath(item, part, names);
    } else {
      const [p, v] = part.split(' ');
      const now = getPath(item, p, names)?.SS ?? [];
      setPath(item, p, names, { SS: [...new Set([...now, ...values[v].SS])] });
    }
  }
}
class Table {
  constructor(items) { this.items = new Map(items.map((i) => [i.caseId.S, structuredClone(i)])); }
  get(id) { return structuredClone(this.items.get(id)); }
  transact(txItems) {
    const reasons = txItems.map(({ Update: u }) => {
      const item = this.items.get(u.Key.caseId.S);
      const ok = item && holds(item, u.ConditionExpression,
        u.ExpressionAttributeNames ?? {}, u.ExpressionAttributeValues ?? {});
      return { Code: ok ? 'None' : 'ConditionalCheckFailed' };
    });
    if (reasons.some((r) => r.Code !== 'None')) {
      const err = new Error('Transaction cancelled');
      err.name = 'TransactionCanceledException';
      err.CancellationReasons = reasons;
      throw err;
    }
    for (const { Update: u } of txItems) {
      apply(this.items.get(u.Key.caseId.S), u.UpdateExpression,
        u.ExpressionAttributeNames ?? {}, u.ExpressionAttributeValues ?? {});
    }
  }
}

const caseRow = (id, members = {}, extra = {}) => ({
  caseId: { S: id }, kind: { S: 'case' }, state: { S: 'OPEN' }, members: { M: members }, ...extra,
});
const memberValue = (actionId, instanceId) => ({
  M: { actionId: { S: actionId }, instanceId: { S: instanceId }, accountId: { S: '111111111111' } },
});
const runRow = (id, cases = {}, extra = {}) => ({
  caseId: { S: id }, kind: { S: 'action' }, cases: { M: cases },
  requestedTargets: { L: [I1, I2].map((i) => ({ M: { accountId: { S: '111111111111' }, instanceId: { S: i } } })) },
  ...extra,
});
const REC = { seq: 4, at: '2026-11-05T12:00:00Z', key: 'cases/x/log/000004.json' };

function world() {
  return new Table([
    caseRow(A, { [`${RUN}/${I1}`]: memberValue(RUN, I1) }),
    caseRow(B),
    caseRow(C),
    runRow(RUN, { [I1]: { S: A } }, { incident: { S: A } }),
  ]);
}
async function membersFor(t, specs) {
  const m = await load();
  return specs.map(([actionId, instanceId]) => {
    const a = t.get(actionId);
    const inc = a.incident?.S ? t.get(a.incident.S) : null;
    const where = m.locateMember(a, instanceId, inc);
    return { member: m.memberId(actionId, instanceId), actionId, instanceId, accountId: '111111111111',
      recorded: where.recorded, from: where.caseId };
  });
}

describe('what a move argument names', () => {
  test('a member, a whole run, or a whole case', async () => {
    const { parseMemberSpec } = await load();
    assert.deepStrictEqual(parseMemberSpec(`${RUN}/${I1}`), { kind: 'member', actionId: RUN, instanceId: I1 });
    assert.deepStrictEqual(parseMemberSpec(RUN), { kind: 'action', actionId: RUN });
    assert.deepStrictEqual(parseMemberSpec(A), { kind: 'case', caseId: A });
  });

  test('anything else is refused before it can reach a signed record', async () => {
    const { parseMemberSpec } = await load();
    for (const bad of ['', 'i-0aaaaaaaaaaaaaaaa', `${RUN}/vol-1`, `${A}/${I1}`, 'test']) {
      assert.throws(() => parseMemberSpec(bad), /is not a member/, bad);
    }
  });

  test('a run\'s targets come from what it requested and what it acquired', async () => {
    const { targetsOfAction } = await load();
    const row = runRow(RUN, {}, { targets: { M: { 'i-0cccccccccccccccc': { M: { sourceAccount: { S: '222222222222' } } } } } });
    assert.deepStrictEqual(Object.keys(targetsOfAction(row)).sort(), [I1, I2, 'i-0cccccccccccccccc']);
  });
});

describe('where a member is', () => {
  test('the run\'s row says so', async () => {
    const { locateMember } = await load();
    assert.deepStrictEqual(locateMember(runRow(RUN, { [I1]: { S: B } }), I1), { caseId: B, recorded: true });
  });

  test('an older row is read through the case it was isolated into', async () => {
    const { locateMember } = await load();
    const legacy = runRow(LEGACY, undefined, { incident: { S: A } });
    delete legacy.cases;
    const a = caseRow(A, { [`${LEGACY}/${I1}`]: memberValue(LEGACY, I1) });
    assert.deepStrictEqual(locateMember(legacy, I1, a), { caseId: A, recorded: false });
    assert.deepStrictEqual(locateMember(legacy, I2, a), { caseId: null, recorded: false },
      'a target of that run the case does not list is in no case');
  });

  test('a standalone run\'s members are in no case', async () => {
    const { locateMember } = await load();
    assert.deepStrictEqual(locateMember(runRow(RUN), I1), { caseId: null, recorded: false });
  });
});

describe('moving', () => {
  test('a move updates the run, the source and the destination together', async () => {
    const { moveTransaction } = await load();
    const t = world();
    const members = await membersFor(t, [[RUN, I1]]);
    t.transact(moveTransaction({ table: TABLE, members, from: A, to: B, record: REC }));
    assert.strictEqual(t.get(RUN).cases.M[I1].S, B);
    assert.strictEqual(t.get(A).members.M[`${RUN}/${I1}`], undefined);
    assert.deepStrictEqual(t.get(B).members.M[`${RUN}/${I1}`].M.movedSeq, { N: '4' });
  });

  test('two responders move the same host at once: one wins, the other changes nothing', async () => {
    const { moveTransaction } = await load();
    const t = world();
    // Both read the same state, then write.
    const seen = await membersFor(t, [[RUN, I1]]);
    t.transact(moveTransaction({ table: TABLE, members: seen, from: A, to: B, record: REC }));
    const before = JSON.stringify([...t.items]);
    assert.throws(() => t.transact(moveTransaction({ table: TABLE, members: seen, from: A, to: C, record: REC })),
      (e) => e.name === 'TransactionCanceledException');
    assert.strictEqual(JSON.stringify([...t.items]), before, 'the loser leaves every row as it was');
    assert.strictEqual(t.get(RUN).cases.M[I1].S, B);
  });

  test('a move into a merged or closed case is refused', async () => {
    const { moveTransaction } = await load();
    for (const state of ['MERGED', 'CLOSED']) {
      const t = world();
      t.items.get(B).state = { S: state };
      const members = await membersFor(t, [[RUN, I1]]);
      assert.throws(() => t.transact(moveTransaction({ table: TABLE, members, from: A, to: B, record: REC })),
        (e) => e.CancellationReasons.at(-1).Code === 'ConditionalCheckFailed', state);
      assert.strictEqual(t.get(RUN).cases.M[I1].S, A);
    }
  });

  test('a move out of a case that merged meanwhile is refused', async () => {
    const { moveTransaction } = await load();
    const t = world();
    const members = await membersFor(t, [[RUN, I1]]);
    t.items.get(A).state = { S: 'MERGED' };
    assert.throws(() => t.transact(moveTransaction({ table: TABLE, members, from: A, to: B, record: REC })));
  });

  test('a member in no case moves in; one placed meanwhile is not moved again', async () => {
    const { moveTransaction } = await load();
    const t = world();
    const members = await membersFor(t, [[RUN, I2]]);
    assert.strictEqual(members[0].from, null);
    t.transact(moveTransaction({ table: TABLE, members, from: null, to: B, record: REC }));
    assert.strictEqual(t.get(RUN).cases.M[I2].S, B);
    assert.throws(() => t.transact(moveTransaction({ table: TABLE, members, from: null, to: C, record: REC })));
  });

  test('a member of an older row moves, and the row learns where it is', async () => {
    const { moveTransaction } = await load();
    const t = new Table([
      caseRow(A, { [`${LEGACY}/${I1}`]: memberValue(LEGACY, I1) }), caseRow(B),
      runRow(LEGACY, {}, { incident: { S: A } }),
    ]);
    const members = await membersFor(t, [[LEGACY, I1]]);
    assert.deepStrictEqual([members[0].from, members[0].recorded], [A, false]);
    t.transact(moveTransaction({ table: TABLE, members, from: A, to: B, record: REC }));
    assert.strictEqual(t.get(LEGACY).cases.M[I1].S, B);
  });

  test('moving to where it already is, or nothing, is refused outright', async () => {
    const { moveTransaction } = await load();
    const t = world();
    const members = await membersFor(t, [[RUN, I1]]);
    assert.throws(() => moveTransaction({ table: TABLE, members, from: A, to: A, record: REC }), /already in/);
    assert.throws(() => moveTransaction({ table: TABLE, members: [], from: A, to: B, record: REC }), /nothing/);
  });
});

describe('merging', () => {
  test('an emptied case becomes an alias, and the survivor gains its tickets', async () => {
    const { mergeTransaction } = await load();
    const t = new Table([caseRow(A, {}, { tickets: { SS: ['INC-1'] } }), caseRow(B, {}, { tickets: { SS: ['INC-2'] } })]);
    t.transact(mergeTransaction({ table: TABLE, into: B, from: A, tickets: ['INC-1'] }));
    assert.deepStrictEqual([t.get(A).state.S, t.get(A).mergedInto.S], ['MERGED', B]);
    assert.deepStrictEqual(t.get(B).tickets.SS.sort(), ['INC-1', 'INC-2']);
    assert.deepStrictEqual(t.get(B).mergedFrom.SS, [A]);
  });

  test('a case that gained a member since it was emptied does not merge', async () => {
    const { mergeTransaction } = await load();
    const t = new Table([caseRow(A, { [`${RUN}/${I1}`]: memberValue(RUN, I1) }), caseRow(B)]);
    assert.throws(() => t.transact(mergeTransaction({ table: TABLE, into: B, from: A })));
    assert.strictEqual(t.get(A).state.S, 'OPEN');
  });

  test('merging into a case that is no longer open, or merging one twice, is refused', async () => {
    const { mergeTransaction } = await load();
    const t = new Table([caseRow(A), caseRow(B), caseRow(C)]);
    t.transact(mergeTransaction({ table: TABLE, into: B, from: A }));
    assert.throws(() => t.transact(mergeTransaction({ table: TABLE, into: C, from: A })), undefined, 'A is already merged');
    assert.throws(() => t.transact(mergeTransaction({ table: TABLE, into: A, from: C })), undefined, 'A is an alias now');
    assert.throws(() => mergeTransaction({ table: TABLE, into: A, from: A }), /itself/);
  });
});

describe('withdrawn records', () => {
  test('a record an ABORTED note names is withdrawn; the log still verifies', async () => {
    const m = await load();
    const { generateKeyPairSync, sign, createHash } = require('node:crypto');
    const keys = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const docs = [
      ['OPENED', {}],
      ['MEMBER_MOVED', { from: A, to: B, members: [{ member: `${RUN}/${I1}` }], comment: 'x' }],
      ['ABORTED', { aborts: { seq: 2, key: m.caseLogKey(B, 2), event: 'MEMBER_MOVED' }, reason: 'changed' }],
    ];
    const records = [];
    let prev = null;
    docs.forEach(([event, data], i) => {
      const doc = m.buildCaseEvent({ caseId: B, seq: i + 1, event, at: 't', actor: 'a', prev, data });
      const body = JSON.stringify(doc, null, 2);
      const sha = createHash('sha256').update(body).digest('hex');
      records.push({ key: m.caseLogKey(B, i + 1), envelope: { caseEvent: doc, signature: {
        value: sign('sha384', Buffer.from(body), { key: keys.privateKey, dsaEncoding: 'der' }).toString('base64'),
        publicKeyDer: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        signedPayloadBase64: Buffer.from(body).toString('base64'), signedPayloadSha256: sha } } });
      prev = { seq: i + 1, key: m.caseLogKey(B, i + 1), sha256: sha };
    });
    const r = m.verifyCaseLog(B, records);
    assert.ok(r.ok, r.problems.join('; '));
    assert.deepStrictEqual([...m.abortedSeqs(r.records.map((x) => x.doc))], [2]);
  });

  test('moves, merges and aborts change only the log head when replayed', async () => {
    const { rowUpdateFor } = await load();
    for (const event of ['MEMBER_MOVED', 'MERGED', 'ABORTED']) {
      const u = rowUpdateFor({ event, seq: 5, at: 't', members: [{ member: 'x' }], tickets: ['T'] }, 'h');
      assert.doesNotMatch(u.UpdateExpression, /members|tickets/, `${event}: membership is the transaction's job`);
    }
  });
});
