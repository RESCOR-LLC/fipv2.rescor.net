/**
 * Incident case logs: the chain, the row updates, and the run summary.
 *
 * The log is evidence, so the tests that matter are the ones where something
 * has gone wrong: a record deleted, reordered, edited, or signed by someone
 * else. Each must be reported, from the records alone.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const path = require('node:path');

const load = () => import(path.join(__dirname, '..', 'lambda', 'member-action', 'case-log.mjs'));

const CASE = 'case-20261105T101500Z-3f9a1c';
const ours = generateKeyPairSync('ec', { namedCurve: 'P-384' });
const theirs = generateKeyPairSync('ec', { namedCurve: 'P-384' });

// The same envelope signEnvelope() writes, signed locally instead of in KMS.
function envelopeFor(doc, keys = ours) {
  const body = JSON.stringify(doc, null, 2);
  const der = keys.publicKey.export({ format: 'der', type: 'spki' });
  return {
    caseEvent: doc,
    signature: {
      algorithm: 'ECDSA_SHA_384',
      value: sign('sha384', Buffer.from(body), { key: keys.privateKey, dsaEncoding: 'der' }).toString('base64'),
      publicKeyDer: der.toString('base64'),
      signedPayloadBase64: Buffer.from(body).toString('base64'),
      signedPayloadSha256: createHash('sha256').update(body).digest('hex'),
    },
  };
}

async function logOf(events) {
  const m = await load();
  const out = [];
  let prev = null;
  events.forEach(([event, data], i) => {
    const seq = i + 1;
    const doc = m.buildCaseEvent({ caseId: CASE, seq, event, at: `2026-11-05T10:1${i}:00Z`, actor: 'arn:test', prev, data });
    const envelope = envelopeFor(doc);
    out.push({ key: m.caseLogKey(CASE, seq), envelope });
    prev = { seq, key: m.caseLogKey(CASE, seq), sha256: envelope.signature.signedPayloadSha256 };
  });
  return out;
}

const OURS_DER = ours.publicKey.export({ format: 'der', type: 'spki' });

describe('case log chain', () => {
  test('an intact log verifies, with origin', async () => {
    const m = await load();
    const log = await logOf([['OPENED', { tickets: ['INC-1'] }], ['COMMENT', { comment: 'web tier' }], ['TICKET_ADDED', { ticket: 'JIRA-9' }]]);
    const r = m.verifyCaseLog(CASE, log, OURS_DER);
    assert.deepStrictEqual(r.problems, []);
    assert.strictEqual(r.ok, true);
    assert.deepStrictEqual(r.records.map((x) => x.event), ['OPENED', 'COMMENT', 'TICKET_ADDED']);
  });

  test('order on disk does not matter; sequence does', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}], ['COMMENT', { comment: 'a' }], ['COMMENT', { comment: 'b' }]]);
    assert.strictEqual(m.verifyCaseLog(CASE, [log[2], log[0], log[1]], OURS_DER).ok, true);
  });

  test('a deleted record in the middle is reported', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}], ['COMMENT', { comment: 'a' }], ['COMMENT', { comment: 'b' }]]);
    const r = m.verifyCaseLog(CASE, [log[0], log[2]], OURS_DER);
    assert.strictEqual(r.ok, false);
    assert.ok(r.problems.some((p) => /records 2 missing/.test(p)), r.problems.join('; '));
  });

  test('a deleted first record is reported', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}], ['COMMENT', { comment: 'a' }]]);
    assert.strictEqual(m.verifyCaseLog(CASE, [log[1]], OURS_DER).ok, false);
  });

  test('a record replaced by a re-signed one does not chain', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}], ['COMMENT', { comment: 'a' }], ['COMMENT', { comment: 'b' }]]);
    // A validly signed but different record 2: record 3 still names the old one.
    const forged = m.buildCaseEvent({ caseId: CASE, seq: 2, event: 'COMMENT', at: 'x', actor: 'y',
      prev: { seq: 1, key: log[0].key, sha256: log[0].envelope.signature.signedPayloadSha256 }, data: { comment: 'rewritten' } });
    const r = m.verifyCaseLog(CASE, [log[0], { key: log[1].key, envelope: envelopeFor(forged) }, log[2]], OURS_DER);
    assert.strictEqual(r.ok, false);
    assert.ok(r.problems.some((p) => /does not chain to record 2/.test(p)), r.problems.join('; '));
  });

  test('an edited readable copy is reported', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}], ['COMMENT', { comment: 'a' }]]);
    log[1].envelope.caseEvent = { ...log[1].envelope.caseEvent, comment: 'edited' };
    const r = m.verifyCaseLog(CASE, log, OURS_DER);
    assert.ok(r.problems.some((p) => /readable copy differs/.test(p)), r.problems.join('; '));
  });

  test('edited signed bytes fail the signature', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}]]);
    const sig = log[0].envelope.signature;
    const body = Buffer.from(sig.signedPayloadBase64, 'base64').toString().replace('OPENED', 'OPENED ');
    sig.signedPayloadBase64 = Buffer.from(body).toString('base64');
    sig.signedPayloadSha256 = createHash('sha256').update(body).digest('hex');
    const r = m.verifyCaseLog(CASE, log, OURS_DER);
    assert.ok(r.problems.some((p) => /signature does not verify/.test(p)), r.problems.join('; '));
  });

  test('a record signed with another key passes integrity but fails origin', async () => {
    const m = await load();
    const doc = m.buildCaseEvent({ caseId: CASE, seq: 1, event: 'OPENED', at: 'x', actor: 'y', prev: null });
    const log = [{ key: m.caseLogKey(CASE, 1), envelope: envelopeFor(doc, theirs) }];
    assert.strictEqual(m.verifyCaseLog(CASE, log, null).ok, true);
    const r = m.verifyCaseLog(CASE, log, OURS_DER);
    assert.ok(r.problems.some((p) => /not signed by this installation/.test(p)), r.problems.join('; '));
  });

  test('a record from another case is reported', async () => {
    const m = await load();
    const log = await logOf([['OPENED', {}]]);
    const r = m.verifyCaseLog('case-20261105T101500Z-000000', log, OURS_DER);
    assert.strictEqual(r.ok, false);
  });
});

describe('case events', () => {
  test('only the first record is OPENED, and it has no predecessor', async () => {
    const m = await load();
    const p = { seq: 1, key: 'k', sha256: 'h' };
    assert.throws(() => m.buildCaseEvent({ caseId: CASE, seq: 2, event: 'OPENED', at: 'x', prev: p }));
    assert.throws(() => m.buildCaseEvent({ caseId: CASE, seq: 1, event: 'COMMENT', at: 'x', prev: null }));
    assert.throws(() => m.buildCaseEvent({ caseId: CASE, seq: 2, event: 'COMMENT', at: 'x', prev: null }));
  });

  test('isolation ids are not case ids', async () => {
    const m = await load();
    assert.strictEqual(m.isCaseId('fip-20261104T040328Z-62b079'), false);
    assert.strictEqual(m.isCaseId(CASE), true);
    assert.strictEqual(m.isCaseId('case-../../x'), false);
  });

  test('tickets are trimmed, bounded and printable', async () => {
    const m = await load();
    assert.strictEqual(m.checkTicket('  INC-1234 '), 'INC-1234');
    assert.throws(() => m.checkTicket(''));
    assert.throws(() => m.checkTicket('a\nb'));
    assert.throws(() => m.checkTicket('x'.repeat(201)));
  });

  test('a row update never moves the row backwards, and adds tickets idempotently', async () => {
    const m = await load();
    const u = m.rowUpdateFor({ seq: 3, at: 't', event: 'TICKET_ADDED', ticket: 'INC-1' }, 'abc');
    assert.match(u.ConditionExpression, /#seq < :seq/);
    assert.match(u.UpdateExpression, /ADD tickets :tickets/);
    assert.deepStrictEqual(u.ExpressionAttributeValues[':tickets'], { SS: ['INC-1'] });
    assert.doesNotMatch(m.rowUpdateFor({ seq: 4, at: 't', event: 'COMMENT' }, 'd').UpdateExpression, /ADD/);
  });
});

describe('isolation run summary across reruns of one id', () => {
  test('a second run that fixes the failure makes the row ACQUIRED', async () => {
    const m = await load();
    const s = m.summarizeAction({
      targets: { 'i-a': { state: 'ACQUIRED' } },
      previous: [{ accountId: '1', instanceId: 'i-b', error: 'boom' }],
      results: [{ ok: true, accountId: '1', instanceId: 'i-b' }],
    });
    assert.deepStrictEqual([s.state, s.succeeded, s.failed], ['ACQUIRED', 2, 0]);
  });

  test('a second run of other hosts keeps the first run\'s failure', async () => {
    const m = await load();
    const s = m.summarizeAction({
      targets: { 'i-a': { state: 'ACQUIRED' }, 'i-c': { state: 'ACQUIRED' } },
      previous: [{ accountId: '1', instanceId: 'i-b', error: 'boom' }],
      results: [{ ok: true, accountId: '1', instanceId: 'i-c' }],
    });
    assert.deepStrictEqual([s.state, s.succeeded, s.failed], ['PARTIAL', 2, 1]);
    assert.strictEqual(s.failures[0].instanceId, 'i-b');
  });

  test('nothing acquired in any run is FAILED; the target count spans every run', async () => {
    const m = await load();
    const s = m.summarizeAction({
      previous: [{ instanceId: 'i-a', error: 'x' }],
      results: [{ ok: false, instanceId: 'i-b', error: 'y' }],
      requested: [{ instanceId: 'i-a' }, { instanceId: 'i-b' }, { instanceId: 'i-b' }],
    });
    assert.deepStrictEqual([s.state, s.failed, s.targetCount], ['FAILED', 2, 2]);
  });
});
