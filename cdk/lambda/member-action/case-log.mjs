/**
 * Incident cases: the pure half. No AWS SDK here, so the Lambda imports it,
 * the unit tests import it, and `fip case show` runs it with plain node to
 * verify a downloaded log.
 *
 * A CASE is one incident. Each isolation run (an ACTION, id fip-…) keeps its
 * own id, records and evidence; a case only points at them. Everything that
 * happens to a case is an event in its log: a signed envelope of schema
 * fip.case/1 at cases/<caseId>/log/<seq>.json, where seq counts from 1.
 *
 * ── Why the log is chained ────────────────────────────────────────────
 * Each record carries the SHA-256 of the signed bytes of the record before
 * it. Object Lock protects records in production, but nothing is locked in
 * test mode, and a log is only evidence if a deleted or reordered record is
 * detectable. With the chain it is, in either mode, from the records alone.
 *
 * ── Why seq is the object key ─────────────────────────────────────────
 * Two responders can act on one case at the same moment. Each record is
 * written with S3's If-None-Match, so exactly one writer gets seq N and the
 * other is refused and retries at N+1. The log can therefore never fork, and
 * nothing has to be cleaned up after a lost race.
 */

import { createHash, verify as cryptoVerify } from 'node:crypto';

export const CASE_SCHEMA = 'fip.case/1';
export const CASE_ID_PATTERN = /^case-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$/;
export const ACTION_ID_PATTERN = /^fip-[A-Za-z0-9-]{1,120}$/;
export const CASE_EVENTS = new Set(['OPENED', 'TICKET_ADDED', 'COMMENT', 'MEMBER_ATTACHED']);
export const isActionId = (id) => ACTION_ID_PATTERN.test(String(id ?? ''));
const INSTANCE_ID_PATTERN = /^i-[0-9a-f]{8,17}$/;
const ACCOUNT_ID_PATTERN = /^[0-9]{12}$/;

/** A member is one target of one action: `<actionId>/<instanceId>`. */
export const memberId = (actionId, instanceId) => `${actionId}/${instanceId}`;

/**
 * The members an isolation run brings into a case, from its requested
 * targets. Checked here because they go into a signed record, which cannot be
 * corrected afterwards.
 */
export function attachedMembers(actionId, targets = []) {
  if (!isActionId(actionId)) throw new Error(`'${actionId}' is not an isolation run id (fip-…)`);
  const seen = new Map();
  for (const t of targets) {
    const accountId = String(t?.accountId ?? '');
    const instanceId = String(t?.instanceId ?? '');
    if (!ACCOUNT_ID_PATTERN.test(accountId)) throw new Error(`'${accountId}' is not an account id`);
    if (!INSTANCE_ID_PATTERN.test(instanceId)) throw new Error(`'${instanceId}' is not an instance id`);
    seen.set(instanceId, { member: memberId(actionId, instanceId), accountId, instanceId });
  }
  if (!seen.size) throw new Error('an isolation run attaches at least one target');
  return [...seen.values()].sort((a, b) => a.member.localeCompare(b.member));
}

const MAX_TEXT = 4000;
const MAX_TICKET = 200;

export const isCaseId = (id) => CASE_ID_PATTERN.test(String(id ?? ''));

export function caseLogKey(caseId, seq) {
  return `cases/${caseId}/log/${String(seq).padStart(6, '0')}.json`;
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** A ticket from the customer's own system. Free text, kept short and printable. */
export function checkTicket(ticket) {
  const t = String(ticket ?? '').trim();
  if (!t) throw new Error('a ticket must not be empty');
  if (t.length > MAX_TICKET) throw new Error(`a ticket is at most ${MAX_TICKET} characters`);
  if (/[\u0000-\u001f\u007f]/.test(t)) throw new Error('a ticket must not contain control characters');
  return t;
}

export function checkComment(comment, { required = false } = {}) {
  if (comment === undefined || comment === null || comment === '') {
    if (required) throw new Error('a comment is required');
    return null;
  }
  const c = String(comment);
  if (c.length > MAX_TEXT) throw new Error(`a comment is at most ${MAX_TEXT} characters`);
  return c;
}

/**
 * The document one log record signs. `prev` is null for the first record,
 * which must be OPENED; otherwise it names the record before it and the hash
 * of that record's signed bytes.
 */
export function buildCaseEvent({ caseId, seq, event, at, actor, prev, data = {} }) {
  if (!isCaseId(caseId)) throw new Error(`'${caseId}' is not a case id`);
  if (!CASE_EVENTS.has(event)) throw new Error(`unknown case event '${event}'`);
  if (!Number.isInteger(seq) || seq < 1) throw new Error(`bad sequence number ${seq}`);
  if ((seq === 1) !== (event === 'OPENED')) {
    throw new Error('the first record of a case log is OPENED, and only the first');
  }
  if ((seq === 1) !== (prev === null)) throw new Error('only the first record has no predecessor');
  return {
    schema: CASE_SCHEMA,
    caseId,
    seq,
    event,
    at,
    actor: actor ?? null,
    prev: prev ? { seq: prev.seq, key: prev.key, sha256: prev.sha256 } : null,
    ...data,
  };
}

/**
 * What a record does to the case row, as one DynamoDB UpdateItem. Applied
 * both by the writer and by whoever finds a record the row has not caught up
 * with, so it must be idempotent: SET of the record's own values, and ADD to
 * a string set.
 */
export function rowUpdateFor(doc, sha256) {
  const names = { '#seq': 'logSeq' };
  const values = {
    ':seq': { N: String(doc.seq) },
    ':head': { S: sha256 },
    ':at': { S: doc.at },
  };
  const set = ['#seq = :seq', 'logHead = :head', 'lastEventAt = :at'];
  const add = [];
  const tickets = doc.event === 'OPENED' ? (doc.tickets ?? [])
    : doc.event === 'TICKET_ADDED' ? [doc.ticket] : [];
  if (tickets.length) {
    add.push('tickets :tickets');
    values[':tickets'] = { SS: [...new Set(tickets)] };
  }
  // One map entry per member, each SET to the record's own values, so
  // applying the record twice changes nothing. The members map exists from
  // OPENED, which is what makes a nested SET possible.
  if (doc.event === 'MEMBER_ATTACHED') {
    names['#members'] = 'members';
    (doc.members ?? []).forEach((m, i) => {
      names[`#m${i}`] = m.member;
      values[`:m${i}`] = {
        M: {
          actionId: { S: doc.actionId },
          accountId: { S: m.accountId },
          instanceId: { S: m.instanceId },
          attachedSeq: { N: String(doc.seq) },
          attachedAt: { S: doc.at },
        },
      };
      set.push(`#members.#m${i} = :m${i}`);
    });
  }
  return {
    UpdateExpression: `SET ${set.join(', ')}${add.length ? ` ADD ${add.join(', ')}` : ''}`,
    // Never move the row backwards: a slower writer must not overwrite a
    // head that a later record already advanced.
    ConditionExpression: 'attribute_not_exists(#seq) OR #seq < :seq',
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: values,
  };
}

/** The signed document inside an envelope, from the signed bytes, not the readable copy. */
export function signedDocument(envelope) {
  const b64 = envelope?.signature?.signedPayloadBase64;
  if (!b64) throw new Error('no signedPayloadBase64 in the envelope');
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

/**
 * Check a whole case log: each record's integrity, optionally its origin, and
 * the chain from OPENED to the last record.
 *
 * records: [{ key, envelope }] in any order.
 * expectedPublicKeyDer: Buffer of this installation's signing key, or null to
 *   check integrity and chain only.
 *
 * Returns { ok, records: [{ key, seq, event, doc, problems }], problems }.
 */
export function verifyCaseLog(caseId, records, expectedPublicKeyDer = null) {
  const problems = [];
  const checked = [];

  for (const { key, envelope } of records) {
    const p = [];
    const sig = envelope?.signature ?? {};
    let payload = null;
    let doc = null;
    try {
      payload = Buffer.from(sig.signedPayloadBase64 ?? '', 'base64');
      doc = JSON.parse(payload.toString('utf8'));
    } catch {
      p.push('signed bytes are missing or not JSON');
    }
    if (payload && sig.signedPayloadSha256 !== sha256Hex(payload)) {
      p.push('signed bytes do not hash to the recorded digest');
    }
    if (payload) {
      let good = false;
      try {
        good = cryptoVerify('sha384', payload,
          { key: Buffer.from(sig.publicKeyDer ?? '', 'base64'), format: 'der', type: 'spki', dsaEncoding: 'der' },
          Buffer.from(sig.value ?? '', 'base64'));
      } catch { good = false; }
      if (!good) p.push('signature does not verify');
    }
    if (expectedPublicKeyDer
        && !Buffer.from(sig.publicKeyDer ?? '', 'base64').equals(expectedPublicKeyDer)) {
      p.push('not signed by this installation\'s key');
    }
    if (doc) {
      const readable = envelope.caseEvent;
      if (JSON.stringify(readable) !== JSON.stringify(doc)) {
        p.push('readable copy differs from the signed bytes');
      }
      if (doc.schema !== CASE_SCHEMA) p.push(`schema is ${doc.schema}, not ${CASE_SCHEMA}`);
      if (doc.caseId !== caseId) p.push(`belongs to case ${doc.caseId}`);
      if (key && doc.seq && key !== caseLogKey(caseId, doc.seq)) p.push(`stored at ${key}, not at its sequence number's key`);
    }
    checked.push({ key, seq: doc?.seq ?? null, event: doc?.event ?? null, doc,
      sha256: payload ? sha256Hex(payload) : null, problems: p });
  }

  checked.sort((a, b) => (a.seq ?? Infinity) - (b.seq ?? Infinity));
  let expect = 1;
  let prev = null;
  for (const r of checked) {
    if (r.seq === null) continue;
    if (r.seq !== expect) {
      problems.push(r.seq < expect
        ? `record ${r.seq} appears more than once`
        : `records ${expect}${r.seq - 1 > expect ? `-${r.seq - 1}` : ''} missing before ${r.seq}`);
    }
    if (prev && r.doc?.prev?.sha256 !== prev.sha256 && r.seq === prev.seq + 1) {
      r.problems.push(`does not chain to record ${prev.seq}: its predecessor has changed`);
    }
    if (r.seq === 1 && r.doc?.event !== 'OPENED') r.problems.push('the first record is not OPENED');
    prev = r;
    expect = r.seq + 1;
  }
  if (!checked.length) problems.push('the log is empty');

  for (const r of checked) for (const p of r.problems) problems.push(`${r.key ?? '?'}: ${p}`);
  return { ok: problems.length === 0, records: checked, problems };
}

/**
 * The verdict for an isolation run's row, from everything it holds rather
 * than from the latest run alone. A run reusing an id with --case-id must
 * not make the row forget the runs before it.
 *
 * targets:  the row's targets map, as plain objects ({ instanceId: { state } })
 * previous: failures recorded by earlier runs, [{ accountId, instanceId, error, cause }]
 * results:  this run's per-target outcomes, [{ ok, accountId, instanceId, error, cause }]
 * requested: every requested target so far, [{ accountId, instanceId }]
 */
export function summarizeAction({ targets = {}, previous = [], results = [], requested = [] }) {
  const acquired = new Set(Object.entries(targets)
    .filter(([, v]) => v?.state === 'ACQUIRED').map(([k]) => k));
  for (const r of results) if (r?.ok === true && r.instanceId) acquired.add(r.instanceId);

  const failures = new Map();
  for (const f of [...previous, ...results.filter((r) => !r || r.ok !== true)]) {
    const id = f?.instanceId ?? 'unknown';
    failures.set(id, {
      accountId: String(f?.accountId ?? 'unknown'),
      instanceId: String(id),
      error: String(f?.error ?? 'unknown'),
      cause: String(f?.cause ?? '').slice(0, 1024),
    });
  }
  for (const id of acquired) failures.delete(id);

  const all = new Set([...acquired, ...failures.keys(),
    ...requested.map((t) => t?.instanceId).filter(Boolean)]);
  const state = acquired.size === 0 ? 'FAILED' : failures.size === 0 ? 'ACQUIRED' : 'PARTIAL';
  return {
    state,
    succeeded: acquired.size,
    failed: failures.size,
    targetCount: all.size,
    failures: [...failures.values()],
  };
}
