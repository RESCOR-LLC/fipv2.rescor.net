/**
 * The rules for naming a case from the shell (bin/fip-case-lib.sh): a case
 * by id, or by a ticket exactly one case carries; and an isolation attaches
 * only to an OPEN case. `evidence` (the aws CLI as the evidence profile) is
 * replaced with canned table contents, so this runs with bash and jq alone.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const LIB = path.join(__dirname, '..', 'bin', 'fip-case-lib.sh');

const OPEN_A = 'case-20261105T100000Z-aaaaaa';
const OPEN_B = 'case-20261105T110000Z-bbbbbb';
const CLOSED = 'case-20261104T090000Z-cccccc';
const RUN = 'fip-20261105T120000Z-dddddd';

const ROWS = [
  { caseId: { S: OPEN_A }, kind: { S: 'case' }, state: { S: 'OPEN' }, openedAt: { S: '2026-11-05T10:00:00Z' },
    tickets: { SS: ['INC-1', 'SHARED'] } },
  { caseId: { S: OPEN_B }, kind: { S: 'case' }, state: { S: 'OPEN' }, openedAt: { S: '2026-11-05T11:00:00Z' },
    tickets: { SS: ['SHARED'] } },
  { caseId: { S: CLOSED }, kind: { S: 'case' }, state: { S: 'CLOSED' }, openedAt: { S: '2026-11-04T09:00:00Z' },
    tickets: { SS: ['OLD-7'] } },
  { caseId: { S: RUN }, kind: { S: 'action' }, state: { S: 'ACQUIRED' }, openedAt: { S: '2026-11-05T12:00:00Z' } },
];

/** Run `script` with the lib sourced and `evidence` answering from `rows`. */
function run(script, rows = ROWS) {
  const stub = `
evidence() {
  case "$2" in
    scan) printf '%s' "$ROWS" | jq '{Items: .}' ;;
    get-item)
      local id; id="$(printf '%s' "$*" | sed -n 's/.*"S":"\\([^"]*\\)".*/\\1/p')"
      printf '%s' "$ROWS" | jq --arg id "$id" '{Item: (map(select(.caseId.S == $id)) | .[0])} | if .Item == null then {} else . end' ;;
  esac
}
. "${LIB}"
set -euo pipefail
${script}`;
  const r = spawnSync('bash', ['-c', stub], { env: { ...process.env, ROWS: JSON.stringify(rows) }, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

describe('naming a case', () => {
  test('an id is taken as given', () => {
    assert.strictEqual(run(`resolve ${OPEN_A} ""`).out, OPEN_A);
  });

  test('a ticket names the one case that carries it', () => {
    assert.strictEqual(run('resolve "" INC-1').out, OPEN_A);
  });

  test('a ticket two cases carry is refused, and both are listed', () => {
    const r = run('resolve "" SHARED');
    assert.strictEqual(r.code, 1);
    assert.match(r.err, /several cases carry ticket SHARED/);
    assert.match(r.err, new RegExp(OPEN_A));
    assert.match(r.err, new RegExp(OPEN_B));
  });

  test('a ticket no case carries is refused', () => {
    const r = run('resolve "" NOPE-1');
    assert.strictEqual(r.code, 1);
    assert.match(r.err, /no case carries ticket NOPE-1/);
  });

  test('a case and a ticket together are refused', () => {
    assert.strictEqual(run(`resolve ${OPEN_A} INC-1`).code, 2);
  });
});

describe('attaching an isolation', () => {
  test('an open case is accepted', () => {
    assert.strictEqual(run(`require_open_case ${OPEN_A}; echo ok`).out.trim(), 'ok');
  });

  test('a closed case is refused', () => {
    const r = run(`require_open_case ${CLOSED}`);
    assert.strictEqual(r.code, 1);
    assert.match(r.err, /is CLOSED/);
  });

  test('an isolation run id is refused, and the right flag is named', () => {
    const r = run(`require_open_case ${RUN}`);
    assert.strictEqual(r.code, 2);
    assert.match(r.err, /isolation run, not an incident case/);
  });

  test('a case that does not exist is refused', () => {
    const r = run('require_open_case case-20261105T130000Z-eeeeee');
    assert.strictEqual(r.code, 1);
    assert.match(r.err, /no incident case/);
  });
});

describe('the open-case notice', () => {
  test('lists open cases only, newest first, with tickets', () => {
    const lines = run('open_cases').out.trim().split('\n').map((l) => l.split('\t'));
    assert.deepStrictEqual(lines.map((l) => l[0]), [OPEN_B, OPEN_A]);
    assert.strictEqual(lines[1][2], 'INC-1,SHARED');
  });

  test('is empty when no case is open', () => {
    assert.strictEqual(run('open_cases', [ROWS[2], ROWS[3]]).out, '');
  });
});
