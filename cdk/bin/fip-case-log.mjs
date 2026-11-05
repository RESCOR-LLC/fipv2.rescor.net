#!/usr/bin/env node
/**
 * fip-case-log.mjs — verify a downloaded case log and print it as JSON.
 *   (used by fip case show; not meant to be run by hand)
 *
 *   node fip-case-log.mjs <case-id> <dir-of-log-records> [our-public-key.der]
 *
 * Reads every *.json in the directory, checks each record's signature and the
 * chain (lambda/member-action/case-log.mjs), and with a key file also checks
 * that this installation signed each one. Prints
 *   { ok, problems: [...], records: [{ seq, event, at, actor, ...fields }] }
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { verifyCaseLog, caseLogKey } = await import(join(here, '..', 'lambda', 'member-action', 'case-log.mjs'));

const [caseId, dir, keyFile] = process.argv.slice(2);
if (!caseId || !dir) {
  process.stderr.write('usage: fip-case-log.mjs <case-id> <dir> [public-key.der]\n');
  process.exit(2);
}

let files = [];
try { files = readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { files = []; }
const records = files.map((f) => {
  const seq = Number(f.replace(/\.json$/, ''));
  return {
    key: Number.isInteger(seq) && seq > 0 ? caseLogKey(caseId, seq) : f,
    envelope: JSON.parse(readFileSync(join(dir, f), 'utf8')),
  };
});

const result = verifyCaseLog(caseId, records, keyFile ? readFileSync(keyFile) : null);
process.stdout.write(JSON.stringify({
  ok: result.ok,
  problems: result.problems,
  records: result.records.map((r) => ({ ...(r.doc ?? {}), key: r.key, problems: r.problems })),
}, null, 2) + '\n');
