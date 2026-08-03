#!/usr/bin/env node
/**
 * Verifies every lab's vendored src/lab_common.py is byte-identical to the
 * canonical copy at shared/lambda-common/lab_common.py.
 *
 *   node scripts/check-common-sync.mjs          # check (exit 1 on drift)
 *   node scripts/check-common-sync.mjs --write  # resync vendored copies
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const canonicalPath = join(root, 'shared/lambda-common/lab_common.py');
const canonical = readFileSync(canonicalPath, 'utf8');
const write = process.argv.includes('--write');

const labDirs = readdirSync(join(root, 'labs'), { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

let drift = 0;
for (const lab of labDirs) {
  const vendored = join(root, 'labs', lab, 'src', 'lab_common.py');
  const current = existsSync(vendored) ? readFileSync(vendored, 'utf8') : null;
  if (current === canonical) continue;
  if (write) {
    writeFileSync(vendored, canonical);
    console.log(`synced labs/${lab}/src/lab_common.py`);
  } else {
    console.error(`DRIFT: labs/${lab}/src/lab_common.py ${current === null ? 'is missing' : 'differs from canonical'}`);
    drift += 1;
  }
}

if (drift) {
  console.error(`\n${drift} vendored copies out of sync. Run: node scripts/check-common-sync.mjs --write`);
  process.exit(1);
}
console.log(`lab_common sync OK — ${labDirs.length} labs match ${canonicalPath.replace(root + '/', '')}`);
