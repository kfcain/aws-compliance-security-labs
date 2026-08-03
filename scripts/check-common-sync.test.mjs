import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const script = join(root, 'scripts/check-common-sync.mjs');
const vendored = join(root, 'labs/01-mfa-continuous-validation/src/lab_common.py');

describe('check-common-sync', () => {
  it('passes when all vendored copies match canonical', () => {
    const out = execFileSync(process.execPath, [script], { encoding: 'utf8' });
    assert.match(out, /lab_common sync OK — \d+ labs/);
  });

  it('fails on drift and repairs with --write', () => {
    const original = readFileSync(vendored, 'utf8');
    try {
      writeFileSync(vendored, original + '# drift\n');
      assert.throws(
        () => execFileSync(process.execPath, [script], { encoding: 'utf8' }),
        /Command failed|DRIFT/,
      );
      execFileSync(process.execPath, [script, '--write'], { encoding: 'utf8' });
      assert.equal(readFileSync(vendored, 'utf8'), original);
    } finally {
      writeFileSync(vendored, original);
    }
  });
});
