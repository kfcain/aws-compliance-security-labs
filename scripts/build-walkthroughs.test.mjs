import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LAB_OPS } from './lab-operator-data.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const script = join(root, 'scripts/build-walkthroughs.mjs');
const catalog = JSON.parse(readFileSync(join(root, 'labs/catalog.json'), 'utf8'));

describe('build-walkthroughs', () => {
  it('covers every catalog lab exactly once', () => {
    const ids = catalog.labs.map((lab) => lab.id).sort();
    assert.deepEqual(Object.keys(LAB_OPS).sort(), ids);
    for (const id of ids) {
      JSON.parse(LAB_OPS[id].liveEvent.json);
    }
  });

  it('writes the playbook and a WALKTHROUGH.md per lab', () => {
    const log = execFileSync(process.execPath, [script], { encoding: 'utf8' });
    assert.match(log, /walkthroughs built/);
    assert.equal(existsSync(join(root, 'docs/walkthroughs/00-operator-playbook.md')), true);
    for (const lab of catalog.labs) {
      const path = join(root, lab.path, 'WALKTHROUGH.md');
      assert.equal(existsSync(path), true, path);
      const text = readFileSync(path, 'utf8');
      assert.match(text, /## 1. Configure/);
      assert.match(text, /## 2. Collect evidence/);
      assert.match(text, /## 3. Document/);
      assert.match(text, /cat > payload\.json/);
      assert.match(text, /evidence_uri/);
      assert.match(text, /evidence-package/);
      assert.equal(text.includes(lab.id), true);
    }
    const playbook = readFileSync(join(root, 'docs/walkthroughs/00-operator-playbook.md'), 'utf8');
    assert.match(playbook, /## 1. Configure/);
    assert.match(playbook, /## 2. Collect evidence/);
    assert.match(playbook, /## 3. Document/);
  });

  it('passes --check after a build', () => {
    execFileSync(process.execPath, [script]);
    const log = execFileSync(process.execPath, [script, '--check'], { encoding: 'utf8' });
    assert.match(log, /walkthroughs check OK/);
  });
});
