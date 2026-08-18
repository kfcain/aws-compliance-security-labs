import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const script = join(root, 'scripts/build-learn.mjs');
const out = join(root, 'docs/learn/index.html');
const catalog = JSON.parse(readFileSync(join(root, 'labs/catalog.json'), 'utf8'));

function run(args = []) {
  return execFileSync(process.execPath, [script, ...args], { encoding: 'utf8' });
}

function extractData(html) {
  const marker = 'window.LEARN_DATA = ';
  const start = html.indexOf(marker);
  assert.notEqual(start, -1, 'LEARN_DATA payload missing');
  const jsonStart = start + marker.length;
  const jsonEnd = html.indexOf(';</script>', jsonStart);
  assert.notEqual(jsonEnd, -1, 'LEARN_DATA payload is not closed');
  return JSON.parse(html.slice(jsonStart, jsonEnd));
}

describe('build-learn', () => {
  it('writes a hub that embeds every catalog lab once on the path', () => {
    const log = run();
    assert.match(log, /wrote .*docs\/learn\/index\.html/);
    assert.equal(existsSync(out), true);
    const html = readFileSync(out, 'utf8');
    const data = extractData(html);
    const catalogIds = catalog.labs.map((lab) => lab.id).sort();
    assert.deepEqual(data.labs.map((lab) => lab.id).sort(), catalogIds);
    const pathIds = data.path.flatMap((track) => track.labs).sort();
    assert.deepEqual(pathIds, catalogIds);
    assert.equal(data.path.length, 5);
    for (const lab of catalog.labs) {
      assert.equal(html.includes(lab.id), true, `missing ${lab.id}`);
    }
  });

  it('is deterministic and --check passes after a build', () => {
    run();
    const first = readFileSync(out, 'utf8');
    run();
    const second = readFileSync(out, 'utf8');
    assert.equal(first, second);
    const log = run(['--check']);
    assert.match(log, /learn check OK/);
  });

  it('fails --check when the hub is stale', () => {
    run();
    const original = readFileSync(out, 'utf8');
    try {
      writeFileSync(out, original.replace('Learning hub', 'stale hub'));
      assert.throws(
        () => run(['--check']),
        /DRIFT|Command failed/,
      );
    } finally {
      writeFileSync(out, original);
    }
  });
});
