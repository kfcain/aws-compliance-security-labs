#!/usr/bin/env node
import { readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const labsRoot = join(root, 'labs');
const cli = join(root, 'shared/scf-mapper/src/cli.js');

for (const name of readdirSync(labsRoot).sort()) {
  const lab = join(labsRoot, name);
  const spec = join(lab, 'scf/lab-spec.json');
  if (!existsSync(spec)) continue;
  const out = join(lab, 'scf/scf-mapping.generated.json');
  console.log('Mapping', name);
  const r = spawnSync(process.execPath, [cli, spec, '--out', out], { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}
console.log('Done.');
