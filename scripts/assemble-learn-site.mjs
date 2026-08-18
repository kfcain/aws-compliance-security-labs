#!/usr/bin/env node
/**
 * Copy the learning hub and per-lab walkthrough pages into a static site
 * directory for GitHub Pages / Workers. Rewrites hub paths so they work
 * from the site root.
 */
import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dest = resolve(process.argv[2] || join(root, '_site'));

const hub = readFileSync(join(root, 'docs/learn/index.html'), 'utf8')
  .replaceAll('../../labs/', 'labs/')
  .replaceAll(
    '../../COVERAGE.md',
    'https://github.com/kfcain/aws-compliance-security-labs/blob/main/COVERAGE.md',
  )
  .replaceAll(
    '../../RISKS.md',
    'https://github.com/kfcain/aws-compliance-security-labs/blob/main/RISKS.md',
  )
  .replaceAll(
    '../RISK-METHODOLOGY.md',
    'https://github.com/kfcain/aws-compliance-security-labs/blob/main/docs/RISK-METHODOLOGY.md',
  );

mkdirSync(dest, { recursive: true });
writeFileSync(join(dest, 'index.html'), hub);
writeFileSync(join(dest, '.nojekyll'), '');

const labsRoot = join(root, 'labs');
for (const name of readdirSync(labsRoot)) {
  const src = join(labsRoot, name, 'index.html');
  if (!existsSync(src)) continue;
  const outDir = join(dest, 'labs', name);
  mkdirSync(outDir, { recursive: true });
  const page = readFileSync(src, 'utf8').replaceAll('href="./index.html"', 'href="/"');
  writeFileSync(join(outDir, 'index.html'), page);
}

console.log(`assembled learn site at ${dest}`);
