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
  .replaceAll('../walkthroughs/', 'walkthroughs/')
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
  const outDir = join(dest, 'labs', name);
  const htmlSrc = join(labsRoot, name, 'index.html');
  const walkSrc = join(labsRoot, name, 'WALKTHROUGH.md');
  if (!existsSync(htmlSrc) && !existsSync(walkSrc)) continue;
  mkdirSync(outDir, { recursive: true });
  if (existsSync(htmlSrc)) {
    const page = readFileSync(htmlSrc, 'utf8').replaceAll('href="./index.html"', 'href="/"');
    writeFileSync(join(outDir, 'index.html'), page);
  }
  if (existsSync(walkSrc)) {
    writeFileSync(join(outDir, 'WALKTHROUGH.md'), readFileSync(walkSrc));
  }
}

const playbookSrc = join(root, 'docs/walkthroughs/00-operator-playbook.md');
if (existsSync(playbookSrc)) {
  mkdirSync(join(dest, 'walkthroughs'), { recursive: true });
  writeFileSync(join(dest, 'walkthroughs/00-operator-playbook.md'), readFileSync(playbookSrc));
}

console.log(`assembled learn site at ${dest}`);
