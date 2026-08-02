#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { mapLab, TARGET_FRAMEWORKS, FEDRAMP_20X_KSI } from './index.js';

function usage() {
  console.log(`Usage:
  scf-map <lab-spec.json> [--out mapping.json]
  scf-map --list-frameworks
  scf-map --list-ksi

Lab spec shape:
  { "lab_id": "...", "scf_controls": ["IAC-06"], "ksi": ["KSI-IAM-MFA"] }
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    usage();
    process.exit(0);
  }
  if (args[0] === '--list-frameworks') {
    console.log(JSON.stringify(TARGET_FRAMEWORKS, null, 2));
    return;
  }
  if (args[0] === '--list-ksi') {
    console.log(JSON.stringify(FEDRAMP_20X_KSI, null, 2));
    return;
  }

  const specPath = resolve(args[0]);
  const outIdx = args.indexOf('--out');
  const outPath =
    outIdx >= 0
      ? resolve(args[outIdx + 1])
      : resolve(dirname(specPath), 'scf-mapping.generated.json');

  const spec = JSON.parse(readFileSync(specPath, 'utf8'));
  const mapping = await mapLab(spec);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(mapping, null, 2) + '\n');
  console.log(`Wrote ${outPath}`);
  console.log(
    `Mapped ${mapping.controls.length} SCF controls across ${
      Object.keys(mapping.coverage_summary.frameworks_with_hits).length
    } frameworks`,
  );
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
