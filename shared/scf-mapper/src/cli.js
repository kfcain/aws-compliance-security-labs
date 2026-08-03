#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { mapLab, TARGET_FRAMEWORKS, FEDRAMP_20X_KSI, KSI_OVERLAY_VERSION } from './index.js';

function usage() {
  console.log(`Usage:
  scf-map <lab-spec.json> [--out mapping.json] [--strict]
  scf-map --list-frameworks
  scf-map --list-ksi

Options:
  --strict   Exit non-zero when a requested framework yields zero crosswalk hits

Lab spec shape:
  {
    "lab_id": "...",
    "scf_controls": ["IAC-06"],
    "ksi_by_control": { "IAC-06": ["KSI-IAM-MFA"] },
    "ksi": ["KSI-IAM-MFA"],          // union of ksi_by_control (legacy consumers)
    "frameworks": ["general-nist-800-53-r5-2"]
  }
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
    console.log(JSON.stringify({ version: KSI_OVERLAY_VERSION, ksi: FEDRAMP_20X_KSI }, null, 2));
    return;
  }

  const strict = args.includes('--strict');
  const positional = args.filter((a) => !a.startsWith('--'));
  const specPath = resolve(positional[0]);
  const outIdx = args.indexOf('--out');
  let outPath = resolve(dirname(specPath), 'scf-mapping.generated.json');
  if (outIdx >= 0) {
    const outArg = args[outIdx + 1];
    if (!outArg || outArg.startsWith('--')) {
      throw new Error('--out requires a file path argument');
    }
    outPath = resolve(outArg);
  }

  let spec;
  try {
    spec = JSON.parse(readFileSync(specPath, 'utf8'));
  } catch (err) {
    throw new Error(`cannot read lab spec ${specPath}: ${err.message}`);
  }

  const mapping = await mapLab(spec);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(mapping, null, 2) + '\n');
  console.log(`Wrote ${outPath}`);
  console.log(
    `Mapped ${mapping.controls.length} SCF controls across ${
      Object.keys(mapping.coverage_summary.frameworks_with_hits).length
    } frameworks`,
  );

  const missing = mapping.coverage_summary.frameworks_requested_without_hits ?? [];
  if (missing.length) {
    console.warn(
      `WARNING: ${spec.lab_id}: requested frameworks with ZERO crosswalk hits: ${missing.join(', ')}`,
    );
    if (strict) {
      console.error('--strict: treating unmapped requested frameworks as failure');
      process.exit(2);
    }
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
