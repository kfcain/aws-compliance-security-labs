#!/usr/bin/env node
/**
 * Offline post-processor for labs/<id>/scf/scf-mapping.generated.json.
 *
 * The SCF API is not reachable from every environment, but two classes of
 * defect in the generated crosswalks are fixable from data already on disk:
 *
 *  1. Per-control KSI traceability — the original generator stamped the
 *     lab-level KSI list onto every control (producing assertions like
 *     MON-01 -> KSI-IAM-MFA). This rewrites each control's `fedramp_20x_ksi`
 *     from the lab spec's `ksi_by_control` map and annotates legacy aliases.
 *  2. Silent framework gaps — requested frameworks with zero crosswalk hits
 *     (ISO 27001 in 9 labs; the CMMC/800-171 r2 chain until the scheduled
 *     live regeneration backfills it) now appear in
 *     `coverage_summary.frameworks_requested_without_hits` with a reason.
 *
 * Deterministic by construction: no wall-clock stamps; output derives only
 * from the spec + the existing generated file. `--check` exits non-zero if
 * the files on disk differ from a fresh post-process (CI drift gate).
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  KSI_OVERLAY_VERSION,
  ksiForControl,
  resolveKsi,
  summarizeCoverage,
  validateLabSpec,
} from '../shared/scf-mapper/src/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');

// A framework can be hit-less either because SCF has no crosswalk for the
// declared controls (ISO 27001 in 9 labs) or because it was requested after
// the last live generation (the CMMC / 800-171 r2 chain). The generated file
// does not record which — the scheduled scf-refresh run resolves both.
const NO_HITS_REASON =
  'no crosswalk hits in the current generated data; confirmed or backfilled by the scheduled scf-refresh regeneration';

function postprocess(spec, generated) {
  validateLabSpec(spec);
  const controls = generated.controls.map((control) => {
    const ids = ksiForControl(spec, control.scf_control_id);
    const ksi = {};
    const detail = {};
    for (const id of ids) {
      const entry = resolveKsi(id);
      ksi[id] = entry.description;
      detail[id] = entry;
    }
    return { ...control, fedramp_20x_ksi: ksi, fedramp_20x_ksi_detail: detail };
  });

  const summary = summarizeCoverage(controls, spec.frameworks);
  summary.frameworks_requested = spec.frameworks;
  summary.frameworks_requested_without_hits = (
    summary.frameworks_requested_without_hits ?? []
  ).map((fw) => ({ framework: fw, reason: NO_HITS_REASON }));

  return {
    ...generated,
    ksi_overlay_version: KSI_OVERLAY_VERSION,
    controls,
    coverage_summary: summary,
  };
}

const labDirs = readdirSync(join(root, 'labs'), { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

let drift = 0;
let processed = 0;
for (const lab of labDirs) {
  const specPath = join(root, 'labs', lab, 'scf/lab-spec.json');
  const mappingPath = join(root, 'labs', lab, 'scf/scf-mapping.generated.json');
  if (!existsSync(specPath) || !existsSync(mappingPath)) continue;
  const spec = JSON.parse(readFileSync(specPath, 'utf8'));
  const generated = JSON.parse(readFileSync(mappingPath, 'utf8'));
  const output = JSON.stringify(postprocess(spec, generated), null, 2) + '\n';
  processed += 1;
  if (output === readFileSync(mappingPath, 'utf8')) continue;
  if (check) {
    console.error(`DRIFT: ${lab}/scf/scf-mapping.generated.json is not post-processed`);
    drift += 1;
  } else {
    writeFileSync(mappingPath, output);
    console.log(`post-processed ${lab}`);
  }
}

if (check && drift) {
  console.error(`\n${drift} mapping file(s) out of date. Run: node scripts/postprocess-mappings.mjs`);
  process.exit(1);
}
console.log(
  check
    ? `postprocess check OK — ${processed} mapping files current (overlay ${KSI_OVERLAY_VERSION})`
    : `done — ${processed} mapping files (overlay ${KSI_OVERLAY_VERSION})`,
);
