#!/usr/bin/env node
/**
 * Validates labs/catalog.json against its JSON schema (when present) and
 * cross-checks every entry against the filesystem and each lab's
 * scf/lab-spec.json. Exits non-zero on any inconsistency so CI can gate on
 * catalog/spec/filesystem drift.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const catalogPath = join(root, 'labs/catalog.json');
const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));

const errors = [];
const err = (msg) => errors.push(msg);

// --- lightweight structural schema check (full JSON Schema arrives with
// labs/catalog.schema.json; this validator enforces the invariants CI needs) ---
const REQUIRED_LAB_KEYS = [
  'id', 'title', 'repo_name', 'path', 'summary', 'primary_risk',
  'scf_controls', 'ksi', 'frameworks', 'aws_services', 'source_repo',
  'status',
];
const VALID_STATUSES = new Set(['skeleton', 'functional', 'hardened']);
const ID_RE = /^\d{2}-[a-z0-9-]+$/;
const REPO_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

if (!Array.isArray(catalog.labs) || catalog.labs.length === 0) {
  err('catalog.labs must be a non-empty array');
}

const seenIds = new Set();
for (const lab of catalog.labs ?? []) {
  const id = lab.id ?? '<missing id>';
  for (const key of REQUIRED_LAB_KEYS) {
    if (!(key in lab)) err(`${id}: missing key "${key}"`);
  }
  if (lab.id && !ID_RE.test(lab.id)) err(`${id}: id does not match ${ID_RE}`);
  if (lab.status && !VALID_STATUSES.has(lab.status)) err(`${id}: invalid status "${lab.status}"`);
  if (lab.repo_name && !REPO_RE.test(lab.repo_name)) err(`${id}: invalid repo_name "${lab.repo_name}"`);
  if (seenIds.has(lab.id)) err(`${id}: duplicate id`);
  seenIds.add(lab.id);

  if (lab.path) {
    const labDir = join(root, lab.path);
    if (!existsSync(labDir)) { err(`${id}: path "${lab.path}" does not exist`); continue; }
    for (const rel of ['README.md', 'RISK.md', 'SPEC.md', 'scf/lab-spec.json',
      'infrastructure/template.yaml', 'src/handler.py', 'package.json']) {
      if (!existsSync(join(labDir, rel))) err(`${id}: missing ${rel}`);
    }

    const specPath = join(labDir, 'scf/lab-spec.json');
    if (existsSync(specPath)) {
      const spec = JSON.parse(readFileSync(specPath, 'utf8'));
      if (spec.lab_id !== lab.id) err(`${id}: lab-spec lab_id "${spec.lab_id}" != catalog id`);
      if (spec.title !== lab.title) err(`${id}: lab-spec title differs from catalog`);
      const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      if (!eq(spec.scf_controls, lab.scf_controls)) err(`${id}: scf_controls differ between catalog and lab-spec`);
      if (!eq(spec.frameworks, lab.frameworks)) err(`${id}: frameworks differ between catalog and lab-spec`);
      if (!eq(spec.ksi, lab.ksi)) err(`${id}: ksi differ between catalog and lab-spec`);
      // When the per-control KSI map exists, the flat ksi list must be its union.
      if (spec.ksi_by_control) {
        const union = [...new Set(Object.values(spec.ksi_by_control).flat())].sort();
        const flat = [...(spec.ksi ?? [])].sort();
        if (!eq(union, flat)) err(`${id}: ksi is not the union of ksi_by_control values`);
        for (const control of Object.keys(spec.ksi_by_control)) {
          if (!spec.scf_controls.includes(control)) {
            err(`${id}: ksi_by_control references unknown control "${control}"`);
          }
        }
      }
    }
  }
}

// Every lab directory on disk must be cataloged.
import { readdirSync } from 'node:fs';
const onDisk = readdirSync(join(root, 'labs'), { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name);
for (const dir of onDisk) {
  if (!seenIds.has(dir)) err(`labs/${dir} exists on disk but is not in catalog.json`);
}

if (errors.length) {
  console.error(`catalog validation FAILED (${errors.length} error(s)):`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(`catalog validation OK — ${catalog.labs.length} labs consistent with specs and filesystem`);
