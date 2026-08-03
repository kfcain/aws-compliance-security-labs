#!/usr/bin/env node
/**
 * Generates an OSCAL 1.1.2 component-definition per lab at
 * labs/<id>/scf/oscal-component.json from the post-processed SCF crosswalk.
 *
 * Frameworks with canonical public OSCAL catalogs (NIST 800-53 r5,
 * NIST 800-171 r3, FedRAMP rev5 Moderate) become control-implementations
 * with normalized OSCAL control ids; ISO 27001 / PCI DSS / CMMC identifiers
 * ride as props on each implemented requirement.
 *
 * Deterministic: all UUIDs are UUIDv5 over stable names, no wall-clock
 * stamps (last-modified reuses the crosswalk's generated_at), stable
 * ordering — so `--check` can gate drift in CI.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KSI_OVERLAY_VERSION } from '../shared/scf-mapper/src/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');

// RFC 4122 UUIDv5 (SHA-1, name-based) under the URL namespace.
const URL_NAMESPACE = '6ba7b8119dad11d180b400c04fd430c8';
function uuidv5(name) {
  const namespaceBytes = Buffer.from(URL_NAMESPACE, 'hex');
  const hash = createHash('sha1').update(namespaceBytes).update(name, 'utf8').digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const OSCAL_SOURCES = {
  'general-nist-800-53-r5-2': {
    source:
      'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json',
    description: 'NIST SP 800-53 rev 5 catalog',
    normalize: normalize80053,
  },
  'general-nist-800-171-r3': {
    source:
      'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP-800-171_rev3_catalog.json',
    description: 'NIST SP 800-171 rev 3 catalog',
    normalize: (id) => id.toLowerCase(),
  },
  'usa-federal-gsa-fedramp-5-mod': {
    source:
      'https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json',
    description: 'FedRAMP rev 5 Moderate baseline profile',
    normalize: normalize80053,
  },
};

/** "IA-02(01)" / "IA-2(1)" -> "ia-2.1"; "CA-7" -> "ca-7". */
function normalize80053(id) {
  const match = id.trim().match(/^([A-Za-z]{2})-0*(\d+)(?:\((\d+)\))?/);
  if (!match) return id.toLowerCase();
  const [, family, number, enhancement] = match;
  const base = `${family.toLowerCase()}-${Number(number)}`;
  return enhancement ? `${base}.${Number(enhancement)}` : base;
}

function buildComponentDefinition(labId, mapping) {
  const ns = (...parts) => uuidv5(`aws-compliance-security-labs/${labId}/${parts.join('/')}`);
  const controlImplementations = [];
  for (const [fw, meta] of Object.entries(OSCAL_SOURCES)) {
    const requirements = [];
    for (const control of mapping.controls) {
      for (const frameworkControl of control.framework_mappings?.[fw] ?? []) {
        const props = [
          { name: 'scf-control', ns: 'https://securecontrolsframework.com', value: control.scf_control_id },
        ];
        for (const ksi of Object.keys(control.fedramp_20x_ksi ?? {})) {
          props.push({ name: 'fedramp-20x-ksi', ns: 'https://fedramp.gov/20x', value: ksi });
        }
        requirements.push({
          uuid: ns('requirement', fw, control.scf_control_id, frameworkControl),
          'control-id': meta.normalize(frameworkControl),
          description:
            `Implemented by lab ${labId} via SCF ${control.scf_control_id} ` +
            `(${control.title}): automated validation with persisted evidence.`,
          props,
        });
      }
    }
    if (requirements.length) {
      requirements.sort((a, b) => a.uuid.localeCompare(b.uuid));
      controlImplementations.push({
        uuid: ns('implementation', fw),
        source: meta.source,
        description: `${meta.description} — controls satisfied by ${labId}`,
        'implemented-requirements': requirements,
      });
    }
  }

  const otherFrameworkProps = [];
  for (const fw of mapping.coverage_summary?.frameworks_requested ?? []) {
    if (OSCAL_SOURCES[fw]) continue;
    for (const control of mapping.controls) {
      for (const frameworkControl of control.framework_mappings?.[fw] ?? []) {
        otherFrameworkProps.push({
          name: 'framework-mapping',
          ns: 'https://securecontrolsframework.com',
          class: fw,
          value: `${control.scf_control_id}:${frameworkControl}`,
        });
      }
    }
  }
  otherFrameworkProps.sort((a, b) => `${a.class}${a.value}`.localeCompare(`${b.class}${b.value}`));

  return {
    'component-definition': {
      uuid: ns('component-definition'),
      metadata: {
        title: `AWS Compliance Lab ${labId} — component definition`,
        'last-modified': mapping.generated_at,
        version: mapping.ksi_overlay_version ?? KSI_OVERLAY_VERSION,
        'oscal-version': '1.1.2',
        remarks:
          'Generated by scripts/build-oscal.mjs from the SCF crosswalk; ' +
          'frameworks without public OSCAL catalogs are carried as props.',
      },
      components: [
        {
          uuid: ns('component'),
          type: 'software',
          title: labId,
          description:
            'Serverless compliance validation lab: EventBridge-scheduled Lambda ' +
            'evaluates the control objective against live AWS APIs, persists ' +
            'KMS-encrypted evidence to S3, and raises Security Hub findings on failure.',
          props: [
            { name: 'lab-id', ns: 'https://github.com/kfcain/aws-compliance-security-labs', value: labId },
            ...otherFrameworkProps,
          ],
          'control-implementations': controlImplementations,
        },
      ],
    },
  };
}

const labDirs = readdirSync(join(root, 'labs'), { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

let drift = 0;
let written = 0;
for (const lab of labDirs) {
  const mappingPath = join(root, 'labs', lab, 'scf/scf-mapping.generated.json');
  if (!existsSync(mappingPath)) continue;
  const mapping = JSON.parse(readFileSync(mappingPath, 'utf8'));
  const outPath = join(root, 'labs', lab, 'scf/oscal-component.json');
  const output = JSON.stringify(buildComponentDefinition(lab, mapping), null, 2) + '\n';
  const current = existsSync(outPath) ? readFileSync(outPath, 'utf8') : null;
  written += 1;
  if (current === output) continue;
  if (check) {
    console.error(`DRIFT: ${outPath} is stale`);
    drift += 1;
  } else {
    writeFileSync(outPath, output);
    console.log(`wrote labs/${lab}/scf/oscal-component.json`);
  }
}
if (check && drift) {
  console.error('\nRun: node scripts/build-oscal.mjs');
  process.exit(1);
}
console.log(`oscal ${check ? 'check OK' : 'built'} — ${written} component definitions`);
