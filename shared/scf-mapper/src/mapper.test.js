import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FEDRAMP_20X_KSI,
  KSI_ALIASES,
  KSI_OVERLAY_VERSION,
  TARGET_FRAMEWORKS,
  ksiForControl,
  mapControl,
  mapLab,
  resolveKsi,
  summarizeCoverage,
  validateLabSpec,
} from './index.js';

const fixturesDir = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/controls');

/** Hermetic fetch: serves fixture control JSON, records requested URLs. */
function fixtureFetch() {
  const requested = [];
  const impl = async (url) => {
    requested.push(url);
    const match = url.match(/\/controls\/([^/]+)\.json$/);
    const controlId = match ? decodeURIComponent(match[1]) : null;
    try {
      const body = readFileSync(join(fixturesDir, `${controlId}.json`), 'utf8');
      return { ok: true, status: 200, text: async () => body };
    } catch {
      return { ok: false, status: 404, text: async () => 'not found' };
    }
  };
  impl.requested = requested;
  return impl;
}

describe('scf-mapper', () => {
  it('exposes target frameworks', () => {
    assert.equal(TARGET_FRAMEWORKS.nist_800_53_r5, 'general-nist-800-53-r5-2');
    assert.ok(TARGET_FRAMEWORKS.pci_dss_4);
    assert.ok(TARGET_FRAMEWORKS.cmmc_l2);
  });

  it('lists FedRAMP 20x KSIs with a pinned overlay version', () => {
    assert.match(FEDRAMP_20X_KSI['KSI-AFR-VDR'], /vulnerability/i);
    assert.match(FEDRAMP_20X_KSI['KSI-IAM-MFA'], /multi-factor/i);
    assert.match(KSI_OVERLAY_VERSION, /^\d{4}-\d{2}/);
  });

  it('resolveKsi annotates legacy aliases and rejects unknown ids', () => {
    const mfa = resolveKsi('KSI-IAM-MFA');
    assert.equal(mfa.legacy, true);
    assert.equal(mfa.alias_of, 'KSI-IAM-APM');
    const current = resolveKsi('KSI-IAM-ELP');
    assert.equal(current.legacy, undefined);
    assert.throws(() => resolveKsi('KSI-NOPE-XXX'), /unknown FedRAMP 20x KSI/);
    // prototype keys must not resolve
    assert.throws(() => resolveKsi('constructor'), /unknown FedRAMP 20x KSI/);
  });

  it('maps a control from fixtures (offline)', async () => {
    const result = await mapControl('IAC-06', {
      frameworks: [
        TARGET_FRAMEWORKS.nist_800_53_r5,
        TARGET_FRAMEWORKS.iso_27001_2022,
        TARGET_FRAMEWORKS.pci_dss_4,
      ],
      ksi: ['KSI-IAM-MFA'],
      fetchImpl: fixtureFetch(),
    });
    assert.equal(result.scf_control_id, 'IAC-06');
    assert.deepEqual(result.framework_mappings[TARGET_FRAMEWORKS.nist_800_53_r5], [
      'IA-02(01)',
      'IA-02(02)',
    ]);
    // ISO has an empty crosswalk in the fixture -> omitted from mappings
    assert.equal(result.framework_mappings[TARGET_FRAMEWORKS.iso_27001_2022], undefined);
    assert.equal(result.fedramp_20x_ksi['KSI-IAM-MFA'], FEDRAMP_20X_KSI['KSI-IAM-MFA']);
    assert.equal(result.fedramp_20x_ksi_detail['KSI-IAM-MFA'].alias_of, 'KSI-IAM-APM');
  });

  it('per-control ksi applied via ksi_by_control (regression: lab-level stamping)', async () => {
    const mapping = await mapLab(
      {
        lab_id: 'test-lab',
        scf_controls: ['IAC-06', 'MON-01'],
        ksi_by_control: {
          'IAC-06': ['KSI-IAM-MFA'],
          'MON-01': ['KSI-AFR-PVL'],
        },
        ksi: ['KSI-IAM-MFA', 'KSI-AFR-PVL'],
        frameworks: [TARGET_FRAMEWORKS.nist_800_53_r5],
      },
      { fetchImpl: fixtureFetch() },
    );
    const byId = Object.fromEntries(mapping.controls.map((c) => [c.scf_control_id, c]));
    // Previously every control carried the identical lab-level KSI block,
    // producing assertions like MON-01 -> KSI-IAM-MFA.
    assert.deepEqual(Object.keys(byId['IAC-06'].fedramp_20x_ksi), ['KSI-IAM-MFA']);
    assert.deepEqual(Object.keys(byId['MON-01'].fedramp_20x_ksi), ['KSI-AFR-PVL']);
    assert.equal(mapping.ksi_overlay_version, KSI_OVERLAY_VERSION);
  });

  it('frameworks_requested_without_hits reported (regression: silent ISO drop)', async () => {
    const mapping = await mapLab(
      {
        lab_id: 'test-lab',
        scf_controls: ['MON-01'],
        frameworks: [TARGET_FRAMEWORKS.nist_800_53_r5, TARGET_FRAMEWORKS.iso_27001_2022],
      },
      { fetchImpl: fixtureFetch() },
    );
    assert.deepEqual(mapping.coverage_summary.frameworks_requested_without_hits, [
      TARGET_FRAMEWORKS.iso_27001_2022,
    ]);
  });

  it('validateLabSpec enforces ksi union and known controls', () => {
    assert.throws(
      () =>
        validateLabSpec({
          lab_id: 'x',
          scf_controls: ['IAC-06'],
          ksi_by_control: { 'MON-01': ['KSI-AFR-PVL'] },
        }),
      /unknown control MON-01/,
    );
    assert.throws(
      () =>
        validateLabSpec({
          lab_id: 'x',
          scf_controls: ['IAC-06'],
          ksi_by_control: { 'IAC-06': ['KSI-IAM-MFA'] },
          ksi: ['KSI-IAM-MFA', 'KSI-AFR-PVL'],
        }),
      /union/,
    );
    assert.throws(
      () =>
        validateLabSpec({
          lab_id: 'x',
          scf_controls: ['IAC-06'],
          ksi_by_control: { 'IAC-06': ['KSI-NOPE'] },
        }),
      /unknown FedRAMP 20x KSI/,
    );
  });

  it('ksiForControl falls back to legacy flat list', () => {
    assert.deepEqual(
      ksiForControl({ ksi: ['KSI-IAM-ELP'] }, 'ANY'),
      ['KSI-IAM-ELP'],
    );
    assert.deepEqual(
      ksiForControl({ ksi_by_control: { 'IAC-06': ['KSI-IAM-MFA'] } }, 'IAC-06'),
      ['KSI-IAM-MFA'],
    );
    assert.deepEqual(
      ksiForControl({ ksi_by_control: { 'IAC-06': ['KSI-IAM-MFA'] } }, 'MON-01'),
      [],
    );
  });

  it('summarizeCoverage counts controls per framework', () => {
    const summary = summarizeCoverage(
      [
        { framework_mappings: { fw1: ['a'], fw2: ['b'] } },
        { framework_mappings: { fw1: ['c'] } },
      ],
      ['fw1', 'fw2', 'fw3'],
    );
    assert.deepEqual(summary.frameworks_with_hits, { fw1: 2, fw2: 1 });
    assert.deepEqual(summary.frameworks_requested_without_hits, ['fw3']);
  });

  it('fetch failure surfaces a clear error (404 is fatal, no retry storm)', async () => {
    await assert.rejects(
      mapControl('NO-SUCH', { fetchImpl: fixtureFetch() }),
      /SCF API 404/,
    );
  });

  it('every alias target is a defined KSI', () => {
    for (const [alias, target] of Object.entries(KSI_ALIASES)) {
      assert.ok(FEDRAMP_20X_KSI[alias], `alias ${alias} must be defined`);
      if (target) assert.ok(FEDRAMP_20X_KSI[target], `alias target ${target} must be defined`);
    }
  });

  // Live-network integration test: opt in with SCF_LIVE=1 (runs in the
  // scheduled scf-refresh workflow; local/CI default suites stay offline).
  it('maps IAC-06 MFA control from live SCF API', { skip: !process.env.SCF_LIVE }, async () => {
    const result = await mapControl('IAC-06', {
      frameworks: [
        TARGET_FRAMEWORKS.nist_800_53_r5,
        TARGET_FRAMEWORKS.nist_800_171_r3,
        TARGET_FRAMEWORKS.pci_dss_4,
        TARGET_FRAMEWORKS.fedramp_mod,
      ],
      ksi: ['KSI-IAM-MFA'],
    });
    assert.equal(result.scf_control_id, 'IAC-06');
    assert.ok(result.framework_mappings[TARGET_FRAMEWORKS.nist_800_53_r5]?.length);
    assert.ok(result.framework_mappings[TARGET_FRAMEWORKS.pci_dss_4]?.length);
    assert.equal(result.fedramp_20x_ksi['KSI-IAM-MFA'], FEDRAMP_20X_KSI['KSI-IAM-MFA']);
  });
});
