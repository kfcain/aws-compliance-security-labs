import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CR26_RULES,
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

  it('lists FedRAMP CR26 KSIs pinned to 2026.10.08.01', () => {
    assert.equal(KSI_OVERLAY_VERSION, '2026.10.08.01');
    assert.match(FEDRAMP_20X_KSI['KSI-IAM-APM'], /Passwordless/);
    assert.match(CR26_RULES['VDR-CSO-DET'], /Vulnerability Detection/);
    const apm = resolveKsi('KSI-IAM-APM');
    assert.match(apm.statement, /phishing-resistant MFA/);
    assert.equal(apm.kind, undefined);
    const rule = resolveKsi('VDR-CSO-DET');
    assert.equal(rule.kind, 'FRR');
    assert.match(rule.statement, /vulnerability detection/i);
  });

  it('resolveKsi rejects retired ids and unknown ids', () => {
    for (const retired of [
      'KSI-IAM-MFA',
      'KSI-AFR-PVL',
      'KSI-AFR-VDR',
      'KSI-AFR-MAS',
      'KSI-AFR-SCN',
      'KSI-SVC-SEC',
      'KSI-SVC-SNT',
      'KSI-SVC-ENC',
      'KSI-SCR-SRA',
      'KSI-SCR-TPM',
      'KSI-CMT-CHG',
      'KSI-INR-IRP',
      'KSI-INR-PRC',
      'KSI-RPL-BKP',
    ]) {
      assert.throws(() => resolveKsi(retired), /unknown FedRAMP CR26 identifier/);
    }
    const current = resolveKsi('KSI-IAM-ELP');
    assert.equal(current.legacy, undefined);
    assert.throws(() => resolveKsi('KSI-NOPE-XXX'), /unknown FedRAMP CR26 identifier/);
    // prototype keys must not resolve
    assert.throws(() => resolveKsi('constructor'), /unknown FedRAMP CR26 identifier/);
  });

  it('maps a control from fixtures (offline)', async () => {
    const result = await mapControl('IAC-06', {
      frameworks: [
        TARGET_FRAMEWORKS.nist_800_53_r5,
        TARGET_FRAMEWORKS.iso_27001_2022,
        TARGET_FRAMEWORKS.pci_dss_4,
      ],
      ksi: ['KSI-IAM-APM'],
      fetchImpl: fixtureFetch(),
    });
    assert.equal(result.scf_control_id, 'IAC-06');
    assert.deepEqual(result.framework_mappings[TARGET_FRAMEWORKS.nist_800_53_r5], [
      'IA-02(01)',
      'IA-02(02)',
    ]);
    // ISO has an empty crosswalk in the fixture -> omitted from mappings
    assert.equal(result.framework_mappings[TARGET_FRAMEWORKS.iso_27001_2022], undefined);
    assert.equal(result.fedramp_20x_ksi['KSI-IAM-APM'], FEDRAMP_20X_KSI['KSI-IAM-APM']);
    assert.match(result.fedramp_20x_ksi_detail['KSI-IAM-APM'].statement, /phishing-resistant MFA/);
    assert.equal(result.fedramp_20x_ksi_detail['KSI-IAM-APM'].kind, undefined);
  });

  it('per-control ksi applied via ksi_by_control (regression: lab-level stamping)', async () => {
    const mapping = await mapLab(
      {
        lab_id: 'test-lab',
        scf_controls: ['IAC-06', 'MON-01'],
        ksi_by_control: {
          'IAC-06': ['KSI-IAM-APM'],
          'MON-01': ['KSI-MLA-EVC'],
        },
        ksi: ['KSI-IAM-APM', 'KSI-MLA-EVC'],
        frameworks: [TARGET_FRAMEWORKS.nist_800_53_r5],
      },
      { fetchImpl: fixtureFetch() },
    );
    const byId = Object.fromEntries(mapping.controls.map((c) => [c.scf_control_id, c]));
    // Previously every control carried the identical lab-level KSI block,
    // producing assertions like MON-01 -> KSI-IAM-APM.
    assert.deepEqual(Object.keys(byId['IAC-06'].fedramp_20x_ksi), ['KSI-IAM-APM']);
    assert.deepEqual(Object.keys(byId['MON-01'].fedramp_20x_ksi), ['KSI-MLA-EVC']);
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
          ksi_by_control: { 'MON-01': ['KSI-MLA-EVC'] },
        }),
      /unknown control MON-01/,
    );
    assert.throws(
      () =>
        validateLabSpec({
          lab_id: 'x',
          scf_controls: ['IAC-06'],
          ksi_by_control: { 'IAC-06': ['KSI-IAM-APM'] },
          ksi: ['KSI-IAM-APM', 'KSI-MLA-EVC'],
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
      /unknown FedRAMP CR26 identifier/,
    );
  });

  it('ksiForControl falls back to legacy flat list', () => {
    assert.deepEqual(
      ksiForControl({ ksi: ['KSI-IAM-ELP'] }, 'ANY'),
      ['KSI-IAM-ELP'],
    );
    assert.deepEqual(
      ksiForControl({ ksi_by_control: { 'IAC-06': ['KSI-IAM-APM'] } }, 'IAC-06'),
      ['KSI-IAM-APM'],
    );
    assert.deepEqual(
      ksiForControl({ ksi_by_control: { 'IAC-06': ['KSI-IAM-APM'] } }, 'MON-01'),
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

  it('every overlay id is in the CR26 pin and aliases are retired', () => {
    assert.deepEqual(KSI_ALIASES, {});
    for (const id of Object.keys(FEDRAMP_20X_KSI)) {
      assert.match(id, /^KSI-[A-Z]+-[A-Z0-9]+$/);
      assert.ok(resolveKsi(id).statement, id);
    }
    for (const id of Object.keys(CR26_RULES)) {
      assert.equal(resolveKsi(id).kind, 'FRR');
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
      ksi: ['KSI-IAM-APM'],
    });
    assert.equal(result.scf_control_id, 'IAC-06');
    assert.ok(result.framework_mappings[TARGET_FRAMEWORKS.nist_800_53_r5]?.length);
    assert.ok(result.framework_mappings[TARGET_FRAMEWORKS.pci_dss_4]?.length);
    assert.equal(result.fedramp_20x_ksi['KSI-IAM-APM'], FEDRAMP_20X_KSI['KSI-IAM-APM']);
  });
});
