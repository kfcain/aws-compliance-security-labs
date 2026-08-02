import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FEDRAMP_20X_KSI, TARGET_FRAMEWORKS, mapControl } from './index.js';

describe('scf-mapper', () => {
  it('exposes target frameworks', () => {
    assert.equal(TARGET_FRAMEWORKS.nist_800_53_r5, 'general-nist-800-53-r5-2');
    assert.ok(TARGET_FRAMEWORKS.pci_dss_4);
  });

  it('lists FedRAMP 20x KSIs', () => {
    assert.match(FEDRAMP_20X_KSI['KSI-AFR-VDR'], /vulnerability/i);
    assert.match(FEDRAMP_20X_KSI['KSI-IAM-MFA'], /multi-factor/i);
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
