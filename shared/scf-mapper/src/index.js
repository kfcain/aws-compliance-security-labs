/**
 * SCF API mapper — live crosswalks for NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP.
 * API: https://grcengclub.github.io/scf-api/
 */

export const SCF_API_BASE =
  process.env.SCF_API_BASE ?? 'https://grcengclub.github.io/scf-api/api';

/** Framework IDs used across compliance labs */
export const TARGET_FRAMEWORKS = {
  nist_800_53_r5: 'general-nist-800-53-r5-2',
  nist_800_53_r5_mod: 'general-nist-800-53-r5-2-mod',
  nist_800_171_r3: 'general-nist-800-171-r3',
  nist_800_171_r2: 'general-nist-800-171-r2',
  iso_27001_2022: 'general-iso-27001-2022',
  pci_dss_4: 'general-pci-dss-4-0-1',
  fedramp_mod: 'usa-federal-gsa-fedramp-5-mod',
  fedramp_high: 'usa-federal-gsa-fedramp-5-high',
  cmmc_l2: 'usa-federal-dow-cmmc-2-level-2',
};

/** FedRAMP 20x / CR26 Key Security Indicators (manual overlay — not in SCF workbook yet) */
export const FEDRAMP_20X_KSI = {
  // Identity
  'KSI-IAM-MFA': 'Phishing-resistant multi-factor authentication (alias)',
  'KSI-IAM-APM': 'Adopt passwordless methods; otherwise strong auth + phishing-resistant MFA',
  'KSI-IAM-ELP': 'Ensure least privilege',
  'KSI-IAM-JIT': 'Authorizing just-in-time',
  'KSI-IAM-AAM': 'Automating account management lifecycle and privileges',
  'KSI-IAM-SNU': 'Securing non-user authentication',
  'KSI-IAM-SUS': 'Responding to suspicious activity on privileged accounts',
  // AFR legacy aliases used by early labs
  'KSI-AFR-VDR': 'Vulnerability detection and response with N1–N5 severity SLAs',
  'KSI-AFR-SCN': 'Significant change notification',
  'KSI-AFR-PVL': 'Persistent validation cadence',
  'KSI-AFR-MAS': 'Minimum assessment scope / authorization boundary',
  // Cloud native
  'KSI-CNA-RNT': 'Restricting network traffic',
  'KSI-CNA-MAT': 'Minimizing attack surface',
  'KSI-CNA-EIS': 'Enforcing intended state',
  'KSI-CNA-OFA': 'Optimizing for availability and rapid recovery',
  'KSI-CNA-RVP': 'Reviewing DoS and unwanted-activity protections',
  'KSI-CNA-DFP': 'Defining functionality and privileges',
  'KSI-CNA-IBP': 'Implementing provider best practices',
  'KSI-CNA-ULN': 'Using logical networking',
  // Service configuration (federal data–critical)
  'KSI-SVC-SNT': 'Secure network traffic / encryption in transit (alias)',
  'KSI-SVC-ENC': 'Encryption at rest (alias)',
  'KSI-SVC-SEC': 'Secrets management (alias)',
  'KSI-SVC-SIN': 'Securing information (encrypt or otherwise protect)',
  'KSI-SVC-ASM': 'Automating secret management',
  'KSI-SVC-ACM': 'Automating configuration management',
  'KSI-SVC-VRI': 'Validating resource integrity',
  'KSI-SVC-VCM': 'Validating communications authenticity/integrity (Class C)',
  'KSI-SVC-PRR': 'Preventing residual risk after changes (Class C; federal customer data)',
  'KSI-SVC-RUD': 'Removing unwanted federal customer data including backups (Class C)',
  'KSI-SVC-EIS': 'Evaluating and improving security',
  // Monitoring
  'KSI-MLA-OSM': 'Operating SIEM capability',
  'KSI-MLA-EVC': 'Evaluating configurations',
  'KSI-MLA-ALA': 'Authorizing log access (Class C)',
  'KSI-MLA-RVL': 'Reviewing logs',
  'KSI-MLA-LET': 'Logging event types inventory',
  // Change
  'KSI-CMT-CHG': 'Change control (alias)',
  'KSI-CMT-LMC': 'Logging modifications to the CSO',
  'KSI-CMT-RMV': 'Redeploying version-controlled resources vs direct modification',
  'KSI-CMT-VTD': 'Validating throughout deployment (automated)',
  'KSI-CMT-RVP': 'Reviewing change procedures',
  // Policy & inventory
  'KSI-PIY-GIV': 'Generating real-time inventories of information resources',
  'KSI-PIY-RSD': 'Reviewing security in the SDLC / Secure by Design',
  'KSI-PIY-RVD': 'Reviewing vulnerability disclosures',
  'KSI-PIY-RES': 'Reviewing executive support',
  'KSI-PIY-RIS': 'Reviewing investments in security',
  // Recovery
  'KSI-RPL-BKP': 'Backup and recovery objectives (alias)',
  'KSI-RPL-RRO': 'Reviewing recovery objectives (RTO/RPO)',
  'KSI-RPL-ARP': 'Aligning recovery plan with objectives',
  'KSI-RPL-ABO': 'Aligning backups with objectives',
  'KSI-RPL-TRC': 'Testing recovery capabilities',
  // Incident / supply chain
  'KSI-INR-IRP': 'Incident response plan (alias)',
  'KSI-INR-PRC': 'Incident response procedures (alias)',
  'KSI-INR-AAR': 'Generating after-action reports',
  'KSI-INR-RIR': 'Reviewing incident response procedures',
  'KSI-INR-RPI': 'Reviewing past incidents for patterns',
  'KSI-SCR-SRA': 'Supply chain risk assessment (alias)',
  'KSI-SCR-TPM': 'Third-party monitoring (alias)',
  'KSI-SCR-MIT': 'Mitigating supply chain risk',
  'KSI-SCR-MON': 'Monitoring supply chain risk',
  'KSI-CED-RAT': 'Reviewing all cybersecurity training',
};

/**
 * @param {string} path
 * @returns {Promise<any>}
 */
export async function scfFetch(path) {
  const url = `${SCF_API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`SCF API ${res.status} for ${url}`);
  }
  return res.json();
}

/**
 * @param {string} controlId e.g. IAC-06
 */
export async function getControl(controlId) {
  return scfFetch(`/controls/${encodeURIComponent(controlId)}.json`);
}

/**
 * Map one SCF control to target frameworks + optional FedRAMP 20x KSIs.
 * @param {string} controlId
 * @param {{ frameworks?: string[], ksi?: string[] }} [opts]
 */
export async function mapControl(controlId, opts = {}) {
  const frameworks = opts.frameworks ?? Object.values(TARGET_FRAMEWORKS);
  const control = await getControl(controlId);
  const crosswalks = control.crosswalks ?? {};

  /** @type {Record<string, string[]>} */
  const mapped = {};
  for (const fw of frameworks) {
    if (crosswalks[fw]?.length) {
      mapped[fw] = crosswalks[fw];
    }
  }

  /** @type {Record<string, string>} */
  const ksi = {};
  for (const id of opts.ksi ?? []) {
    if (FEDRAMP_20X_KSI[id]) ksi[id] = FEDRAMP_20X_KSI[id];
  }

  return {
    scf_control_id: control.control_id,
    title: control.title,
    family: control.family,
    description: control.description,
    evidence_requests: control.evidence_requests ?? [],
    nist_csf_function: control.nist_csf_function,
    relative_weight: control.relative_weight,
    framework_mappings: mapped,
    fedramp_20x_ksi: ksi,
    source: `${SCF_API_BASE}/controls/${controlId}.json`,
  };
}

/**
 * Map a lab's declared SCF controls into a portable mapping document.
 * @param {{ lab_id: string, scf_controls: string[], ksi?: string[], frameworks?: string[] }} labSpec
 */
export async function mapLab(labSpec) {
  const results = [];
  for (const id of labSpec.scf_controls) {
    results.push(
      await mapControl(id, {
        frameworks: labSpec.frameworks,
        ksi: labSpec.ksi,
      }),
    );
  }

  return {
    lab_id: labSpec.lab_id,
    generated_at: new Date().toISOString(),
    scf_api_base: SCF_API_BASE,
    controls: results,
    coverage_summary: summarizeCoverage(results),
  };
}

/**
 * @param {Awaited<ReturnType<typeof mapControl>>[]} controls
 */
function summarizeCoverage(controls) {
  /** @type {Record<string, number>} */
  const byFramework = {};
  for (const c of controls) {
    for (const fw of Object.keys(c.framework_mappings)) {
      byFramework[fw] = (byFramework[fw] ?? 0) + 1;
    }
  }
  return {
    control_count: controls.length,
    frameworks_with_hits: byFramework,
  };
}

/**
 * Resolve which SCF controls map to a framework control ID (reverse lookup via crosswalk file).
 * @param {string} frameworkId
 * @param {string} frameworkControlId
 */
export async function reverseLookup(frameworkId, frameworkControlId) {
  const crosswalk = await scfFetch(`/crosswalks/${encodeURIComponent(frameworkId)}.json`);
  const f2s = crosswalk.framework_to_scf?.mappings ?? {};
  const hits = f2s[frameworkControlId] ?? [];
  return {
    framework_id: frameworkId,
    framework_control: frameworkControlId,
    scf_controls: hits,
  };
}
