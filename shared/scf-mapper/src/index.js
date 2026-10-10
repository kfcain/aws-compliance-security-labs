/**
 * SCF API mapper — live crosswalks for NIST 800-53/171, ISO 27001, PCI DSS, FedRAMP.
 * API: https://grcengclub.github.io/scf-api/
 *
 * Design notes:
 *  - `scfFetch` is hardened: https-only base URL, request timeout, bounded
 *    retries, and a response-size cap. `SCF_API_BASE` may be overridden for
 *    mirrors, but only with an https URL — the generated crosswalks ship in
 *    evidence packages, so a cleartext or attacker-chosen source is refused.
 *  - KSI assignments are PER CONTROL: `mapLab` consumes `ksi_by_control`
 *    ({ "IAC-06": ["KSI-IAM-APM"], ... }). The legacy flat `ksi` array is
 *    still accepted but stamps every control identically (the defect that
 *    stamped one lab-level list onto every control) and warns.
 *  - Frameworks requested by a lab that yield zero crosswalk hits are
 *    reported loudly in `coverage_summary.frameworks_requested_without_hits`
 *    instead of silently disappearing.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_API_BASE = 'https://grcengclub.github.io/scf-api/api';

function resolveApiBase() {
  const base = process.env.SCF_API_BASE ?? DEFAULT_API_BASE;
  let parsed;
  try {
    parsed = new URL(base);
  } catch {
    throw new Error(`SCF_API_BASE is not a valid URL: ${base}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(
      `SCF_API_BASE must use https (crosswalks feed evidence packages): ${base}`,
    );
  }
  return base.replace(/\/$/, '');
}

export const SCF_API_BASE = resolveApiBase();

const FETCH_TIMEOUT_MS = 15_000;
const FETCH_RETRIES = 2;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const CONCURRENCY = 4;

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

/**
 * FedRAMP CR26 Key Security Indicators, pinned to Consolidated Rules
 * version 2026.10.08.01 (`cr26-2026.10.08.01.json`).
 *
 * Descriptions are the official indicator names. `resolveKsi` also returns
 * the official statement. Retired ids are rejected. Where a retired AFR
 * theme became a CR26 rule family, labs cite the rule id from this pin
 * (`CR26_RULES`). Do not add an id that is not in the pin file.
 */
const cr26Pin = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'cr26-2026.10.08.01.json'), 'utf8'),
);

export const KSI_OVERLAY_VERSION = cr26Pin.version;
export const KSI_OVERLAY_SOURCE = `${cr26Pin.source} ${cr26Pin.version}`;

/** @type {Record<string, string>} official KSI name by id */
export const FEDRAMP_20X_KSI = Object.fromEntries(
  Object.entries(cr26Pin.ksi).map(([id, entry]) => [id, entry.name]),
);

/**
 * CR26 rules cited where a retired KSI has no single KSI successor.
 * @type {Record<string, string>}
 */
export const CR26_RULES = Object.fromEntries(
  Object.entries(cr26Pin.rules).map(([id, entry]) => [id, entry.name]),
);

const CR26_CATALOG = { ...FEDRAMP_20X_KSI, ...CR26_RULES };

function cr26Statement(id) {
  const entry = cr26Pin.ksi[id] ?? cr26Pin.rules[id];
  return entry?.statement ?? '';
}

/**
 * Empty. Stale ids used to live here as aliases. They are rejected now.
 * @type {Record<string, string | null>}
 */
export const KSI_ALIASES = {};

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Hardened fetch: timeout, bounded retries with backoff, size cap.
 * @param {string} path
 * @param {{ fetchImpl?: typeof fetch }} [opts] injectable for hermetic tests
 * @returns {Promise<any>}
 */
export async function scfFetch(path, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${SCF_API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
  let lastError;
  for (let attempt = 0; attempt <= FETCH_RETRIES; attempt += 1) {
    try {
      const res = await fetchImpl(url, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { Accept: 'application/json', 'User-Agent': 'scf-mapper' },
      });
      if (!res.ok) {
        // 4xx will not improve on retry; 5xx might.
        if (res.status >= 400 && res.status < 500) {
          throw Object.assign(new Error(`SCF API ${res.status} for ${url}`), { fatal: true });
        }
        throw new Error(`SCF API ${res.status} for ${url}`);
      }
      const text = await res.text();
      if (text.length > MAX_RESPONSE_BYTES) {
        throw Object.assign(
          new Error(`SCF API response exceeds ${MAX_RESPONSE_BYTES} bytes for ${url}`),
          { fatal: true },
        );
      }
      return JSON.parse(text);
    } catch (err) {
      lastError = err;
      if (err.fatal || attempt === FETCH_RETRIES) break;
      await sleep(500 * 2 ** attempt);
    }
  }
  throw lastError;
}

/**
 * @param {string} controlId e.g. IAC-06
 * @param {{ fetchImpl?: typeof fetch }} [opts]
 */
export async function getControl(controlId, opts = {}) {
  return scfFetch(`/controls/${encodeURIComponent(controlId)}.json`, opts);
}

/**
 * Resolve a CR26 KSI or cited rule id.
 * Unknown ids are hard errors — a typo here would silently drop a compliance
 * claim from the generated evidence.
 * @param {string} id
 */
export function resolveKsi(id) {
  if (typeof id !== 'string' || !Object.prototype.hasOwnProperty.call(CR26_CATALOG, id)) {
    throw new Error(`unknown FedRAMP CR26 identifier: ${id} (CR26 ${KSI_OVERLAY_VERSION})`);
  }
  const entry = {
    description: CR26_CATALOG[id],
    statement: cr26Statement(id),
  };
  if (Object.prototype.hasOwnProperty.call(CR26_RULES, id)) entry.kind = 'FRR';
  return entry;
}

/**
 * Map one SCF control to target frameworks + its FedRAMP 20x KSIs.
 * @param {string} controlId
 * @param {{ frameworks?: string[], ksi?: string[], fetchImpl?: typeof fetch }} [opts]
 */
export async function mapControl(controlId, opts = {}) {
  const frameworks = opts.frameworks ?? Object.values(TARGET_FRAMEWORKS);
  const control = await getControl(controlId, opts);
  const crosswalks = control.crosswalks ?? {};

  /** @type {Record<string, string[]>} */
  const mapped = {};
  for (const fw of frameworks) {
    if (Object.prototype.hasOwnProperty.call(crosswalks, fw) && crosswalks[fw]?.length) {
      mapped[fw] = crosswalks[fw];
    }
  }

  /** @type {Record<string, any>} */
  const ksi = {};
  for (const id of opts.ksi ?? []) {
    ksi[id] = resolveKsi(id).description;
  }
  /** @type {Record<string, any>} */
  const ksiDetail = {};
  for (const id of opts.ksi ?? []) {
    ksiDetail[id] = resolveKsi(id);
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
    fedramp_20x_ksi_detail: ksiDetail,
    source: `${SCF_API_BASE}/controls/${encodeURIComponent(controlId)}.json`,
  };
}

/** Small promise pool so a lab's controls fetch with bounded concurrency. */
async function mapWithConcurrency(items, worker, limit = CONCURRENCY) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

/**
 * Resolve the KSI list for one control from a lab spec.
 * @param {{ ksi?: string[], ksi_by_control?: Record<string, string[]> }} labSpec
 * @param {string} controlId
 */
export function ksiForControl(labSpec, controlId) {
  if (labSpec.ksi_by_control) {
    return labSpec.ksi_by_control[controlId] ?? [];
  }
  return labSpec.ksi ?? [];
}

/**
 * Validate a lab spec's KSI declarations before any network work.
 * @param {{ lab_id?: string, scf_controls?: string[], ksi?: string[], ksi_by_control?: Record<string, string[]> }} labSpec
 */
export function validateLabSpec(labSpec) {
  if (!labSpec || typeof labSpec.lab_id !== 'string' || !labSpec.lab_id) {
    throw new Error('lab spec must have a lab_id');
  }
  if (!Array.isArray(labSpec.scf_controls) || labSpec.scf_controls.length === 0) {
    throw new Error(`lab spec ${labSpec.lab_id} must declare scf_controls`);
  }
  if (labSpec.ksi_by_control) {
    for (const [control, ids] of Object.entries(labSpec.ksi_by_control)) {
      if (!labSpec.scf_controls.includes(control)) {
        throw new Error(
          `${labSpec.lab_id}: ksi_by_control references unknown control ${control}`,
        );
      }
      for (const id of ids) resolveKsi(id);
    }
    if (labSpec.ksi) {
      const union = [...new Set(Object.values(labSpec.ksi_by_control).flat())].sort();
      const flat = [...labSpec.ksi].sort();
      if (JSON.stringify(union) !== JSON.stringify(flat)) {
        throw new Error(
          `${labSpec.lab_id}: ksi must equal the union of ksi_by_control values`,
        );
      }
    }
  } else if (labSpec.ksi) {
    for (const id of labSpec.ksi) resolveKsi(id);
    console.warn(
      `${labSpec.lab_id}: flat "ksi" array stamps every control with the same KSIs; ` +
        'migrate to "ksi_by_control" for per-control traceability',
    );
  }
}

/**
 * Map a lab's declared SCF controls into a portable mapping document.
 * @param {{ lab_id: string, scf_controls: string[], ksi?: string[], ksi_by_control?: Record<string, string[]>, frameworks?: string[] }} labSpec
 * @param {{ fetchImpl?: typeof fetch }} [opts]
 */
export async function mapLab(labSpec, opts = {}) {
  validateLabSpec(labSpec);
  const results = await mapWithConcurrency(labSpec.scf_controls, (id) =>
    mapControl(id, {
      frameworks: labSpec.frameworks,
      ksi: ksiForControl(labSpec, id),
      fetchImpl: opts.fetchImpl,
    }),
  );

  return {
    lab_id: labSpec.lab_id,
    generated_at: new Date().toISOString(),
    scf_api_base: SCF_API_BASE,
    ksi_overlay_version: KSI_OVERLAY_VERSION,
    controls: results,
    coverage_summary: summarizeCoverage(results, labSpec.frameworks),
  };
}

/**
 * @param {Awaited<ReturnType<typeof mapControl>>[]} controls
 * @param {string[]} [requestedFrameworks]
 */
export function summarizeCoverage(controls, requestedFrameworks) {
  /** @type {Record<string, number>} */
  const byFramework = {};
  for (const c of controls) {
    for (const fw of Object.keys(c.framework_mappings)) {
      byFramework[fw] = (byFramework[fw] ?? 0) + 1;
    }
  }
  const summary = {
    control_count: controls.length,
    frameworks_with_hits: byFramework,
  };
  if (requestedFrameworks) {
    const missing = requestedFrameworks.filter((fw) => !(fw in byFramework));
    summary.frameworks_requested_without_hits = missing;
  }
  return summary;
}

/**
 * Resolve which SCF controls map to a framework control ID (reverse lookup via crosswalk file).
 * @param {string} frameworkId
 * @param {string} frameworkControlId
 * @param {{ fetchImpl?: typeof fetch }} [opts]
 */
export async function reverseLookup(frameworkId, frameworkControlId, opts = {}) {
  const crosswalk = await scfFetch(`/crosswalks/${encodeURIComponent(frameworkId)}.json`, opts);
  const f2s = crosswalk.framework_to_scf?.mappings ?? {};
  const hits = Object.prototype.hasOwnProperty.call(f2s, frameworkControlId)
    ? f2s[frameworkControlId]
    : [];
  return {
    framework_id: frameworkId,
    framework_control: frameworkControlId,
    scf_controls: Array.isArray(hits) ? hits : [],
  };
}
