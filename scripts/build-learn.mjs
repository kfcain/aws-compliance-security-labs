#!/usr/bin/env node
/**
 * Portfolio learning hub: embeds catalog.json, coverage.json, and risks.json
 * into a static page at docs/learn/index.html. Deterministic (content-derived
 * only — no wall-clock stamps) so `--check` can gate drift in CI.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const check = process.argv.includes('--check');
const outPath = join(root, 'docs/learn/index.html');

const FRAMEWORK_LABELS = {
  'general-nist-800-53-r5-2': 'NIST 800-53 r5',
  'general-nist-800-171-r3': 'NIST 800-171 r3',
  'general-nist-800-171-r2': 'NIST 800-171 r2',
  'general-iso-27001-2022': 'ISO 27001:2022',
  'general-pci-dss-4-0-1': 'PCI DSS 4.0.1',
  'usa-federal-gsa-fedramp-5-mod': 'FedRAMP r5 Mod',
  'usa-federal-dow-cmmc-2-level-2': 'CMMC 2.0 L2',
};

/** Guided curriculum: every catalog lab id appears in exactly one track. */
const LEARNING_PATH = [
  {
    id: 'identity',
    title: 'Identity and access',
    why: 'Start here. Identity is the primary control plane. MFA, credential rotation, and privileged suspend close the account-takeover path.',
    labs: [
      '01-mfa-continuous-validation',
      '03-nhi-credential-rotation',
      '14-privileged-suspend-lifecycle',
    ],
  },
  {
    id: 'detect',
    title: 'Detect and respond',
    why: 'A finding must become an action. Inspector, GuardDuty, and incident-response playbooks reduce dwell time.',
    labs: [
      '02-inspector-vdr',
      '05-guardduty-automated-response',
      '09-incident-response-automation',
    ],
  },
  {
    id: 'change',
    title: 'Configuration and change',
    why: 'The declared baseline must match reality. Config rules, Terraform drift checks, and CI/CD gates stop silent change.',
    labs: [
      '04-config-drift-compliance',
      '16-terraform-drift-detection',
      '15-immutable-cicd-change-control',
    ],
  },
  {
    id: 'evidence',
    title: 'Evidence, inventory, and cryptography',
    why: 'You must prove who did what. Immutable CloudTrail evidence, a live asset inventory, and KMS governance make the control assessable.',
    labs: [
      '07-cloudtrail-evidence-pipeline',
      '13-boundary-asset-inventory',
      '06-kms-encryption-governance',
    ],
  },
  {
    id: 'resilience',
    title: 'Network, data, and resilience',
    why: 'A control that cannot survive a breach or a disaster is incomplete. Segment the network, delete residual data, test backups, and prove DR.',
    labs: [
      '08-vpc-network-segmentation',
      '10-supply-chain-sbom',
      '11-federal-data-deletion-residual',
      '12-backup-recovery-rto-rpo',
      '17-terraform-dr-readiness',
    ],
  },
];

function rel(fromDir, toPath) {
  const from = fromDir.split('/').filter(Boolean);
  const to = toPath.split('/').filter(Boolean);
  let i = 0;
  while (i < from.length && i < to.length && from[i] === to[i]) i += 1;
  return `${'../'.repeat(from.length - i)}${to.slice(i).join('/')}`;
}

function buildPayload(catalog, coverage, risks) {
  const catalogIds = catalog.labs.map((lab) => lab.id).sort();
  const pathIds = LEARNING_PATH.flatMap((track) => track.labs).sort();
  const missing = catalogIds.filter((id) => !pathIds.includes(id));
  const extra = pathIds.filter((id) => !catalogIds.includes(id));
  const dupes = pathIds.filter((id, i) => pathIds.indexOf(id) !== i);
  if (missing.length || extra.length || dupes.length) {
    throw new Error(
      `LEARNING_PATH does not match catalog (missing=${missing} extra=${extra} dupes=${dupes})`,
    );
  }

  const coverageByLab = Object.fromEntries(
    coverage.labs.map((lab) => [
      lab.lab_id,
      {
        mapped_control_counts: lab.mapped_control_counts,
        frameworks_without_hits: lab.frameworks_without_hits,
        generated_at: lab.generated_at,
      },
    ]),
  );

  const learnDir = 'docs/learn';
  const labs = catalog.labs.map((lab) => {
    const walkthrough = join(root, lab.path, 'index.html');
    const hasWalkthrough = existsSync(walkthrough);
    return {
      id: lab.id,
      title: lab.title,
      summary: lab.summary,
      primary_risk: lab.primary_risk,
      scf_controls: lab.scf_controls,
      ksi: lab.ksi,
      frameworks: lab.frameworks,
      aws_services: lab.aws_services,
      external_services: lab.external_services ?? [],
      status: lab.status,
      pages: lab.pages ?? null,
      has_walkthrough: hasWalkthrough,
      walkthrough_href: rel(learnDir, `${lab.path}/index.html`),
      readme_href: rel(learnDir, `${lab.path}/README.md`),
      spec_href: rel(learnDir, `${lab.path}/SPEC.md`),
      risk_href: rel(learnDir, `${lab.path}/RISK.md`),
      assessment_href: rel(learnDir, `${lab.path}/ASSESSMENT.md`),
    };
  });

  return {
    project: catalog.portfolio,
    version: catalog.version,
    description: catalog.description,
    architecture_pattern: catalog.architecture_pattern,
    scf_api: catalog.scf_api,
    labs,
    path: LEARNING_PATH,
    coverage: {
      ksi_overlay_version: coverage.ksi_overlay_version,
      frameworks: coverage.frameworks,
      framework_labels: FRAMEWORK_LABELS,
      labs: coverageByLab,
      unique_scf_controls: coverage.portfolio.unique_scf_controls,
      scf_control_labs: coverage.portfolio.scf_control_labs,
      unique_framework_controls: coverage.portfolio.unique_framework_controls,
      ksi_in_use: coverage.portfolio.ksi_in_use,
    },
    risks: risks.risks.map((risk) => ({
      risk_id: risk.risk_id,
      lab: risk.lab,
      statement: risk.statement,
      residual: risk.residual,
      inherent: risk.inherent,
      owner: risk.owner,
      attack_techniques: risk.attack_techniques,
    })),
    band_summary: risks.band_summary,
  };
}

function architectureSvg() {
  return `<svg viewBox="0 0 1000 280" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Shared architecture pattern for all labs">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#5b6b82"/>
    </marker>
  </defs>
  <rect width="1000" height="280" fill="#0b1220"/>
  <text x="40" y="28" fill="#7dd3fc" font-size="14" font-family="IBM Plex Sans, sans-serif">Shared pattern — data in, evidence out</text>
  <rect x="40" y="48" width="280" height="36" rx="8" fill="#151d2e" stroke="#3d8bfd"/>
  <text x="180" y="71" text-anchor="middle" fill="#e8eef7" font-size="13" font-family="IBM Plex Sans, sans-serif">1. Data sources</text>
  <rect x="360" y="48" width="280" height="36" rx="8" fill="#151d2e" stroke="#34d399"/>
  <text x="500" y="71" text-anchor="middle" fill="#e8eef7" font-size="13" font-family="IBM Plex Sans, sans-serif">2. Detection and aggregation</text>
  <rect x="680" y="48" width="280" height="36" rx="8" fill="#151d2e" stroke="#fb923c"/>
  <text x="820" y="71" text-anchor="middle" fill="#e8eef7" font-size="13" font-family="IBM Plex Sans, sans-serif">3. Automation and evidence</text>
  <path d="M320,160 C340,160 340,160 360,160" fill="none" stroke="#5b6b82" stroke-width="2" marker-end="url(#arrow)"/>
  <path d="M640,160 C660,160 660,160 680,160" fill="none" stroke="#5b6b82" stroke-width="2" marker-end="url(#arrow)"/>
  <g>
    <rect x="40" y="108" width="280" height="48" rx="10" fill="#1e3a5f" stroke="#3d8bfd"/>
    <text x="180" y="137" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">CloudTrail · Config · Flow Logs</text>
  </g>
  <g>
    <rect x="40" y="168" width="280" height="48" rx="10" fill="#1e3a5f" stroke="#3d8bfd"/>
    <text x="180" y="197" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">Inspector · IdP · Terraform plan</text>
  </g>
  <g>
    <rect x="360" y="108" width="280" height="48" rx="10" fill="#1a4d3e" stroke="#34d399"/>
    <text x="500" y="137" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">GuardDuty · Config · Inspector</text>
  </g>
  <g>
    <rect x="360" y="168" width="280" height="48" rx="10" fill="#1a4d3e" stroke="#34d399"/>
    <text x="500" y="197" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">Security Hub findings</text>
  </g>
  <g>
    <rect x="680" y="108" width="280" height="48" rx="10" fill="#4a2c1a" stroke="#fb923c"/>
    <text x="820" y="137" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">EventBridge → Lambda</text>
  </g>
  <g>
    <rect x="680" y="168" width="280" height="48" rx="10" fill="#4a2c1a" stroke="#fb923c"/>
    <text x="820" y="197" text-anchor="middle" fill="#e8eef7" font-size="12" font-family="IBM Plex Sans, sans-serif">Evidence store · SNS alerts</text>
  </g>
  <text x="500" y="250" text-anchor="middle" fill="#9aa8bc" font-size="12" font-family="IBM Plex Sans, sans-serif">Every lab implements this pipeline for one control theme.</text>
</svg>`;
}

function renderHtml(payload, css, clientJs) {
  const dataJson = JSON.stringify(payload).replace(/</g, '\\u003c');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Learn the AWS Compliance &amp; Security Labs</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&amp;family=IBM+Plex+Sans:wght@400;500;600&amp;family=Source+Serif+4:opsz,wght@8..60,500;8..60,700&amp;display=swap" rel="stylesheet"/>
  <style>
${css.trim()}
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <div class="wrap">
    <header class="hero">
      <p class="brand">AWS Compliance &amp; Security Labs</p>
      <p class="sub">One page to visualize and learn all ${payload.labs.length} labs. Filter by framework, walk a guided path, and open each lab's walkthrough, risk, and assessment.</p>
      <nav class="nav" aria-label="Hub sections">
        <button type="button" data-nav="overview">Overview</button>
        <button type="button" data-nav="path">Learn path</button>
        <button type="button" data-nav="labs">Labs</button>
        <button type="button" data-nav="coverage">Coverage</button>
        <button type="button" data-nav="controls">Controls</button>
        <button type="button" data-nav="risks">Risks</button>
      </nav>
      <div class="progress" aria-live="polite">
        <div class="progress-track"><span id="progress-fill"></span></div>
        <span id="progress-label"></span>
      </div>
    </header>

    <main id="main">
      <section class="section" data-view="overview" id="overview">
        <h2>What this portfolio is</h2>
        <p>${payload.description}</p>
        <p class="note">Target frameworks: NIST SP 800-171, NIST SP 800-53, ISO 27001, PCI DSS, and FedRAMP 20x / CR26 KSIs. Crosswalks use the Secure Controls Framework static API.</p>
        <div class="kpi" id="overview-kpis"></div>
        <h3>How to use this page</h3>
        <ol>
          <li>Open <strong>Learn path</strong> and complete the tracks in order.</li>
          <li>Mark a lab complete after you read its walkthrough (or README for labs 16–17).</li>
          <li>Use <strong>Coverage</strong> and <strong>Controls</strong> when you need the GRC view.</li>
          <li>Use <strong>Risks</strong> when you need likelihood, impact, and ATT&amp;CK technique.</li>
        </ol>
        <h3>Shared architecture</h3>
        <p class="mono">${payload.architecture_pattern}</p>
        <div class="diagram">${architectureSvg()}</div>
        <p class="meta">KSI overlay ${payload.coverage.ksi_overlay_version}. Generated from <code class="mono">labs/catalog.json</code>, <code class="mono">coverage.json</code>, and <code class="mono">risks.json</code>. Do not edit this HTML by hand.</p>
      </section>

      <section data-view="path" id="path" hidden>
        <div class="section">
          <h2>Guided learn path</h2>
          <p>Complete the five tracks in order. The sequence starts with identity, then detection, then change control, then evidence, then resilience.</p>
        </div>
        <div id="path-tracks"></div>
      </section>

      <section data-view="labs" id="labs" hidden>
        <div class="section">
          <h2>Lab catalog</h2>
          <p>Search by title, SCF control, KSI, AWS service, or risk text. Open a card to see mapping density and source files.</p>
          <div class="toolbar">
            <input id="lab-search" type="search" placeholder="Search labs, controls, services" aria-label="Search labs"/>
            <select id="framework-filter" aria-label="Filter by framework"></select>
            <span class="meta" id="lab-count"></span>
          </div>
        </div>
        <div class="labs-layout">
          <div class="grid cards" id="lab-grid"></div>
          <aside id="lab-drawer" hidden></aside>
        </div>
      </section>

      <section class="section" data-view="coverage" id="coverage" hidden>
        <h2>Control coverage heatmap</h2>
        <p>Each cell is mapped SCF controls / declared SCF controls for that lab and framework. Red is zero hits in the current crosswalk. Orange is partial. Green is complete.</p>
        <div style="overflow:auto"><table id="coverage-table"></table></div>
        <h3>Portfolio rollup</h3>
        <ul class="tight" id="coverage-rollup"></ul>
        <p class="meta">Source: <a href="../../COVERAGE.md">COVERAGE.md</a>. CMMC 2.0 L2 and NIST 800-171 r2 columns are pending the next live SCF refresh when they show zero.</p>
      </section>

      <section class="section" data-view="controls" id="controls" hidden>
        <h2>SCF control map</h2>
        <p>Select a control to see every lab that declares it. Chip size follows the number of labs.</p>
        <div id="control-cloud"></div>
        <div id="control-detail"></div>
        <h3>FedRAMP 20x KSIs in use</h3>
        <ul class="tight" id="ksi-list"></ul>
      </section>

      <section class="section" data-view="risks" id="risks" hidden>
        <h2>Residual risk map</h2>
        <p>Each lab has one residual rating after the lab controls are in place. Select a lab number to open its catalog card.</p>
        <div class="kpi" id="risk-bands"></div>
        <div style="overflow:auto"><table id="risk-heat"></table></div>
        <h3>Register</h3>
        <div style="overflow:auto"><table id="risk-table"></table></div>
        <p class="meta">Source: <a href="../../RISKS.md">RISKS.md</a>. Scales: <a href="../RISK-METHODOLOGY.md">docs/RISK-METHODOLOGY.md</a>.</p>
      </section>
    </main>

    <footer class="footer">
      AWS Compliance &amp; Security Labs · SCF crosswalks · FedRAMP 20x / CR26 KSIs · Learning hub
    </footer>
  </div>
  <script>window.LEARN_DATA = ${dataJson};</script>
  <script>
${clientJs.trim()}
  </script>
</body>
</html>
`;
}

const catalog = JSON.parse(readFileSync(join(root, 'labs/catalog.json'), 'utf8'));
const coverage = JSON.parse(readFileSync(join(root, 'coverage.json'), 'utf8'));
const risks = JSON.parse(readFileSync(join(root, 'risks.json'), 'utf8'));
const css = readFileSync(join(here, 'learn-styles.css'), 'utf8');
const clientJs = readFileSync(join(here, 'learn-client.js'), 'utf8');
const payload = buildPayload(catalog, coverage, risks);
const html = renderHtml(payload, css, clientJs);

if (check) {
  const current = existsSync(outPath) ? readFileSync(outPath, 'utf8') : null;
  if (current !== html) {
    console.error(`DRIFT: ${outPath} is stale`);
    console.error('Run: node scripts/build-learn.mjs');
    process.exit(1);
  }
  console.log(`learn check OK — ${payload.labs.length} labs`);
} else {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, html);
  console.log(`wrote ${outPath} — ${payload.labs.length} labs`);
}
