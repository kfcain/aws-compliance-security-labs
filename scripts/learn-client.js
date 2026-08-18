/* Inlined into docs/learn/index.html by scripts/build-learn.mjs. */
(function () {
  const data = window.LEARN_DATA;
  const STORAGE_KEY = 'acf-labs-learn-v1';
  const views = ['overview', 'path', 'labs', 'coverage', 'controls', 'risks'];

  const esc = (value) =>
    String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  const labById = Object.fromEntries(data.labs.map((lab) => [lab.id, lab]));
  const riskByLab = Object.fromEntries(data.risks.map((risk) => [risk.lab, risk]));

  const loadDone = () => {
    try {
      const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
      return new Set(Array.isArray(raw.done) ? raw.done : []);
    } catch {
      return new Set();
    }
  };

  let done = loadDone();
  let activeView = 'overview';
  let selectedLab = null;
  let query = '';
  let frameworkFilter = '';
  let selectedControl = '';

  const saveDone = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ done: [...done].sort() }));
  };

  const setView = (view) => {
    activeView = views.includes(view) ? view : 'overview';
    document.querySelectorAll('[data-view]').forEach((el) => {
      el.hidden = el.getAttribute('data-view') !== activeView;
    });
    document.querySelectorAll('[data-nav]').forEach((el) => {
      el.setAttribute('aria-current', el.getAttribute('data-nav') === activeView ? 'page' : 'false');
    });
    const hash = selectedLab && activeView === 'labs'
      ? `#labs/${selectedLab}`
      : `#${activeView}`;
    if (location.hash !== hash) history.replaceState(null, '', hash);
  };

  const openLab = (id) => {
    selectedLab = labById[id] ? id : null;
    setView('labs');
    renderLabs();
    renderDrawer();
    const card = document.getElementById(`lab-card-${id}`);
    if (card) card.scrollIntoView({ block: 'nearest' });
  };

  const toggleDone = (id) => {
    if (done.has(id)) done.delete(id);
    else done.add(id);
    saveDone();
    renderProgress();
    renderPath();
    renderLabs();
    renderDrawer();
  };

  const bandClass = (band) => {
    if (band === 'Severe' || band === 'Major') return 'crit';
    if (band === 'Moderate') return 'high';
    return 'ok';
  };

  const coverageRatio = (lab, fw) => {
    const cov = data.coverage.labs[lab.id];
    if (!cov) return null;
    const total = lab.scf_controls.length || 1;
    const mapped = cov.mapped_control_counts[fw] ?? 0;
    return { mapped, total, ratio: mapped / total };
  };

  const renderProgress = () => {
    const total = data.labs.length;
    const count = [...done].filter((id) => labById[id]).length;
    const pct = Math.round((count / total) * 100);
    const fill = document.getElementById('progress-fill');
    const label = document.getElementById('progress-label');
    if (fill) fill.style.width = `${pct}%`;
    if (label) label.textContent = `${count} of ${total} labs marked complete`;
  };

  const renderOverview = () => {
    const kpi = document.getElementById('overview-kpis');
    if (kpi) {
      kpi.innerHTML = [
        ['Labs', data.labs.length],
        ['SCF controls', data.coverage.unique_scf_controls.length],
        ['FedRAMP 20x KSIs', data.coverage.ksi_in_use.length],
        ['Frameworks', data.coverage.frameworks.length],
      ]
        .map(
          ([label, value]) =>
            `<div class="card"><strong>${esc(value)}</strong>${esc(label)}</div>`,
        )
        .join('');
    }
  };

  const renderPath = () => {
    const root = document.getElementById('path-tracks');
    if (!root) return;
    root.innerHTML = data.path
      .map((track, index) => {
        const complete = track.labs.filter((id) => done.has(id)).length;
        const items = track.labs
          .map((id, step) => {
            const lab = labById[id];
            if (!lab) return '';
            const risk = riskByLab[id];
            const checked = done.has(id) ? 'checked' : '';
            return `<li class="path-item">
              <input type="checkbox" data-done="${esc(id)}" ${checked} aria-label="Mark ${esc(lab.id)} complete"/>
              <span class="step-num">${step + 1}</span>
              <span>
                <button type="button" class="linkish" data-open-lab="${esc(id)}">${esc(lab.title)}</button>
                <span class="meta">${esc(lab.id)} · residual ${esc(risk?.residual.band ?? 'n/a')}</span>
              </span>
            </li>`;
          })
          .join('');
        return `<article class="section track">
          <h3>Track ${index + 1}. ${esc(track.title)}</h3>
          <p>${esc(track.why)}</p>
          <p class="meta">${complete} of ${track.labs.length} complete</p>
          <ol class="path-list">${items}</ol>
        </article>`;
      })
      .join('');
  };

  const filteredLabs = () => {
    const q = query.trim().toLowerCase();
    return data.labs.filter((lab) => {
      if (frameworkFilter && !lab.frameworks.includes(frameworkFilter)) return false;
      if (selectedControl && !lab.scf_controls.includes(selectedControl)) return false;
      if (!q) return true;
      const hay = [
        lab.id,
        lab.title,
        lab.summary,
        lab.primary_risk,
        lab.scf_controls.join(' '),
        lab.ksi.join(' '),
        lab.aws_services.join(' '),
        (lab.external_services || []).join(' '),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  };

  const renderLabs = () => {
    const root = document.getElementById('lab-grid');
    if (!root) return;
    const labs = filteredLabs();
    document.getElementById('lab-count').textContent = `${labs.length} shown`;
    root.innerHTML = labs
      .map((lab) => {
        const risk = riskByLab[lab.id];
        const active = selectedLab === lab.id ? ' selected' : '';
        const complete = done.has(lab.id) ? ' complete' : '';
        return `<article class="card lab-card${active}${complete}" id="lab-card-${esc(lab.id)}">
          <button type="button" class="card-hit" data-open-lab="${esc(lab.id)}" aria-expanded="${selectedLab === lab.id}">
            <h2>${esc(lab.title)}</h2>
            <p class="meta">${esc(lab.id)} · ${esc(lab.status)}</p>
            <p>${esc(lab.primary_risk)}</p>
            <div class="pillrow">
              <span class="pill ${bandClass(risk?.residual.band)}">${esc(risk?.residual.band ?? 'risk')}</span>
              <span class="pill">${lab.scf_controls.length} SCF</span>
              <span class="pill">${lab.ksi.length} KSI</span>
              ${done.has(lab.id) ? '<span class="pill ok">complete</span>' : ''}
            </div>
          </button>
        </article>`;
      })
      .join('');
  };

  const renderDrawer = () => {
    const drawer = document.getElementById('lab-drawer');
    const lab = labById[selectedLab];
    if (!drawer) return;
    if (!lab) {
      drawer.hidden = true;
      drawer.innerHTML = '';
      return;
    }
    const risk = riskByLab[lab.id];
    const cov = data.coverage.labs[lab.id];
    const walk = lab.has_walkthrough
      ? `<a href="${esc(lab.walkthrough_href)}">Open walkthrough</a>`
      : `<a href="${esc(lab.readme_href)}">Open README (no walkthrough page)</a>`;
    const coverageRows = data.coverage.frameworks
      .map((fw) => {
        const cell = coverageRatio(lab, fw);
        if (!cell) return '';
        const width = Math.round(cell.ratio * 100);
        const cls = cell.mapped === 0 ? 'crit' : cell.mapped < cell.total ? 'high' : 'ok';
        return `<tr>
          <td>${esc(data.coverage.framework_labels[fw] || fw)}</td>
          <td class="mono">${cell.mapped}/${cell.total}</td>
          <td><div class="bar"><span class="${cls}" style="width:${width}%"></span></div></td>
        </tr>`;
      })
      .join('');
    drawer.hidden = false;
    drawer.innerHTML = `
      <div class="drawer-inner">
        <div class="drawer-head">
          <h2>${esc(lab.title)}</h2>
          <button type="button" class="icon-btn" data-close-drawer aria-label="Close lab detail">Close</button>
        </div>
        <p class="meta">${esc(lab.id)} · ${esc(lab.status)}</p>
        <p>${esc(lab.summary)}</p>
        <h3>Primary risk</h3>
        <p>${esc(lab.primary_risk)}</p>
        ${
          risk
            ? `<p class="meta">Residual: ${esc(risk.residual.likelihood)} likelihood × ${esc(risk.residual.impact)} impact (${esc(risk.residual.band)}). ATT&amp;CK: ${esc(risk.attack_techniques.join(', '))}.</p>`
            : ''
        }
        <h3>Controls and services</h3>
        <table>
          <tbody>
            <tr><th>SCF</th><td class="mono">${esc(lab.scf_controls.join(', '))}</td></tr>
            <tr><th>KSI</th><td class="mono">${esc(lab.ksi.join(', '))}</td></tr>
            <tr><th>AWS</th><td>${esc(lab.aws_services.join(', '))}</td></tr>
            <tr><th>External</th><td>${esc((lab.external_services || []).join(', ') || 'None')}</td></tr>
          </tbody>
        </table>
        <h3>Framework mapping density</h3>
        <p class="meta">Mapped SCF controls / declared SCF controls. Zero means the current crosswalk has no hits.</p>
        <table><thead><tr><th>Framework</th><th>Hits</th><th>Ratio</th></tr></thead><tbody>${coverageRows}</tbody></table>
        <div class="drawer-actions">
          ${walk}
          <a href="${esc(lab.spec_href)}">SPEC</a>
          <a href="${esc(lab.risk_href)}">RISK</a>
          <a href="${esc(lab.assessment_href)}">ASSESSMENT</a>
          <button type="button" data-done="${esc(lab.id)}">${done.has(lab.id) ? 'Mark as not complete' : 'Mark as complete'}</button>
        </div>
        ${cov?.generated_at ? `<p class="meta">Crosswalk snapshot: ${esc(cov.generated_at)}</p>` : ''}
      </div>`;
  };

  const renderCoverage = () => {
    const table = document.getElementById('coverage-table');
    if (!table) return;
    const headers = data.coverage.frameworks
      .map((fw) => `<th>${esc(data.coverage.framework_labels[fw] || fw)}</th>`)
      .join('');
    const rows = data.labs
      .map((lab) => {
        const cells = data.coverage.frameworks
          .map((fw) => {
            const cell = coverageRatio(lab, fw);
            if (!cell) return '<td>—</td>';
            const cls = cell.mapped === 0 ? 'heat-0' : cell.mapped < cell.total ? 'heat-part' : 'heat-full';
            return `<td class="${cls}"><button type="button" data-open-lab="${esc(lab.id)}">${cell.mapped}/${cell.total}</button></td>`;
          })
          .join('');
        return `<tr><th scope="row"><button type="button" class="linkish" data-open-lab="${esc(lab.id)}">${esc(lab.id)}</button></th>${cells}</tr>`;
      })
      .join('');
    const rollup = data.coverage.frameworks
      .map((fw) => {
        const n = data.coverage.unique_framework_controls[fw] ?? 0;
        return `<li><span class="mono">${esc(data.coverage.framework_labels[fw] || fw)}</span> · ${n} unique controls</li>`;
      })
      .join('');
    table.innerHTML = `<thead><tr><th>Lab</th>${headers}</tr></thead><tbody>${rows}</tbody>`;
    document.getElementById('coverage-rollup').innerHTML = rollup;
  };

  const renderControls = () => {
    const root = document.getElementById('control-cloud');
    if (!root) return;
    const max = Math.max(
      ...Object.values(data.coverage.scf_control_labs).map((labs) => labs.length),
      1,
    );
    root.innerHTML = data.coverage.unique_scf_controls
      .map((control) => {
        const labs = data.coverage.scf_control_labs[control] || [];
        const weight = 0.75 + (labs.length / max) * 0.6;
        const active = selectedControl === control ? ' selected' : '';
        return `<button type="button" class="chip${active}" data-control="${esc(control)}" style="font-size:${weight}rem" title="${labs.length} labs">
          ${esc(control)} <span>${labs.length}</span>
        </button>`;
      })
      .join('');
    const detail = document.getElementById('control-detail');
    if (!selectedControl) {
      detail.innerHTML = '<p class="meta">Select one SCF control to see the labs that implement it.</p>';
    } else {
      const labs = data.coverage.scf_control_labs[selectedControl] || [];
      detail.innerHTML = `<h3>${esc(selectedControl)}</h3>
        <p>${labs.length} lab(s) declare this control.</p>
        <ul class="tight">${labs
          .map((id) => {
            const lab = labById[id];
            return `<li><button type="button" class="linkish" data-open-lab="${esc(id)}">${esc(lab ? lab.title : id)}</button></li>`;
          })
          .join('')}</ul>`;
    }
    const ksiRoot = document.getElementById('ksi-list');
    ksiRoot.innerHTML = data.coverage.ksi_in_use
      .map((ksi) => `<li class="mono">${esc(ksi)}</li>`)
      .join('');
  };

  const renderRisks = () => {
    const heat = document.getElementById('risk-heat');
    const table = document.getElementById('risk-table');
    if (!heat || !table) return;
    const likelihoods = ['Very Low', 'Low', 'Medium', 'High', 'Very High'];
    const impacts = ['Critical', 'High', 'Medium', 'Low', 'Very Low'];
    const cells = {};
    for (const risk of data.risks) {
      const key = `${risk.residual.likelihood}|${risk.residual.impact}`;
      (cells[key] ??= []).push(risk);
    }
    const grid = impacts
      .map(
        (impact) =>
          `<tr><th scope="row">${esc(impact)}</th>${likelihoods
            .map((likelihood) => {
              const list = cells[`${likelihood}|${impact}`] || [];
              const cls = list.length ? bandClass(list[0].residual.band) : '';
              const body = list
                .map(
                  (risk) =>
                    `<button type="button" class="heat-lab" data-open-lab="${esc(risk.lab)}">${esc(risk.lab.split('-')[0])}</button>`,
                )
                .join('');
              return `<td class="heat-cell ${cls}">${body || '<span class="meta">—</span>'}</td>`;
            })
            .join('')}</tr>`,
      )
      .join('');
    heat.innerHTML = `<thead><tr><th>Impact \\ Likelihood</th>${likelihoods
      .map((l) => `<th>${esc(l)}</th>`)
      .join('')}</tr></thead><tbody>${grid}</tbody>`;
    table.innerHTML = `<thead><tr><th>ID</th><th>Lab</th><th>Statement</th><th>Residual</th><th>ATT&amp;CK</th></tr></thead>
      <tbody>${data.risks
        .map(
          (risk) => `<tr>
            <td class="mono">${esc(risk.risk_id)}</td>
            <td><button type="button" class="linkish" data-open-lab="${esc(risk.lab)}">${esc(risk.lab)}</button></td>
            <td>${esc(risk.statement)}</td>
            <td><span class="pill ${bandClass(risk.residual.band)}">${esc(risk.residual.band)}</span></td>
            <td class="mono">${esc(risk.attack_techniques.join(', '))}</td>
          </tr>`,
        )
        .join('')}</tbody>`;
    const bands = document.getElementById('risk-bands');
    bands.innerHTML = Object.entries(data.band_summary)
      .map(([band, count]) => `<div class="card"><strong>${esc(count)}</strong>${esc(band)} residual</div>`)
      .join('');
  };

  const parseHash = () => {
    const raw = (location.hash || '#overview').slice(1);
    const [view, lab] = raw.split('/');
    if (views.includes(view)) activeView = view;
    if (lab && labById[lab]) selectedLab = lab;
  };

  const onClick = (event) => {
    const nav = event.target.closest('[data-nav]');
    if (nav) {
      selectedLab = null;
      setView(nav.getAttribute('data-nav'));
      renderDrawer();
      return;
    }
    const open = event.target.closest('[data-open-lab]');
    if (open) {
      openLab(open.getAttribute('data-open-lab'));
      return;
    }
    const doneBtn = event.target.closest('button[data-done]');
    if (doneBtn) {
      toggleDone(doneBtn.getAttribute('data-done'));
      return;
    }
    const control = event.target.closest('[data-control]');
    if (control) {
      const id = control.getAttribute('data-control');
      selectedControl = selectedControl === id ? '' : id;
      renderControls();
      renderLabs();
      return;
    }
    if (event.target.closest('[data-close-drawer]')) {
      selectedLab = null;
      setView('labs');
      renderLabs();
      renderDrawer();
    }
  };

  document.addEventListener('click', onClick);
  document.addEventListener('change', (event) => {
    const box = event.target.closest('input[type="checkbox"][data-done]');
    if (!box) return;
    const id = box.getAttribute('data-done');
    if (box.checked) done.add(id);
    else done.delete(id);
    saveDone();
    renderProgress();
    renderPath();
    renderLabs();
    renderDrawer();
  });
  document.getElementById('lab-search').addEventListener('input', (event) => {
    query = event.target.value;
    renderLabs();
  });
  document.getElementById('framework-filter').addEventListener('change', (event) => {
    frameworkFilter = event.target.value;
    renderLabs();
  });
  window.addEventListener('hashchange', () => {
    parseHash();
    setView(activeView);
    renderLabs();
    renderDrawer();
  });

  const fwSelect = document.getElementById('framework-filter');
  fwSelect.innerHTML =
    '<option value="">All frameworks</option>' +
    data.coverage.frameworks
      .map(
        (fw) =>
          `<option value="${esc(fw)}">${esc(data.coverage.framework_labels[fw] || fw)}</option>`,
      )
      .join('');

  parseHash();
  renderOverview();
  renderProgress();
  renderPath();
  renderLabs();
  renderDrawer();
  renderCoverage();
  renderControls();
  renderRisks();
  setView(activeView);
})();
