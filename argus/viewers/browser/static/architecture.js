/*
 * architecture.js — interactive architecture map page.
 *
 * Vanilla JS, no framework, no CDN. Reads the view model from an
 * inlined ``<script type="application/json" id="arch-data">`` block
 * so the page is genuinely self-contained and offline-capable.
 *
 * Three concerns:
 *   1. Render the column grid + flow list from the view model.
 *   2. Wire click handlers: nodes open the side panel; flows
 *      highlight their path; ``Configure`` flips into picker mode.
 *   3. URL state — selected flow + configure mode + picker
 *      selection round-trip through the query string so links are
 *      shareable and refresh preserves the view.
 *
 * Strict CSP: every handler is added via addEventListener; no
 * inline JS, no eval, no template literals interpolated into HTML
 * without escaping.
 */

(function () {
  'use strict';

  // ─── Boot ────────────────────────────────────────────────────────

  const dataEl = document.getElementById('arch-data');
  if (!dataEl) { return; }
  let data;
  try {
    data = JSON.parse(dataEl.textContent || '{}');
  } catch (err) {
    console.error('architecture.js: failed to parse view model', err);
    return;
  }

  const pageEl = document.querySelector('.arch-page');
  const columnsEl = document.getElementById('arch-columns');
  const flowsEl = document.getElementById('arch-flows-list');
  const stepsContainerEl = document.getElementById('arch-steps');
  const stepsListEl = document.getElementById('arch-steps-list');
  const flowClearEl = document.getElementById('arch-flow-clear');
  const panelEl = document.getElementById('arch-panel');
  const panelCloseEl = document.getElementById('arch-panel-close');
  const toolsListEl = document.getElementById('arch-tools-list');
  const configureToggleEl = document.getElementById('arch-configure-toggle');
  const pickerEl = document.getElementById('arch-picker');
  const flowsSidebarEl = document.querySelector('.arch-page__sidebar--flows');
  const stepsSidebarEl = document.querySelector('.arch-page__sidebar--steps');
  const toggleFlowsEl = document.getElementById('arch-toggle-flows');
  const toggleStepsEl = document.getElementById('arch-toggle-steps');
  const drawerBackdropEl = document.getElementById('arch-drawer-backdrop');

  if (!pageEl || !columnsEl || !flowsEl) { return; }

  // ─── State ────────────────────────────────────────────────────────

  const nodesById = new Map();
  for (const n of data.nodes || []) { nodesById.set(n.id, n); }
  for (const t of data.external_tools || []) { nodesById.set(t.id, t); }
  const flowsById = new Map();
  for (const f of data.flows || []) { flowsById.set(f.id, f); }
  const adrsById = new Map();
  for (const a of data.adrs || []) { adrsById.set(a.id, a); }

  const state = {
    activeFlow: null,        // flow id or null
    openNodeId: null,        // node id or null
    configure: false,        // boolean
    selection: new Set(),    // selected scanner / linter node ids
    severityThreshold: 'none',
    format: 'terminal',
  };

  // ─── Rendering ───────────────────────────────────────────────────

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, val] of Object.entries(attrs)) {
        if (key === 'class') { node.className = val; }
        else if (key === 'text') { node.textContent = val; }
        else if (key === 'dataset') {
          for (const [dk, dv] of Object.entries(val)) {
            if (dv !== null && dv !== undefined) {
              node.dataset[dk] = String(dv);
            }
          }
        }
        else if (key.startsWith('on')) {
          node.addEventListener(key.slice(2).toLowerCase(), val);
        }
        else if (val !== null && val !== undefined) {
          node.setAttribute(key, val);
        }
      }
    }
    if (children) {
      for (const c of children) {
        if (c == null) continue;
        if (typeof c === 'string') { node.appendChild(document.createTextNode(c)); }
        else { node.appendChild(c); }
      }
    }
    return node;
  }

  function renderColumns() {
    columnsEl.textContent = '';
    const byCol = new Map();
    for (const col of data.columns || []) { byCol.set(col.id, []); }
    for (const node of data.nodes || []) {
      if (byCol.has(node.column)) { byCol.get(node.column).push(node); }
    }
    for (const col of data.columns || []) {
      const colEl = el('section', { class: 'arch-column' }, [
        el('h3', { class: 'arch-column__title', text: col.label }),
      ]);
      const sortedNodes = byCol.get(col.id) || [];
      for (const node of sortedNodes) { colEl.appendChild(renderNode(node)); }
      columnsEl.appendChild(colEl);
    }
  }

  function renderNode(node) {
    const sub = nodeSubLabel(node);
    const badge = node.is_canonical
      ? el('span', { class: 'arch-node__badge', text: 'canonical' })
      : null;
    const stepIndex = el('span', {
      class: 'arch-node__step-index',
      'aria-hidden': 'true',
    });
    const labelParts = (node.label || '').split('_').flatMap((part, i, arr) =>
      i < arr.length - 1
        ? [document.createTextNode(part + '_'), document.createElement('wbr')]
        : [document.createTextNode(part)]
    );
    const labelEl = el('span', { class: 'arch-node__label' }, [
      stepIndex, ...labelParts,
      badge ? document.createTextNode(' ') : null,
      badge,
    ]);
    const subEl = sub ? el('span', { class: 'arch-node__sub', text: sub }) : null;
    const btn = el('button', {
      type: 'button',
      class: 'arch-node',
      dataset: { id: node.id, column: node.column, kind: node.kind },
      'aria-pressed': 'false',
      onclick: () => onNodeClick(node),
    }, [labelEl, subEl]);
    return btn;
  }

  function nodeSubLabel(node) {
    if (node.kind === 'actor') return '';
    if (node.kind === 'surface-subcommand') return 'CLI';
    if (node.kind === 'scanner-sub') return 'container sub-scanner';
    if (node.kind === 'linter') return 'lint';
    if (node.kind === 'reporter') return node.is_canonical ? 'canonical' : '';
    if (node.kind === 'artifact' && node.is_canonical) return 'canonical';
    return '';
  }

  function renderFlows() {
    flowsEl.textContent = '';
    for (const flow of data.flows || []) {
      const labelEl = el('span', { class: 'arch-flow__label', text: flow.label });
      const summaryEl = el('span', { class: 'arch-flow__summary', text: flow.summary });
      const btn = el('button', {
        type: 'button',
        class: 'arch-flow' + (flow.kind === 'overlay' ? ' arch-flow--overlay' : ''),
        dataset: { id: flow.id, kind: flow.kind },
        'aria-pressed': 'false',
        onclick: () => onFlowClick(flow.id),
      }, [labelEl, summaryEl]);
      flowsEl.appendChild(el('li', null, [btn]));
    }
  }

  function renderTools() {
    if (!toolsListEl) return;
    toolsListEl.textContent = '';
    for (const tool of data.external_tools || []) {
      toolsListEl.appendChild(
        el('li', null, [
          el('span', {
            class: 'arch-tool' + (tool.critical ? ' arch-tool--critical' : ''),
            title: tool.purpose,
            text: tool.name,
          }),
        ])
      );
    }
  }

  // ─── Flow highlight ──────────────────────────────────────────────

  function applyFlowHighlight() {
    const flow = state.activeFlow ? flowsById.get(state.activeFlow) : null;
    if (flow) {
      pageEl.dataset.flowActive = 'true';
    } else {
      delete pageEl.dataset.flowActive;
    }
    const onPath = new Map();
    if (flow) {
      flow.steps.forEach((step, i) => {
        if (!onPath.has(step.node_id)) {
          onPath.set(step.node_id, step.index);
        }
      });
    }
    for (const btn of columnsEl.querySelectorAll('.arch-node')) {
      const id = btn.dataset.id;
      if (onPath.has(id)) {
        btn.dataset.onPath = 'true';
        const idx = btn.querySelector('.arch-node__step-index');
        if (idx) { idx.textContent = String(onPath.get(id)); }
      } else {
        btn.dataset.onPath = 'false';
        const idx = btn.querySelector('.arch-node__step-index');
        if (idx) { idx.textContent = ''; }
      }
    }
    for (const btn of flowsEl.querySelectorAll('.arch-flow')) {
      btn.setAttribute(
        'aria-pressed',
        btn.dataset.id === state.activeFlow ? 'true' : 'false',
      );
    }
    if (flow) {
      renderSteps(flow);
    } else {
      stepsListEl.textContent = '';
    }
  }

  function renderSteps(flow) {
    stepsListEl.textContent = '';
    flow.steps.forEach((step) => {
      const node = nodesById.get(step.node_id);
      if (!node) return;
      stepsListEl.appendChild(
        el('li', { class: 'arch-step' }, [
          el('span', {
            class: 'arch-step__number',
            text: String(step.index),
          }),
          el('div', { class: 'arch-step__body' }, [
            el('span', { class: 'arch-step__name', text: node.label }),
            document.createTextNode(' '),
            el('span', { text: node.purpose ? truncate(node.purpose, 140) : '' }),
          ]),
        ])
      );
    });
  }

  function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? (s.slice(0, n - 1) + '…') : s;
  }

  function onFlowClick(flowId) {
    state.activeFlow = state.activeFlow === flowId ? null : flowId;
    applyFlowHighlight();
    syncUrl();
  }

  function clearFlow() {
    state.activeFlow = null;
    applyFlowHighlight();
    syncUrl();
  }

  // ─── Side panel ──────────────────────────────────────────────────

  function onNodeClick(node) {
    if (state.configure && isPickerEligible(node)) {
      togglePickerSelection(node.id);
      return;
    }
    openPanel(node);
  }

  function isPickerEligible(node) {
    return node.kind === 'scanner' || node.kind === 'scanner-sub'
        || node.kind === 'linter';
  }

  function openPanel(node) {
    for (const btn of columnsEl.querySelectorAll('.arch-node[data-open]')) {
      delete btn.dataset.open;
    }
    const openBtn = columnsEl.querySelector(`.arch-node[data-id="${cssEscape(node.id)}"]`);
    if (openBtn) { openBtn.dataset.open = 'true'; }
    state.openNodeId = node.id;
    const titleEl = panelEl.querySelector('.arch-panel__label');
    const kindEl = panelEl.querySelector('.arch-panel__kind');
    const bodyEl = panelEl.querySelector('.arch-panel__body');
    titleEl.textContent = node.label || node.id;
    kindEl.textContent = node.kind || '';
    bodyEl.textContent = '';
    if (node.purpose) {
      bodyEl.appendChild(el('p', {
        class: 'arch-panel__purpose', text: node.purpose,
      }));
    }
    if (node.file_paths && node.file_paths.length) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'File paths',
      }));
      const ul = el('ul', { class: 'arch-panel__files' });
      for (const fp of node.file_paths) {
        ul.appendChild(el('li', { text: fp }));
      }
      bodyEl.appendChild(ul);
    }
    if (node.scanner_config && node.scanner_config.yaml) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'argus.yml snippet',
      }));
      const code = el('pre', { class: 'arch-panel__code', text: node.scanner_config.yaml });
      const copyBtn = makeCopyBtn(node.scanner_config.yaml);
      bodyEl.appendChild(code);
      bodyEl.appendChild(copyBtn);
    }
    if (node.cli_invocation) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'CLI invocation',
      }));
      const code = el('pre', { class: 'arch-panel__code', text: node.cli_invocation });
      bodyEl.appendChild(code);
      bodyEl.appendChild(makeCopyBtn(node.cli_invocation));
    }
    if (node.enable_via) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'Enable via',
      }));
      bodyEl.appendChild(el('p', { text: node.enable_via }));
    }
    if (node.entry_point) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'Entry point',
      }));
      bodyEl.appendChild(el('p', { text: node.entry_point }));
    }
    if (node.adr_refs && node.adr_refs.length) {
      bodyEl.appendChild(el('h4', {
        class: 'arch-panel__section-title', text: 'Related ADRs',
      }));
      const wrap = el('div', { class: 'arch-panel__adrs' });
      for (const ref of node.adr_refs) {
        const adr = adrsById.get(ref) || { id: ref, found: false, title: ref };
        const cls = 'arch-panel__adr' + (adr.found ? '' : ' arch-panel__adr--missing');
        wrap.appendChild(el('span', {
          class: cls,
          title: adr.title || ref,
          text: ref,
        }));
      }
      bodyEl.appendChild(wrap);
    }
    panelEl.dataset.open = 'true';
    positionPanelDefault();
  }

  // Minimum top position for the panel — the bottom of the page
  // header (plus a small gap) so the panel can never slide under the
  // header chrome. Read live in case the header height changes
  // (responsive wrap, etc.).
  function panelMinTop() {
    const header = document.querySelector('body > header');
    const headerBottom = header ? header.getBoundingClientRect().bottom : 0;
    return Math.max(8, headerBottom + 4);
  }

  // Place the panel near the top-right on first open; once the user
  // drags or resizes it, leave their position alone on subsequent opens.
  function positionPanelDefault() {
    if (panelEl.dataset.userPlaced === 'true') return;
    const rect = panelEl.getBoundingClientRect();
    const left = Math.max(8, window.innerWidth - rect.width - 16);
    panelEl.style.left = `${left}px`;
    panelEl.style.top = `${panelMinTop()}px`;
  }

  function makeCopyBtn(payload) {
    return el('button', {
      type: 'button',
      class: 'arch-panel__copy',
      text: 'Copy',
      onclick: async () => {
        try { await navigator.clipboard.writeText(payload); }
        catch (_err) { /* clipboard unavailable; silent. */ }
      },
    });
  }

  function closePanel() {
    delete panelEl.dataset.open;
    state.openNodeId = null;
    for (const btn of columnsEl.querySelectorAll('.arch-node[data-open]')) {
      delete btn.dataset.open;
    }
  }

  // ─── Configure (picker) mode ─────────────────────────────────────

  function toggleConfigure(forceOn) {
    state.configure = forceOn !== undefined ? forceOn : !state.configure;
    pageEl.dataset.mode = state.configure ? 'configure' : 'view';
    configureToggleEl.setAttribute(
      'aria-pressed', state.configure ? 'true' : 'false',
    );
    if (pickerEl) { pickerEl.hidden = !state.configure; }
    renderPicker();
    syncUrl();
  }

  function togglePickerSelection(id) {
    if (state.selection.has(id)) { state.selection.delete(id); }
    else { state.selection.add(id); }
    for (const btn of columnsEl.querySelectorAll('.arch-node')) {
      btn.dataset.selected = state.selection.has(btn.dataset.id) ? 'true' : 'false';
    }
    renderPicker();
    syncUrl();
  }

  function selectedScannerNames() {
    const names = [];
    for (const id of state.selection) {
      const n = nodesById.get(id);
      if (!n) continue;
      const short = id.includes(':') ? id.split(':', 2)[1] : id;
      names.push(short);
    }
    return names.sort();
  }

  function renderPicker() {
    if (!pickerEl) return;
    const yamlPane = pickerEl.querySelector('[data-pane="yaml"]');
    const cliPane = pickerEl.querySelector('[data-pane="cli"]');
    const ghPane = pickerEl.querySelector('[data-pane="github"]');
    const mcpPane = pickerEl.querySelector('[data-pane="mcp"]');
    if (!yamlPane || !cliPane || !ghPane || !mcpPane) return;
    const names = selectedScannerNames();
    if (names.length === 0) {
      const hint = 'Click scanners / linters in the columns to add them.';
      yamlPane.textContent = '';
      yamlPane.appendChild(el('p', { class: 'arch-picker__empty', text: hint }));
      cliPane.textContent = '';
      cliPane.appendChild(el('p', { class: 'arch-picker__empty', text: hint }));
      ghPane.textContent = '';
      ghPane.appendChild(el('p', { class: 'arch-picker__empty', text: hint }));
      mcpPane.textContent = '';
      mcpPane.appendChild(el('p', { class: 'arch-picker__empty', text: hint }));
      return;
    }
    fillPaneCode(yamlPane, buildYaml(names));
    fillPaneCode(cliPane, buildCli(names));
    fillPaneCode(ghPane, buildGithubWorkflow(names));
    fillPaneCode(mcpPane, buildMcpConfig(names));
  }

  function fillPaneCode(pane, text) {
    pane.textContent = '';
    pane.appendChild(el('pre', { class: 'arch-panel__code', text }));
    pane.appendChild(makeCopyBtn(text));
  }

  function buildYaml(names) {
    const lines = ['version: "1.0"', 'scanners:'];
    for (const name of names) {
      lines.push(`  ${name}:`);
      lines.push('    enabled: true');
    }
    if (state.severityThreshold && state.severityThreshold !== 'none') {
      lines.push('reporting:');
      lines.push(`  severity_threshold: ${state.severityThreshold}`);
    }
    if (state.format && state.format !== 'terminal') {
      lines.push('reporting:');
      lines.push(`  formats: ["${state.format}"]`);
    }
    return lines.join('\n') + '\n';
  }

  function buildCli(names) {
    const parts = ['argus scan', ...names];
    if (state.severityThreshold && state.severityThreshold !== 'none') {
      parts.push('--severity-threshold', state.severityThreshold);
    }
    if (state.format && state.format !== 'terminal') {
      parts.push('--format', state.format);
    }
    return parts.join(' ') + '\n';
  }

  function buildGithubWorkflow(names) {
    const version = data.version || 'main';
    const ref = /^\d+\.\d+\.\d+$/.test(version) ? `v${version}` : 'main';
    const steps = [];
    steps.push('jobs:');
    steps.push('  argus:');
    steps.push('    runs-on: ubuntu-latest');
    steps.push('    steps:');
    steps.push('      - uses: actions/checkout@v5');
    for (const name of names) {
      // Composite-action names mirror SDK scanner names where one
      // exists; linters use ``linter-<name>``.
      const action = name.startsWith('lint-')
        ? `linter-${name.slice('lint-'.length)}`
        : `scanner-${name}`;
      // ``${ref}`` is computed at runtime from data.version; the static
      // ref shape would never resolve here, so release-it-ignore the line.
      steps.push(`      - uses: huntridge-labs/argus/.github/actions/${action}@${ref}`);  // release-it-ignore
      if (state.severityThreshold && state.severityThreshold !== 'none') {
        steps.push('        with:');
        steps.push(`          fail_on_severity: ${state.severityThreshold}`);
      }
    }
    return steps.join('\n') + '\n';
  }

  function buildMcpConfig(names) {
    const cfg = {
      mcpServers: {
        argus: {
          command: 'argus',
          args: ['mcp'],
          env: { ARGUS_SCANNERS: names.join(',') },
        },
      },
    };
    return JSON.stringify(cfg, null, 2) + '\n';
  }

  function setupPickerTabs() {
    if (!pickerEl) return;
    const tabs = pickerEl.querySelectorAll('[data-tab]');
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        tabs.forEach((t) => {
          t.setAttribute(
            'aria-selected', t.dataset.tab === target ? 'true' : 'false',
          );
        });
        pickerEl.querySelectorAll('[data-pane]').forEach((pane) => {
          pane.dataset.active = pane.dataset.pane === target ? 'true' : 'false';
        });
      });
    });
  }

  function setupPickerControls() {
    if (!pickerEl) return;
    const sev = pickerEl.querySelector('[data-control="severity"]');
    if (sev) {
      sev.value = state.severityThreshold;
      sev.addEventListener('change', () => {
        state.severityThreshold = sev.value;
        renderPicker();
        syncUrl();
      });
    }
    const fmt = pickerEl.querySelector('[data-control="format"]');
    if (fmt) {
      fmt.value = state.format;
      fmt.addEventListener('change', () => {
        state.format = fmt.value;
        renderPicker();
        syncUrl();
      });
    }
  }

  // ─── URL state ───────────────────────────────────────────────────

  function syncUrl() {
    const params = new URLSearchParams();
    if (state.activeFlow) { params.set('flow', state.activeFlow); }
    if (state.configure) { params.set('mode', 'configure'); }
    if (state.selection.size) {
      params.set('scanners', selectedScannerNames().join(','));
    }
    if (state.severityThreshold !== 'none') {
      params.set('sev', state.severityThreshold);
    }
    if (state.format !== 'terminal') { params.set('fmt', state.format); }
    const qs = params.toString();
    const url = window.location.pathname + (qs ? '?' + qs : '');
    window.history.replaceState(null, '', url);
  }

  function restoreUrl() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('flow') && flowsById.has(params.get('flow'))) {
      state.activeFlow = params.get('flow');
    }
    if (params.get('mode') === 'configure') { state.configure = true; }
    const scanners = params.get('scanners');
    if (scanners) {
      for (const name of scanners.split(',').filter(Boolean)) {
        // Match against scanner: / scanner-sub / linter: prefixes.
        for (const prefix of ['scanner:', 'linter:']) {
          if (nodesById.has(prefix + name)) {
            state.selection.add(prefix + name);
          }
        }
      }
    }
    if (params.get('sev')) { state.severityThreshold = params.get('sev'); }
    if (params.get('fmt')) { state.format = params.get('fmt'); }
  }

  // ─── Wire up ────────────────────────────────────────────────────

  renderColumns();
  renderFlows();
  renderTools();
  setupPickerTabs();
  setupPickerControls();
  restoreUrl();

  // Reflect restored state into the DOM.
  applyFlowHighlight();
  if (state.configure) { toggleConfigure(true); }
  for (const id of state.selection) {
    const btn = columnsEl.querySelector(`.arch-node[data-id="${cssEscape(id)}"]`);
    if (btn) { btn.dataset.selected = 'true'; }
  }
  renderPicker();

  // ─── Zoom / pan ─────────────────────────────────────────────────────
  const viewportEl = document.getElementById('arch-columns-viewport');
  if (viewportEl) {
    const zs = { scale: 1, x: 0, y: 0 };
    const SCALE_MIN = 0.25, SCALE_MAX = 2;
    const zoomInEl    = document.getElementById('arch-zoom-in');
    const zoomOutEl   = document.getElementById('arch-zoom-out');
    const zoomResetEl = document.getElementById('arch-zoom-reset');
    const zoomFitEl   = document.getElementById('arch-zoom-fit');

    // Pick the best scaling primitive for the current browser.
    // ``zoom`` re-rasterizes text at the new size (sharp output) and
    // works correctly in Chrome and Firefox 126+. Safari supports
    // ``zoom`` syntactically but does not scale grid column widths
    // in lockstep with font sizes, so text wraps incorrectly. Fall
    // back to ``transform: scale`` there — slightly blurry but
    // layout stays stable.
    const isSafari = /^((?!chrome|android|crios|fxios).)*safari/i
      .test(navigator.userAgent);
    const useCssZoom = !isSafari;

    let baseWidth = 0, baseHeight = 0;
    function measureBaseSize() {
      const savedZoom = columnsEl.style.zoom;
      const savedTransform = columnsEl.style.transform;
      columnsEl.style.zoom = '1';
      columnsEl.style.transform = '';
      baseWidth = columnsEl.scrollWidth;
      baseHeight = columnsEl.scrollHeight;
      columnsEl.style.zoom = savedZoom;
      columnsEl.style.transform = savedTransform;
    }

    function applyZoom() {
      if (useCssZoom) {
        columnsEl.style.zoom = zs.scale;
        // ``transform: translate`` on a zoomed element is interpreted
        // in the zoomed coordinate space (a 50px translate at zoom 2
        // visually moves 100px). Divide by zoom to convert viewport
        // CSS pixels to the translate value the browser expects.
        const tx = zs.x / zs.scale;
        const ty = zs.y / zs.scale;
        columnsEl.style.transform = `translate(${tx}px, ${ty}px)`;
      } else {
        columnsEl.style.zoom = '';
        columnsEl.style.transform =
          `translate(${zs.x}px, ${zs.y}px) scale(${zs.scale})`;
      }
      if (zoomResetEl) {
        zoomResetEl.textContent = `${Math.round(zs.scale * 100)}%`;
      }
    }

    function zoomAround(cx, cy, factor) {
      const next = Math.min(SCALE_MAX, Math.max(SCALE_MIN, zs.scale * factor));
      const r = next / zs.scale;
      zs.x = cx - r * (cx - zs.x);
      zs.y = cy - r * (cy - zs.y);
      zs.scale = next;
      applyZoom();
    }

    viewportEl.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = viewportEl.getBoundingClientRect();
      zoomAround(e.clientX - rect.left, e.clientY - rect.top,
                 e.deltaY < 0 ? 1.1 : 1 / 1.1);
    }, { passive: false });

    // Pan: pointer-down anywhere inside the viewport (including over
    // node buttons) primes a drag. Only after the cursor moves past a
    // small threshold (4px) does panning actually begin, so a quick
    // click on a node still opens its detail panel. When the drag
    // does engage, the trailing ``click`` event is swallowed so a
    // pan that happens to release over a button doesn't accidentally
    // open it. Clicks on the floating zoom controls are left alone.
    const DRAG_THRESHOLD = 4;
    let drag = null;
    viewportEl.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      if (e.target.closest('.arch-zoom-controls')) return;
      drag = {
        sx: e.clientX, sy: e.clientY,
        px: zs.x, py: zs.y,
        moved: false,
      };
    });
    window.addEventListener('mousemove', (e) => {
      if (!drag) return;
      const dx = e.clientX - drag.sx;
      const dy = e.clientY - drag.sy;
      if (!drag.moved &&
          (Math.abs(dx) > DRAG_THRESHOLD || Math.abs(dy) > DRAG_THRESHOLD)) {
        drag.moved = true;
        viewportEl.style.cursor = 'grabbing';
      }
      if (drag.moved) {
        zs.x = drag.px + dx;
        zs.y = drag.py + dy;
        applyZoom();
        e.preventDefault();
      }
    });
    window.addEventListener('mouseup', () => {
      if (!drag) return;
      const wasMoved = drag.moved;
      drag = null;
      viewportEl.style.cursor = '';
      if (wasMoved) {
        const swallow = (ev) => {
          ev.stopPropagation();
          ev.preventDefault();
          window.removeEventListener('click', swallow, true);
        };
        window.addEventListener('click', swallow, true);
        // Safety net: clean up the listener if no click fires (drag
        // released over empty space, outside any clickable element).
        setTimeout(() => window.removeEventListener('click', swallow, true), 50);
      }
    });

    // Reset = fit-to-view: scale so the entire diagram is visible
    // inside the viewport, then centre it. Capped at 1 so a small
    // diagram in a large viewport doesn't zoom in past 100 %. The
    // user can wheel-zoom or click + from here to dig deeper.
    function resetView() {
      if (!baseWidth || !baseHeight) measureBaseSize();
      const dw = baseWidth;
      const dh = baseHeight;
      const vw = viewportEl.clientWidth;
      const vh = viewportEl.clientHeight;
      if (!dw || !dh || !vw || !vh) {
        zs.scale = 1;
        zs.x = 0;
        zs.y = 0;
      } else {
        const fit = Math.min(1, vw / dw, vh / dh);
        zs.scale = fit;
        zs.x = Math.max(0, (vw - dw * fit) / 2);
        zs.y = Math.max(0, (vh - dh * fit) / 2);
      }
      applyZoom();
    }

    if (zoomInEl)    { zoomInEl.addEventListener('click',    () => zoomAround(viewportEl.clientWidth / 2, viewportEl.clientHeight / 2, 1.2)); }
    if (zoomOutEl)   { zoomOutEl.addEventListener('click',   () => zoomAround(viewportEl.clientWidth / 2, viewportEl.clientHeight / 2, 1 / 1.2)); }
    if (zoomResetEl) { zoomResetEl.addEventListener('click', resetView); }
    if (zoomFitEl)   { zoomFitEl.addEventListener('click',   resetView); }

    // Auto-fit on initial render so the whole diagram is visible on
    // any viewport size. ``requestAnimationFrame`` lets the columns
    // render (so ``scrollWidth``/``scrollHeight`` reflect real sizes)
    // before we measure.
    requestAnimationFrame(resetView);
  }

  // ─── Panel drag ─────────────────────────────────────────────────────
  const panelHeaderEl = document.getElementById('arch-panel-header');
  if (panelHeaderEl && panelEl) {
    let pd = null;
    panelHeaderEl.addEventListener('mousedown', (e) => {
      if (e.button !== 0 || e.target.closest('button')) return;
      const r = panelEl.getBoundingClientRect();
      pd = { sx: e.clientX, sy: e.clientY, px: r.left, py: r.top, w: r.width, h: r.height };
      panelEl.dataset.userPlaced = 'true';
      e.preventDefault();
    });
    window.addEventListener('mousemove', (e) => {
      if (!pd) return;
      const margin = 8;
      const minTop = panelMinTop();
      const maxLeft = window.innerWidth - pd.w - margin;
      const maxTop = window.innerHeight - 40;
      let nx = pd.px + (e.clientX - pd.sx);
      let ny = pd.py + (e.clientY - pd.sy);
      nx = Math.max(margin, Math.min(nx, maxLeft));
      ny = Math.max(minTop, Math.min(ny, maxTop));
      panelEl.style.left = `${nx}px`;
      panelEl.style.top = `${ny}px`;
    });
    window.addEventListener('mouseup', () => { pd = null; });
  }

  // ─── Sidebar / footer clearance ──────────────────────────────────
  // The sidebars are ``position: fixed`` so they ignore page scroll.
  // When the user scrolls far enough to reveal the global footer,
  // the sidebars' bottom edges would overlap it. Watch the footer's
  // top edge and lift the sidebars by however much is intruding.
  const footerEl = document.querySelector('body > footer');
  const sidebars = document.querySelectorAll('.arch-page__sidebar');
  function updateSidebarBottom() {
    if (!footerEl || sidebars.length === 0) return;
    const fr = footerEl.getBoundingClientRect();
    const overlap = Math.max(0, window.innerHeight - fr.top);
    const bottomPx = 16 + overlap; // 1rem base + the intruding pixels
    for (const s of sidebars) {
      s.style.bottom = `${bottomPx}px`;
    }
  }
  window.addEventListener('scroll', updateSidebarBottom, { passive: true });
  window.addEventListener('resize', updateSidebarBottom);
  updateSidebarBottom();

  // ─── Info popover ────────────────────────────────────────────────
  const infoToggleEl = document.getElementById('arch-info-toggle');
  const infoPopoverEl = document.getElementById('arch-info-popover');
  if (infoToggleEl && infoPopoverEl) {
    const setInfo = (open) => {
      infoPopoverEl.hidden = !open;
      infoToggleEl.setAttribute('aria-expanded', open ? 'true' : 'false');
    };
    infoToggleEl.addEventListener('click', (e) => {
      e.stopPropagation();
      setInfo(infoPopoverEl.hidden);
    });
    // Dismiss when clicking outside the popover or its toggle.
    document.addEventListener('click', (e) => {
      if (infoPopoverEl.hidden) return;
      if (e.target === infoToggleEl || infoToggleEl.contains(e.target)) return;
      if (infoPopoverEl.contains(e.target)) return;
      setInfo(false);
    });
  }

  if (flowClearEl) { flowClearEl.addEventListener('click', clearFlow); }
  if (panelCloseEl) { panelCloseEl.addEventListener('click', closePanel); }
  if (configureToggleEl) {
    configureToggleEl.addEventListener('click', () => toggleConfigure());
  }

  // ─── Responsive drawer toggles ───────────────────────────────────
  function setDrawer(which, open) {
    const sidebar = which === 'flows' ? flowsSidebarEl : stepsSidebarEl;
    const btn = which === 'flows' ? toggleFlowsEl : toggleStepsEl;
    const other = which === 'flows' ? stepsSidebarEl : flowsSidebarEl;
    const otherBtn = which === 'flows' ? toggleStepsEl : toggleFlowsEl;
    if (!sidebar) return;
    if (open) {
      delete other?.dataset.open;
      if (otherBtn) otherBtn.setAttribute('aria-pressed', 'false');
      sidebar.dataset.open = 'true';
      if (btn) btn.setAttribute('aria-pressed', 'true');
      pageEl.dataset.drawerOpen = which;
    } else {
      delete sidebar.dataset.open;
      if (btn) btn.setAttribute('aria-pressed', 'false');
      delete pageEl.dataset.drawerOpen;
    }
  }
  function closeDrawers() {
    setDrawer('flows', false);
    setDrawer('steps', false);
  }
  if (toggleFlowsEl) {
    toggleFlowsEl.addEventListener('click', () => {
      const isOpen = flowsSidebarEl?.dataset.open === 'true';
      setDrawer('flows', !isOpen);
    });
  }
  if (toggleStepsEl) {
    toggleStepsEl.addEventListener('click', () => {
      const isOpen = stepsSidebarEl?.dataset.open === 'true';
      setDrawer('steps', !isOpen);
    });
  }
  if (drawerBackdropEl) {
    drawerBackdropEl.addEventListener('click', closeDrawers);
  }
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      if (infoPopoverEl && !infoPopoverEl.hidden) {
        infoPopoverEl.hidden = true;
        infoToggleEl?.setAttribute('aria-expanded', 'false');
      }
      else if (pageEl.dataset.drawerOpen) { closeDrawers(); }
      else if (panelEl.dataset.open === 'true') { closePanel(); }
      else if (state.activeFlow) { clearFlow(); }
    }
  });

  function cssEscape(s) {
    return s.replace(/[^a-zA-Z0-9_\-:.]/g, (c) => `\\${c}`);
  }
})();
