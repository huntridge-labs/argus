/* argus view browser — command palette (Phase B0).
 *
 * Cmd/Ctrl-K opens a fuzzy launcher over the page's own navigation: jump to
 * any view, severity filter, product, or scanner without the mouse — browser
 * parity with the TUI's Ctrl+P, and the kind of touch that makes a tool feel
 * like a product.
 *
 * Progressive enhancement + CSP-friendly: the overlay is built in the DOM by
 * this 'self' script (no inline JS), commands are scraped from existing
 * links already on the page (no inline data blob), and with no JS the page
 * navigates normally. Honours prefers-reduced-motion. Append `#command` to a
 * URL to auto-open it (used to capture docs screenshots). */
(function () {
  "use strict";

  var reduce =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Collect navigable commands from the page. ``[data-cmd]`` marks a curated
  // target (its value is the label); we also fold in the header nav links.
  function collectCommands() {
    var seen = {};
    var out = [];
    function add(label, href) {
      label = (label || "").replace(/\s+/g, " ").trim();
      if (!label || !href || seen[label + "|" + href]) return;
      seen[label + "|" + href] = true;
      out.push({ label: label, href: href });
    }
    document.querySelectorAll("[data-cmd][href]").forEach(function (el) {
      add(el.getAttribute("data-cmd"), el.href);
    });
    document.querySelectorAll("header nav a[href]").forEach(function (el) {
      add(el.textContent, el.href);
    });
    return out;
  }

  // Subsequence fuzzy match: every query char appears in order. Empty query
  // matches everything (recently-built order preserved).
  function matches(query, label) {
    if (!query) return true;
    query = query.toLowerCase();
    label = label.toLowerCase();
    var qi = 0;
    for (var i = 0; i < label.length && qi < query.length; i++) {
      if (label[i] === query[qi]) qi++;
    }
    return qi === query.length;
  }

  var commands = [];
  var overlay, input, list, selected = 0, filtered = [];

  function build() {
    overlay = document.createElement("div");
    overlay.className = "cmdk-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Command palette");
    overlay.hidden = true;
    if (reduce) overlay.setAttribute("data-reduce", "");

    var box = document.createElement("div");
    box.className = "cmdk-box";
    input = document.createElement("input");
    input.className = "cmdk-input";
    input.type = "text";
    input.setAttribute("placeholder", "Jump to… (type to filter, ↑↓ + Enter)");
    input.setAttribute("aria-label", "Filter commands");
    list = document.createElement("ul");
    list.className = "cmdk-list";
    box.appendChild(input);
    box.appendChild(list);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    overlay.addEventListener("mousedown", function (e) {
      if (e.target === overlay) close();
    });
    input.addEventListener("input", render);
    input.addEventListener("keydown", onKey);
  }

  function render() {
    var q = input.value.trim();
    filtered = commands.filter(function (c) { return matches(q, c.label); });
    selected = 0;
    while (list.firstChild) list.removeChild(list.firstChild);  // no innerHTML
    filtered.forEach(function (c, i) {
      var li = document.createElement("li");
      li.className = "cmdk-item" + (i === selected ? " is-selected" : "");
      li.textContent = c.label;
      li.addEventListener("mouseenter", function () { selected = i; paint(); });
      li.addEventListener("mousedown", function (e) { e.preventDefault(); go(c); });
      list.appendChild(li);
    });
  }

  function paint() {
    var items = list.children;
    for (var i = 0; i < items.length; i++) {
      items[i].className = "cmdk-item" + (i === selected ? " is-selected" : "");
    }
    if (items[selected]) items[selected].scrollIntoView({ block: "nearest" });
  }

  function onKey(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); selected = Math.min(selected + 1, filtered.length - 1); paint(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); selected = Math.max(selected - 1, 0); paint(); }
    else if (e.key === "Enter") { e.preventDefault(); if (filtered[selected]) go(filtered[selected]); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  }

  function go(cmd) { window.location.href = cmd.href; }

  function open() {
    if (!overlay) build();
    commands = collectCommands();
    input.value = "";
    render();
    overlay.hidden = false;
    input.focus();
  }

  function close() { if (overlay) overlay.hidden = true; }

  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      overlay && !overlay.hidden ? close() : open();
    }
  });

  // A clickable affordance (the ⌘K hint in the header) opens it too, and we
  // localise its label to the platform's modifier: macOS shows ⌘, everyone
  // else (Windows / Linux — no Command key) shows Ctrl. The keybinding itself
  // already accepts either (metaKey || ctrlKey); this just fixes the *label*.
  var isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent || "");
  document.querySelectorAll("[data-cmdk-open]").forEach(function (el) {
    el.addEventListener("click", function (e) { e.preventDefault(); open(); });
    var kbd = el.querySelector("kbd");
    if (kbd) kbd.textContent = isMac ? "⌘K" : "Ctrl K";
  });

  // Auto-open for screenshots / deep-links.
  if (window.location.hash === "#command") {
    if (document.readyState !== "loading") open();
    else document.addEventListener("DOMContentLoaded", open);
  }
})();
