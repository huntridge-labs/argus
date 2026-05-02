/* argus serve — theme toggle.
 *
 * Reads localStorage for a saved preference, applies it via
 * data-theme on <html>, and flips on click. With no saved pref the
 * initial render uses prefers-color-scheme (handled entirely in
 * argus.css); this script only activates user overrides.
 *
 * Storage key: "argus-theme" — "light" or "dark". Any other value
 * is treated as unset.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "argus-theme";
  var btn = document.getElementById("theme-toggle");
  var icon = btn && btn.querySelector(".theme-toggle-icon");
  var label = btn && btn.querySelector(".theme-toggle-label");
  if (!btn) { return; }

  function readSavedTheme() {
    try {
      var v = localStorage.getItem(STORAGE_KEY);
      return (v === "light" || v === "dark") ? v : null;
    } catch (e) {
      // Private mode or disabled storage — fall back to OS pref.
      return null;
    }
  }

  function resolvedTheme() {
    // What's actually in effect right now? Explicit override wins;
    // otherwise match the OS pref so the icon / aria-label reflect
    // reality.
    var attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") { return attr; }
    try {
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
        return "light";
      }
    } catch (e) { /* matchMedia unsupported — default to dark */ }
    return "dark";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    updateButton(theme);
  }

  function updateButton(theme) {
    // Icon flips — moon glyph when currently light (click → dark),
    // sun glyph when currently dark (click → light). The label is
    // sr-only but still updates for assistive tech.
    if (icon) {
      icon.textContent = theme === "light" ? "☾" : "☀";
    }
    if (label) {
      label.textContent = theme === "light" ? "Switch to dark" : "Switch to light";
    }
    btn.setAttribute(
      "aria-label",
      theme === "light" ? "Switch to dark theme" : "Switch to light theme"
    );
  }

  // Initial sync: apply the saved theme (if any) and update the icon.
  // Without a saved pref, argus.css's @media has already applied the
  // right palette; we just need to set the icon based on what's live.
  var saved = readSavedTheme();
  if (saved) {
    applyTheme(saved);
  } else {
    updateButton(resolvedTheme());
  }

  btn.addEventListener("click", function () {
    var next = resolvedTheme() === "light" ? "dark" : "light";
    applyTheme(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch (e) {
      // Can't persist — the flip still applies for the session.
    }
  });
})();
