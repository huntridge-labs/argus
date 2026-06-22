/* argus view browser — progressive-enhancement filter refresh.
 *
 * The findings form works fully without JavaScript (plain GET submit
 * renders a new page). This script upgrades the experience: as the
 * user changes dropdowns or types in the search box, fetch the
 * ``?partial=1`` fragment and swap it into the existing table body
 * so the page never reloads. URL stays bookmarkable (via history
 * API) and the same query-param shape powers both paths.
 *
 * Vendored vanilla rather than HTMX because the scope is tiny (one
 * form, one target) and a ~15 KB framework for that is disproportionate.
 * If we grow more interactive pages later and duplicate this
 * pattern, switch to HTMX then.
 *
 * Security note on innerHTML: the fragment comes from this same
 * origin's /findings?partial=1 endpoint, which renders via Jinja2
 * with autoescape on (default for .html.j2 templates). All scanner-
 * supplied strings are HTML-escaped before they reach the wire.
 * Combined with the CSP 'script-src self' header — which blocks any
 * inline <script> that might slip through — the attack surface for
 * content injection here is zero. Using innerHTML is the right
 * tool (we need to parse HTML fragments, not textContent).
 */
(function () {
  "use strict";

  var form = document.querySelector("form[data-auto-filter]");
  if (!form) { return; }
  var target = document.getElementById("findings-target");
  if (!target) { return; }

  var debounceTimer = null;

  function buildUrl(includePartial) {
    var params = new URLSearchParams();
    new FormData(form).forEach(function (value, key) {
      // Skip blank values so URLs stay short and readable.
      if (value) { params.append(key, value); }
    });
    if (includePartial) { params.append("partial", "1"); }
    var query = params.toString();
    return form.action + (query ? "?" + query : "");
  }

  function swapContent(html) {
    // Intentional innerHTML use — see module docstring for the
    // trust-boundary rationale. CSP blocks any <script> in the
    // fragment; Jinja autoescape neutralizes scanner-supplied text.
    target.innerHTML = html;
  }

  async function refresh() {
    // Subtle loading state so the user gets feedback on slow disks
    // / big scans. The CSS rule dims the target until content swaps
    // back in. Class is cleared in both the success and failure
    // paths below so we never leave the table stuck "loading".
    target.classList.add("is-loading");
    try {
      var resp = await fetch(buildUrl(true), {
        headers: { "Accept": "text/html" },
        credentials: "same-origin",
      });
      if (!resp.ok) {
        // Server responded but unhappily — log so a user debugging
        // via devtools can see why the table didn't refresh. The
        // full-page Apply button is still the fallback path.
        console.warn(
          "argus view browser: filter refresh returned HTTP " + resp.status +
          " — leaving table as-is. Click Apply to submit as a full page."
        );
        return;
      }
      swapContent(await resp.text());
      // Keep the browser URL in sync so refresh / share / back-button
      // all observe the current filter state.
      window.history.replaceState(null, "", buildUrl(false));
    } catch (err) {
      // Network hiccup — leave the table as-is. Surface the error
      // to devtools so it isn't silently swallowed; full-page submit
      // via the Apply button is always the fallback.
      console.warn("argus view browser: filter refresh failed:", err);
    } finally {
      target.classList.remove("is-loading");
    }
  }

  form.addEventListener("change", function (event) {
    var isSearch = event.target && event.target.type === "search";
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(refresh, isSearch ? 300 : 0);
  });

  form.addEventListener("input", function (event) {
    // Debounce keystrokes in the search input so we don't fire on
    // every character — 300 ms is short enough to feel live and long
    // enough to coalesce a normal typing burst.
    if (event.target && event.target.type === "search") {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(refresh, 300);
    }
  });

  // Suppress the default full-page submit when JS is live — the
  // Apply button is decorative once auto-filter is running.
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    refresh();
  });
})();
