/* argus serve — animated count-up for the dashboard stat cards (Phase B0).
 *
 * Progressive enhancement: the server already renders the final numbers, so
 * with no JS (or under prefers-reduced-motion) the cards read correctly and
 * we simply leave them be. When motion is allowed we count up from 0 with an
 * ease-out so the dashboard feels alive on load. External (not inline)
 * because the page ships a strict CSP (script-src 'self'). */
(function () {
  "use strict";

  var reduce =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var els = document.querySelectorAll("[data-count]");
  if (!els.length) return;

  els.forEach(function (el) {
    var target = parseInt(el.getAttribute("data-count"), 10);
    if (isNaN(target)) return;
    if (reduce || target <= 0) {
      el.textContent = String(target);
      return;
    }
    var duration = 700;
    var start = null;
    function tick(now) {
      if (start === null) start = now;
      var t = Math.min(1, (now - start) / duration);
      var eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      el.textContent = String(Math.round(eased * target));
      if (t < 1) {
        window.requestAnimationFrame(tick);
      } else {
        el.textContent = String(target);
      }
    }
    window.requestAnimationFrame(tick);
    // Guarantee the final value lands even if rAF stalls (e.g. background
    // tab, or a headless screenshot's virtual clock) — timers fire reliably
    // where rAF may not, so the displayed number always ends exact.
    window.setTimeout(function () { el.textContent = String(target); }, duration + 80);
  });
})();
