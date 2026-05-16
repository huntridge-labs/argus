/* argus serve — humanize scan-file mtime in the metadata panel.
 *
 * The server renders the epoch as a raw integer so the page works
 * without JS. This script upgrades that to a locale-formatted
 * date/time like "Apr 24, 2026, 2:54:13 PM" with a relative
 * suffix ("2 hours ago") when recent.
 */
(function () {
  "use strict";

  function relative(deltaSec) {
    var abs = Math.abs(deltaSec);
    if (abs < 60)        { return Math.round(abs) + "s ago"; }
    if (abs < 3600)      { return Math.round(abs / 60) + "m ago"; }
    if (abs < 86400)     { return Math.round(abs / 3600) + "h ago"; }
    if (abs < 2592000)   { return Math.round(abs / 86400) + "d ago"; }
    return Math.round(abs / 2592000) + "mo ago";
  }

  var elems = document.querySelectorAll(".scan-mtime[data-epoch]");
  var now = Date.now() / 1000;
  for (var i = 0; i < elems.length; i++) {
    var el = elems[i];
    var epoch = parseFloat(el.getAttribute("data-epoch"));
    if (isNaN(epoch)) { continue; }
    var d = new Date(epoch * 1000);
    var abs = d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "numeric", minute: "2-digit",
    });
    var rel = relative(now - epoch);
    el.textContent = abs + " (" + rel + ")";
    el.setAttribute("datetime", d.toISOString());
  }
})();
