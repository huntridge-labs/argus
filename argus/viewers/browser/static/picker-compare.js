/* argus serve — picker compare-select.
 *
 * Each scan-ready row in the picker renders a checkbox with
 * data-scan-path set to the absolute scan path. When exactly two
 * are checked, this script enables the Compare button and points
 * it at /diff?a=<first>&b=<second>. Any other count disables it
 * (and if more than two are checked, the status line warns the
 * user rather than silently picking two).
 *
 * Zero-JS fallback: without this script the checkboxes still
 * render but the Compare bar stays hidden (its hidden attr lives
 * on the markup). Users on a no-JS build fall back to navigating
 * into a scan and hitting /diff?a=X&b=Y manually — still
 * documented, just less ergonomic.
 */
(function () {
  "use strict";

  var bar = document.getElementById("picker-compare-bar");
  var btn = document.getElementById("picker-compare-btn");
  var status = document.getElementById("picker-compare-status");
  var checkboxes = document.querySelectorAll(".picker-compare-cb");
  if (!bar || !btn || checkboxes.length === 0) { return; }

  // Unhide the compare bar once JS is alive. Markup default is
  // hidden so non-JS users don't see a button they can't use.
  bar.hidden = false;

  function selectedPaths() {
    var paths = [];
    for (var i = 0; i < checkboxes.length; i++) {
      if (checkboxes[i].checked) {
        paths.push(checkboxes[i].getAttribute("data-scan-path"));
      }
    }
    return paths;
  }

  function updateCompareState() {
    var paths = selectedPaths();
    if (paths.length === 0) {
      btn.disabled = true;
      btn.removeAttribute("data-href");
      status.textContent = "Check two scans to compare.";
      status.removeAttribute("data-tone");
    } else if (paths.length === 1) {
      btn.disabled = true;
      btn.removeAttribute("data-href");
      status.textContent = "1 selected — pick one more.";
      status.setAttribute("data-tone", "info");
    } else if (paths.length === 2) {
      var href = "/diff?a=" + encodeURIComponent(paths[0]) +
                 "&b=" + encodeURIComponent(paths[1]);
      btn.disabled = false;
      btn.setAttribute("data-href", href);
      status.textContent = "2 selected — ready.";
      status.setAttribute("data-tone", "ok");
    } else {
      btn.disabled = true;
      btn.removeAttribute("data-href");
      status.textContent = paths.length + " selected — diff compares two. Uncheck " +
                           (paths.length - 2) + ".";
      status.setAttribute("data-tone", "error");
    }
  }

  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].addEventListener("change", updateCompareState);
  }
  btn.addEventListener("click", function () {
    var href = btn.getAttribute("data-href");
    if (href) { window.location.href = href; }
  });

  updateCompareState();
})();
