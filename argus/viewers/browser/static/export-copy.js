/* argus serve — Copy-to-clipboard button for the Export menu.
 *
 * Each Copy button carries the /export URL in data-export-url. On
 * click we fetch the serialized content, write it to the clipboard
 * via navigator.clipboard.writeText, and flash a short confirmation
 * in the status line. Fallback when the Clipboard API is unavailable
 * (insecure context, permission denied): select-all a hidden textarea
 * so the user can hit Cmd/Ctrl+C manually.
 *
 * Zero framework dependency to keep the CSP simple (script-src 'self'
 * with no 'unsafe-inline'). The menu still works fully without JS —
 * "Download" is a plain anchor and does not need this script.
 */
(function () {
  "use strict";

  var menu = document.querySelector(".export-menu");
  if (!menu) { return; }
  var status = menu.querySelector(".export-status");

  function flash(msg, tone) {
    if (!status) { return; }
    status.textContent = msg;
    status.setAttribute("data-tone", tone || "ok");
    // Clear after a few seconds so the status doesn't read stale.
    setTimeout(function () {
      if (status.textContent === msg) {
        status.textContent = "";
        status.removeAttribute("data-tone");
      }
    }, 3000);
  }

  async function copyViaClipboardApi(text) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      throw new Error("Clipboard API unavailable");
    }
    await navigator.clipboard.writeText(text);
  }

  function copyViaTextareaFallback(text) {
    // Off-screen textarea + document.execCommand("copy"). Deprecated
    // but still works in browsers that block the Clipboard API for
    // non-HTTPS or cross-origin reasons — and localhost is sometimes
    // such a context in strict corporate configs.
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "absolute";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      var ok = document.execCommand && document.execCommand("copy");
      if (!ok) { throw new Error("execCommand('copy') returned false"); }
    } finally {
      document.body.removeChild(ta);
    }
  }

  async function handleCopy(ev) {
    var btn = ev.currentTarget;
    var url = btn.getAttribute("data-export-url");
    var fmt = btn.getAttribute("data-export-format") || "export";
    if (!url) { return; }

    btn.disabled = true;
    flash("Fetching " + fmt.toUpperCase() + "…", "info");
    try {
      var resp = await fetch(url, {
        headers: { "Accept": "text/plain, application/json" },
        credentials: "same-origin",
      });
      if (!resp.ok) {
        flash("Export failed: HTTP " + resp.status, "error");
        return;
      }
      var text = await resp.text();
      try {
        await copyViaClipboardApi(text);
      } catch (clipErr) {
        // Clipboard API rejected — fall through to the textarea path.
        copyViaTextareaFallback(text);
      }
      flash(fmt.toUpperCase() + " copied to clipboard", "ok");
    } catch (err) {
      console.warn("argus serve: export copy failed:", err);
      flash("Copy failed — see devtools for details", "error");
    } finally {
      btn.disabled = false;
    }
  }

  var copyButtons = menu.querySelectorAll(".export-copy");
  for (var i = 0; i < copyButtons.length; i++) {
    copyButtons[i].addEventListener("click", handleCopy);
  }
})();
