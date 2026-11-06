/* mypki's only script (0.3.0). Loaded as <script src="/static/app.js"> from base.html, which the existing CSP
 * `default-src 'self'; base-uri 'self'; frame-ancestors 'none'` already permits: no unsafe-inline, no CDN, no inline handler
 * anywhere in the markup. If this file fails to load, every page still works — see the three rules below.
 *
 * Progressive enhancement, stated as three rules this file actually follows
 * -------------------------------------------------------------------------
 * 1. Nothing here is required. Copy has a download link and selectable <pre> text; selection has a server that counts what
 *    arrived rather than trusting a counter; revoke confirmation has a server-rendered amber block at the top of /issued that
 *    asks the same question. Each feature below only makes an existing flow nicer.
 * 2. Every enhancement is opt-in by markup: a page that does not carry the data-mypki-* hook gets no behaviour, so a template
 *    cannot accidentally acquire a script it never asked for.
 * 3. When a browser refuses an API, the UI says so in place of the control. A button that silently does nothing is how people
 *    stop trusting a page.
 *
 * Clipboard: what was measured here, and what was not
 * --------------------------------------------------
 * NOT MEASURED: this build box has no browser installed (`which chromium chromium-browser google-chrome firefox` all miss), so
 * the secure-context rule below is implemented from the specification rather than observed on this machine. The user's own run
 * in a real browser is what will confirm it.
 * The rule it implements: `navigator.clipboard` exists only in a secure context, so on mypki's default plain HTTP it is absent
 * or refuses to resolve (MDN / W3C Secure Contexts: `window.isSecureContext` is false for http:// on any host except localhost,
 * and Chromium gates `navigator.clipboard.writeText` on that). Two paths are therefore implemented, in this order:
 *   a) `navigator.clipboard.writeText(...)` when it exists AND the call actually resolves;
 *   b) a selection + `document.execCommand('copy')` fallback, which works over plain HTTP but is deprecated and is not assumed
 *      to work — if it returns false the button says so.
 * Both paths end in an honest line naming Download as the flow that always works.
 */

(function () {
  "use strict";

  // One class on <html>, set only after this script has run. Every CSS rule that depends on JavaScript is written as a
  // `.js-enhanced` descendant, so a blocked or failing script leaves the page exactly as the server rendered it.
  document.documentElement.classList.add("js-enhanced");

  function textOf(node) {
    return node ? node.textContent.trim() : "";
  }

  function note(button, message, failed) {
    var row = button.parentNode;
    if (!row) return;
    var line = row.querySelector(".copy-note");
    if (!line) {
      line = document.createElement("p");
      line.className = "copy-note";
      row.appendChild(line);
    }
    line.textContent = message;
    line.classList.toggle("failed", Boolean(failed));
  }

  // The deprecated path. Kept because mypki's default deployment is plain HTTP, where the modern API is unavailable — dropping
  // this fallback would mean "copy" simply does not exist on the most common setup this project ships on.
  function copyBySelection(pre) {
    var range = document.createRange();
    range.selectNodeContents(pre);
    var selection = window.getSelection();
    if (!selection) return false;
    selection.removeAllRanges();
    selection.addRange(range);
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (error) {
      ok = false;
    }
    selection.removeAllRanges();
    return ok;
  }

  function report(button, ok, pre) {
    if (ok) {
      // 0.4.0: the brief was "only 'Copied to clipboard' in bright green". The 0.3.0 sentence was honest but it was a
      // paragraph, and a paragraph under a button is what a reader skims past; the fact it carried (nothing left this
      // machine) is already stated next to the Download link on every page that offers these buttons. The failure branch
      // below stays verbose on purpose — an honest sentence about *what went wrong* is the one a reader must not skim.
      note(button, "Copied to clipboard", false);
      return;
    }
    // Named rather than generic: the operator needs to know which thing failed and what to do instead. The name comes from
    // the button's own data-mypki-label, rendered by the server next to the block it names — app.js has no idea what a PEM is
    // for, and inventing a label here is how a page ends up describing the wrong artifact.
    var label = button.getAttribute("data-mypki-label") || "That block";
    note(
      button,
      label + " could not be copied by this browser. Clipboard access needs a secure context (https); over plain HTTP use Download.",
      true
    );
  }

  // --------------------------------------------------- copy from a URL instead of from the page (0.7.1)
  //
  // `/ca` no longer renders the certificate on screen: the operator brief put "download root-CA cert" and "copy to clipboard"
  // at the top of the page, which made the in-page PEM block a third copy of bytes this host already serves as an attachment
  // (page-map §1's reason for deleting the home-page CA card applies to a page copying itself too). A button that copies text
  // from the page has nothing to copy from here, so this second wiring fetches the same URL the Download control points at.
  //
  // Two things follow, and both are stated in code rather than hoped for:
  //   * the body is written as `text/plain`, not with its own media type. ClipboardItem's supported-type set is a browser's
  //     decision, not ours, and `application/x-pem-file` is not in it — asking for the type the server sent is how this button
  //     would throw on a browser that otherwise copies fine. The bytes are unchanged either way; only the label differs.
  //   * there is no selection fallback available. `copyBySelection` needs text already on screen, and this page deliberately has
  //     none, so a refusal says so and names Download. That is the same honesty rule as every other button here: a control that
  //     silently does nothing is how an operator believes they have something they do not have.
  function wireCopyUrl(button) {
    var url = button.getAttribute("data-mypki-copy-url");
    if (!url) return;

    button.addEventListener("click", function () {
      fetch(url, { credentials: "same-origin" })
        .then(function (response) {
          if (!response.ok) throw new Error("the copy source answered " + response.status);
          return response.text();
        })
        .then(function (body) {
          var modern = navigator.clipboard && window.isSecureContext !== false;
          if (!modern) throw new Error("no clipboard access in this context");
          var blob = new Blob([body], { type: "text/plain" });
          if (typeof ClipboardItem !== "undefined" && navigator.clipboard.write) {
            return navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]);
          }
          return navigator.clipboard.writeText(body);
        })
        .then(function () {
          note(button, "Copied to clipboard", false);
        })
        .catch(function () {
          var label = button.getAttribute("data-mypki-label") || "That file";
          note(
            button,
            label + " could not be copied by this browser. Nothing was on this page to select, so use Download instead"
              + " (clipboard access needs a secure context: over plain HTTP browsers refuse it).",
            true
          );
        });
    });
  }

  function wireCopy(button) {
    var target = button.getAttribute("data-mypki-copy");
    if (!target) return;
    var pre = document.getElementById(target);
    if (!pre) return; // markup moved; do nothing rather than throw in front of a working page

    button.addEventListener("click", function () {
      var body = textOf(pre);
      var modern = navigator.clipboard && window.isSecureContext !== false;
      if (modern) {
        navigator.clipboard
          .writeText(body)
          .then(function () {
            report(button, true, pre);
          })
          .catch(function () {
            // The API existing is not the API working: on http:// Chromium resolves this promise as a rejection.
            report(button, copyBySelection(pre), pre);
          });
        return;
      }
      report(button, copyBySelection(pre), pre);
    });
  }

  // --------------------------------------------------- /settings dropdowns and checkbox state (0.4.0, page-map §12)
  //
  // Two enhancements on a page that is fully functional without them. The number input is the control that posts — it
  // carries config.py's own min/max, and `validate_candidate` re-checks the value server-side whatever a menu chose —
  // so the dropdown is a shortcut for typing a common value, never a gate. With JavaScript off the menu is hidden by
  // CSS (`.settings-form .field-choice select { display: none }`) and only the authoritative box is shown.

  function wireChoice(field) {
    var select = field.querySelector("select[data-mypki-select-for]");
    var input = field.querySelector("input");
    if (!select || !input) return; // markup moved; leave the server-rendered box alone rather than half-wiring it

    var presets = Array.prototype.slice
      .call(select.querySelectorAll("option"))
      .filter(function (option) {
        return option.value !== "" && /^[0-9]+$/.test(option.value);
      })
      .map(function (option) {
        return option.value;
      });

    function syncFromMenu() {
      if (select.value === "custom") {
        field.classList.add("custom-open");
        return;
      }
      input.value = select.value;
      field.classList.remove("custom-open");
    }

    // Typed into the box, the box wins: a host running 7 SANs must keep showing 7 rather than being snapped to the
    // nearest preset, and an operator who types 45 deserves 45 back rather than the menu's opinion.
    function syncFromBox() {
      var value = input.value.trim();
      if (presets.indexOf(value) !== -1 && !field.classList.contains("custom-open")) {
        select.value = value;
        return;
      }
      select.value = "custom";
      field.classList.add("custom-open");
    }

    // Opening state: the server already marked a field Custom when its live value matched no preset, so a page whose
    // script loads late starts in the same place the server left it.
    if (select.value === "custom") field.classList.add("custom-open");

    select.addEventListener("change", function () {
      if (select.value === "custom") {
        field.classList.add("custom-open");
        input.focus();
        return;
      }
      syncFromMenu();
    });
    input.addEventListener("input", syncFromBox);
  }

  // The on/off word beside a checkbox. The server renders it already correct; this only keeps it correct while the box
  // is being ticked, so the colour never disagrees with the control next to it.
  function wireCheckboxState(field) {
    var box = field.querySelector("input[data-mypki-state-toggle]");
    var state = field.querySelector(".checkbox-state");
    if (!box || !state) return;
    box.addEventListener("change", function () {
      state.textContent = box.checked ? "on" : "off";
      state.classList.toggle("state-on", box.checked);
      state.classList.toggle("state-off", !box.checked);
    });
  }

  // --------------------------------------------------------------------- /issued selection (page-map §5)
  //
  // The counter and the select-all box. Neither is load-bearing: `POST /issued/revoke` reads every `serial_hex` that arrived
  // (`app._selected_serials`) and refuses with 400 when none did, so a browser that runs no script can still revoke exactly the
  // rows an operator ticked by hand.

  function serialBoxes() {
    return Array.prototype.slice.call(document.querySelectorAll('input[type="checkbox"][name="serial_hex"]'));
  }

  function selectedCount() {
    return serialBoxes().filter(function (box) {
      return box.checked;
    }).length;
  }

  function paintRows() {
    serialBoxes().forEach(function (box) {
      var row = box.closest("tr");
      if (row) row.classList.toggle("row-selected", box.checked);
    });
  }

  function updateCounter() {
    var count = document.querySelector("[data-mypki-count]");
    var n = selectedCount();
    // 0.4.0: the server now renders "0 selected", so this line reproduces the same shape at zero instead of replacing
    // it with a different sentence ("nothing selected"). One spelling for one number, in both languages.
    if (count) {
      count.textContent = n + " selected";
    }
    var bars = document.querySelectorAll(".select-bar");
    Array.prototype.forEach.call(bars, function (bar) {
      bar.classList.toggle("has-selection", n > 0);
    });
    var all = document.querySelector("[data-mypki-select-all]");
    if (all) all.checked = serialBoxes().length > 0 && n === serialBoxes().length;
    paintRows();
  }

  function wireSelection() {
    var boxes = serialBoxes();
    if (!boxes.length) return;

    boxes.forEach(function (box) {
      box.addEventListener("change", updateCounter);
    });

    var all = document.querySelector("[data-mypki-select-all]");
    if (all) {
      all.addEventListener("change", function () {
        boxes.forEach(function (box) {
          box.checked = all.checked;
        });
        updateCounter();
      });
    }

    // The counter's initial text ("0 selected") is already true when no box is ticked, which is what lets it be live
    // from the first paint rather than only after an interaction. It is still stashed so a page whose script fails
    // mid-run can be shown to have started from the server's own accurate value.
    var count = document.querySelector("[data-mypki-count]");
    if (count) count.setAttribute("data-mypki-server-text", count.textContent);

    var form = document.querySelector("form.bulk-revoke");
    if (!form) return;

    // The modal is the nicer route to the POST the server-side amber block already represents. It never submits anything
    // itself: Cancel closes it, Confirm adds `confirm=1` and calls requestSubmit on the same form. If any piece of markup is
    // missing, the listener is not installed at all and the browser takes the server path instead.
    var modal = document.getElementById("revoke-modal");
    if (!modal) return;

    function closeModal() {
      modal.setAttribute("hidden", "");
    }

    function openModal() {
      var chosen = serialBoxes().filter(function (box) {
        return box.checked;
      });
      if (!chosen.length) {
        // No selection is not a confirmation question. The server answers the same case with 400 naming serial_hex, so this
        // says the same thing rather than letting an empty POST travel to the server for no reason.
        var bar = document.querySelector(".select-bar");
        if (bar) bar.classList.add("needs-selection");
        return;
      }
      var list = modal.querySelector("[data-mypki-modal-list]");
      if (list) {
        list.textContent = "";
        chosen.forEach(function (box) {
          var row = box.closest("tr");
          var name = row ? textOf(row.querySelector("td:nth-child(5)")) : "";
          var item = document.createElement("li");
          var serial = document.createElement("span");
          serial.className = "mono";
          serial.textContent = box.value;
          item.appendChild(serial);
          var label = document.createElement("span");
          label.textContent = name || "(no name on this row)";
          item.appendChild(label);
          list.appendChild(item);
        });
      }
      var heading = modal.querySelector("[data-mypki-modal-count]");
      if (heading) heading.textContent = "Revoke " + chosen.length + " certificate" + (chosen.length === 1 ? "" : "s") + "?";
      modal.removeAttribute("hidden");
    }

    form.addEventListener("submit", function (event) {
      // A form that already carries confirm=1 is the server-rendered confirmation form on the amber block's own page: it has
      // already been confirmed, and re-asking would be a dialog about a decision the operator just made.
      if (form.querySelector('input[type="hidden"][name="confirm"]')) return;
      event.preventDefault();
      openModal();
    });

    var confirmButton = modal.querySelector("[data-mypki-modal-confirm]");
    if (confirmButton) {
      confirmButton.addEventListener("click", function () {
        var carry = document.createElement("input");
        carry.type = "hidden";
        carry.name = "confirm";
        carry.value = "1";
        form.appendChild(carry);
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          form.submit();
        }
      });
    }

    Array.prototype.forEach.call(modal.querySelectorAll("[data-mypki-modal-cancel]"), function (cancel) {
      cancel.addEventListener("click", closeModal);
    });
  }

  function main() {
    Array.prototype.forEach.call(document.querySelectorAll("button[data-mypki-copy]"), wireCopy);
    Array.prototype.forEach.call(document.querySelectorAll("button[data-mypki-copy-url]"), wireCopyUrl);
    Array.prototype.forEach.call(document.querySelectorAll("[data-mypki-choice]"), wireChoice);
    Array.prototype.forEach.call(document.querySelectorAll("[data-mypki-state-field]"), wireCheckboxState);
    wireSelection();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", main);
  } else {
    main();
  }
})();
