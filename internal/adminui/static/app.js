"use strict";
(function () {
  var csrf = "";
  var accessCursor = "";
  var killed = false;
  var view = "";
  var pairTimer = null;
  var pairState = "";
  var tunnel = null;
  var messageTimer = null;
  var pendingDelete = null;
  var account = null;
  function $(id) { return document.getElementById(id); }
  // show switches the view; after a change, focus moves to the new view's
  // heading so keyboard and screen reader users are not left on a hidden
  // element.
  function show(id) {
    ["setup", "closed", "login", "dashboard"].forEach(function (x) { $(x).hidden = x !== id; });
    $("settings").hidden = id !== "dashboard";
    if (id !== "dashboard") closeMenu(false);
    $("status-badge").hidden = id !== "dashboard";
    if (id !== "dashboard") closeDialogs();
    if (view && view !== id) $(id).querySelector("h2").focus();
    view = id;
  }
  function say(text, kind) {
    var m = $("message");
    clearTimeout(messageTimer);
    m.textContent = text || "";
    m.className = "toast" + (kind ? " " + kind : "");
    // On the password forms the error shows under the field; the live region still announces it.
    ["setup", "login"].forEach(function (f) { $(f + "-error").textContent = ""; });
    if (kind === "error" && (view === "setup" || view === "login")) {
      $(view + "-error").textContent = text;
      m.className = "toast visually-hidden";
    }
    if (text) messageTimer = setTimeout(function () { m.textContent = ""; }, kind ? 10000 : 5000);
  }
  function result(r, ok, failed) {
    if (r.ok) say(ok); else say(r.body.error || failed, "error");
  }
  function call(method, path, body) {
    var headers = { "Accept": "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
    return fetch(path, {
      method: method, headers: headers, credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, body: j }; });
    });
  }
  function el(tag, className, text) {
    var e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function openMenu() {
    $("settings-menu").hidden = false;
    $("settings-open").setAttribute("aria-expanded", "true");
    $("password-open").focus();
  }
  function closeMenu(refocus) {
    if ($("settings-menu").hidden) return;
    $("settings-menu").hidden = true;
    $("settings-open").setAttribute("aria-expanded", "false");
    if (refocus) $("settings-open").focus();
  }
  function closeDialogs() {
    ["pair-dialog", "delete-dialog", "disconnect-dialog", "password-dialog"].forEach(function (id) { if ($(id).open) $(id).close(); });
  }
  function button(label, localID, action, name) {
    var b = el("button", "service-enable", label);
    b.type = "button";
    b.setAttribute("aria-label", name ? label + " " + name : label);
    b.dataset.localId = localID;
    b.dataset.action = action;
    b.addEventListener("click", function () {
      call("POST", "/api/targets/review", { local_id: localID, action: action }).then(function (r) {
        result(r, "Saved.", "Failed.");
        refresh();
      });
    });
    return b;
  }
  // keepFocus puts the keyboard focus back on the same button after a list
  // is rebuilt, or on the app's first button, or on the list heading.
  function keepFocus(ul, keep, heading) {
    if (!keep) return;
    var buttons = Array.prototype.slice.call(ul.querySelectorAll("button"));
    var same = buttons.filter(function (b) { return b.dataset.localId === keep.id; });
    var exact = same.filter(function (b) { return b.dataset.action === keep.action; });
    (exact[0] || same[0] || $(heading)).focus();
  }
  function focused(ul) {
    var active = document.activeElement;
    return active && ul.contains(active) ? { id: active.dataset.localId, action: active.dataset.action } : null;
  }
  function appItem(it, attention) {
    var where = it.host + ":" + it.port;
    var li = el("li", "service-item" + (attention ? " attention" : ""));
    var icon = appIcon(it);
    var info = el("div", "service-info");
    info.appendChild(el("p", "service-name", it.name || "App at " + where));
    info.appendChild(el("p", "service-details", where));
    li.appendChild(icon);
    li.appendChild(info);
    return { li: li, info: info, name: it.name || "App at " + where };
  }
  // appIcon is the app's first letter, as in 1.x.
  function appIcon(it) {
    var icon = el("span", "service-icon", (it.name || "?").charAt(0).toUpperCase());
    icon.setAttribute("aria-hidden", "true");
    return icon;
  }
  function renderReview(items) {
    var ul = $("review");
    var keep = focused(ul);
    ul.textContent = "";
    items = items || [];
    $("review-empty").hidden = items.length > 0;
    items.forEach(function (it) {
      var notes = [];
      if (it.removed_from_account) notes.push("Removed from your Seawise.io account; re-enable to publish it again");
      else if (it.disabled) notes.push("Turned off");
      if (it.refused) notes.push("Connections refused: " + it.refused);
      else if (it.reasons && it.reasons.length) notes.push("Reaches " + it.reasons.join(", "));
      if (it.server_disable_requested_at) notes.push("Seawise.io asks to turn this app off; it keeps running until you accept");
      var row = appItem(it, true);
      row.info.appendChild(el("p", "service-notes", notes.join(". ") + "."));
      var actions = el("div", "service-actions");
      if (it.server_disable_requested_at) {
        actions.appendChild(button("Turn off as asked", it.local_id, "accept_server_disable", row.name));
        actions.appendChild(button("Keep running", it.local_id, "dismiss_server_disable", row.name));
      }
      actions.appendChild(it.disabled ? button(it.removed_from_account ? "Re-enable" : "Turn on", it.local_id, "enable", row.name) : button("Turn off", it.local_id, "disable", row.name));
      row.li.appendChild(actions);
      ul.appendChild(row.li);
    });
    keepFocus(ul, keep, "review-heading");
  }
  function deleteButton(app, name) {
    var b = el("button", "service-delete", "×");
    b.type = "button";
    b.setAttribute("aria-label", "Delete " + name);
    b.dataset.localId = app.local_id;
    b.dataset.action = "delete";
    b.addEventListener("click", function () {
      pendingDelete = { id: app.local_id, name: name, from: b };
      $("delete-title").textContent = "Delete “" + name + "”?";
      $("delete-message").textContent = "This will stop exposing this app through Seawise.io.";
      $("delete-dialog").showModal();
      $("delete-cancel").focus();
    });
    return b;
  }
  function confirmDelete() {
    var d = pendingDelete;
    pendingDelete = null;
    $("delete-dialog").close();
    if (!d) return;
    d.from.focus();
    call("POST", "/api/apps/delete", { local_id: d.id }).then(function (r) {
      result(r, "Removed " + d.name + ".", "Failed to delete app.");
      refresh();
    });
  }
  function renderApps(apps) {
    var ul = $("apps");
    var keep = focused(ul);
    apps = apps || [];
    ul.textContent = "";
    $("apps-count").textContent = apps.length + " app" + (apps.length !== 1 ? "s" : "");
    $("apps-empty").hidden = apps.length > 0;
    apps.forEach(function (a) {
      var row = appItem(a, false);
      var badge;
      if (a.removed_from_account) badge = el("span", "service-subdomain service-badge-local", "Removed from account");
      else if (a.status === "disabled") badge = el("span", "service-subdomain service-badge-local", "Turned off");
      else if (a.subdomain) badge = el("span", "service-subdomain", a.subdomain);
      else badge = el("span", "service-subdomain service-badge-local", "Syncing…");
      row.li.appendChild(badge);
      if (a.removed_from_account) row.li.appendChild(button("Re-enable", a.local_id, "enable", row.name));
      else if (a.status === "disabled") row.li.appendChild(button("Turn on", a.local_id, "enable", row.name));
      row.li.appendChild(deleteButton(a, row.name));
      ul.appendChild(row.li);
    });
    keepFocus(ul, keep, "apps-heading");
  }
  function findHolds(s) {
    if (!s || typeof s !== "object") return [];
    if (s.agent && Array.isArray(s.agent.Holds)) return s.agent.Holds;
    return findHolds(s.status);
  }
  function findTunnel(s) {
    if (!s || typeof s !== "object") return null;
    if (s.agent && s.agent.Tunnel && typeof s.agent.Tunnel === "object") return s.agent.Tunnel;
    return findTunnel(s.status);
  }
  function findUpdates(s) {
    if (!s || typeof s !== "object") return null;
    if (s.updates && typeof s.updates === "object") return s.updates;
    return findUpdates(s.status);
  }
  function renderUpdate(status) {
    var u = findUpdates(status) || {};
    var text = "";
    if (u.available && u.available.version) {
      text = "Version " + u.available.version + " is available on the " + u.channel + " channel. " +
        "To update, pull " + u.available.ref + " (the signed image digest) and recreate the container. " +
        "This client does not update itself.";
    } else if (u.state === "expired") {
      text = "Update information could not be verified because it has expired. Tunnels are not affected.";
    }
    $("update").textContent = text;
    $("update").hidden = !text;
  }
  function findClock(s) {
    if (!s || typeof s !== "object") return null;
    if (s.clock && typeof s.clock === "object") return s.clock;
    return findClock(s.status);
  }
  function renderClock(status) {
    var c = findClock(status) || {};
    var text = c.state === "wrong" ? (c.text || "The clock on this machine is wrong.") : "";
    $("clock").textContent = text;
    $("clock").hidden = !text;
  }
  function renderAccount(status) {
    var b = status && typeof status === "object" ? (status.version ? status : status.status || {}) : {};
    account = b.account && typeof b.account === "object" ? b.account : null;
    $("version-footer").textContent = typeof b.version === "string" ? b.version : "";
    $("server-id-footer").textContent = account && account.server_id ? account.server_id : "";
    if (pairState === "paired") $("pair-state").textContent = pairedMeta();
  }
  // pairedMeta is the line under the server name once paired: the account email as in 1.x.
  function pairedMeta() {
    return account && account.user_email ? account.user_email : "Connected to Seawise.io.";
  }
  function renderTunnels(status) {
    killed = findHolds(status).indexOf("kill_switch") >= 0;
    tunnel = findTunnel(status);
    var text = "Tunnels run for the apps listed below.";
    if (killed) text = "All tunnels are dropped on this machine. Nothing is shared until you restore them.";
    else if (tunnel && tunnel.hold_text) text = "The tunnel is on hold: " + tunnel.hold_text + ". Nothing on this machine was changed.";
    else if (tunnel && !tunnel.up) text = "The tunnel is reconnecting.";
    $("tunnels").textContent = text;
    var ks = $("kill-switch");
    ks.textContent = killed ? "Restore tunnels" : "Drop all tunnels";
    ks.className = "btn btn-small " + (killed ? "btn-primary" : "btn-danger");
    renderBadge();
  }
  // renderBadge sums up pairing and tunnel state in the header.
  function renderBadge() {
    var kind = "offline";
    var text = "Not connected";
    if (pairState === "paired") {
      if (killed) text = "Tunnels dropped";
      else if (tunnel && (tunnel.hold_text || !tunnel.up)) { kind = "pending"; text = tunnel.hold_text ? "On hold" : "Reconnecting"; }
      else { kind = "online"; text = "Connected"; }
    } else if (pairState === "pending") { kind = "pending"; text = "Waiting for approval"; }
    else if (pairState === "reconnect") text = "Needs reconnecting";
    $("status-badge").className = "status-badge " + kind;
    $("status-text").textContent = text;
  }
  function cell(tr, text) {
    var td = document.createElement("td");
    td.textContent = text;
    tr.appendChild(td);
  }
  function loadAccess(cursor) {
    var q = "?limit=50" + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "");
    call("GET", "/api/access-log" + q).then(function (r) {
      var tbody = $("access-rows");
      tbody.textContent = "";
      if (!r.ok) { say(r.body.error || "Could not load the access log.", "error"); return; }
      (r.body.entries || []).forEach(function (e) {
        var tr = document.createElement("tr");
        cell(tr, e.time);
        cell(tr, e.name ? e.name + " (" + e.app + ")" : e.app);
        cell(tr, e.peer);
        cell(tr, e.target);
        cell(tr, String(e.bytes_in));
        cell(tr, String(e.bytes_out));
        cell(tr, e.duration_ms + " ms");
        cell(tr, e.result);
        tbody.appendChild(tr);
      });
      accessCursor = r.body.next || "";
      var older = $("access-older");
      if (!accessCursor && document.activeElement === older) $("access-newest").focus();
      older.disabled = !accessCursor;
    });
  }
  function renderPair(s) {
    s = s || {};
    var paired = s.state === "paired";
    var pending = s.state === "pending";
    var reconnect = s.state === "reconnect";
    var name = s.server_name || "";
    var heading = paired ? (name || "Connected") : pending ? "Pairing in progress" : reconnect ? (name || "Not connected") : "Not connected";
    var text;
    if (paired) text = pairedMeta();
    else if (reconnect) text = "This server needs to be connected again. Pair it, then choose Reconnect an existing server when you approve the code on Seawise.io.";
    else if (pending) text = "Waiting for approval on Seawise.io." + (s.error ? " " + s.error : "");
    else if (s.error) text = s.error;
    else text = "This client is not paired. Pair it to share its apps through Seawise.io.";
    $("pair-heading").textContent = heading;
    $("pair-state").textContent = text;
    $("server-icon").className = "card-icon " + (paired ? "green" : "orange");
    var open = $("pair-open");
    open.hidden = paired;
    open.textContent = pending ? "Show code" : reconnect ? "Reconnect" : "Connect";
    $("disconnect-open").hidden = !(paired || reconnect);
    $("pair-form").hidden = paired || pending;
    $("pair-error").textContent = !paired && !pending && s.error ? s.error : "";
    $("pair-pending").hidden = !pending;
    if (pending) {
      $("pair-code").textContent = s.code || "";
      var link = $("pair-link");
      var url = typeof s.approve_url === "string" && /^https?:\/\//.test(s.approve_url) ? s.approve_url : "";
      link.hidden = !url;
      link.href = url || "#";
      $("pair-key").textContent = s.key_fingerprint ? "Device key (for support): " + s.key_fingerprint : "";
    }
    if (pending && !pairTimer) pairTimer = setInterval(loadPair, 3000);
    if (!pending && pairTimer) { clearInterval(pairTimer); pairTimer = null; }
    var was = pairState;
    pairState = s.state || "";
    renderBadge();
    if (was === "pending" && !pending && $("pair-dialog").open) {
      $("pair-dialog").close();
      open.hidden ? $("pair-heading").focus() : open.focus();
    }
    if (was === "pending" && paired) { say("Connected to Seawise.io."); refresh(); }
  }
  function loadPair() {
    return call("GET", "/api/pair/status").then(function (r) {
      if (r.ok) renderPair(r.body);
      else renderPair({ state: "unavailable", error: r.body.error || "Pairing status is unavailable." });
    });
  }
  function refresh() {
    call("GET", "/api/auth/status").then(function (r) {
      var s = r.body || {};
      csrf = s.csrf || "";
      if (s.setup_required) { show(s.setup_timed_out ? "closed" : "setup"); return; }
      if (!s.authenticated) { show("login"); return; }
      show("dashboard");
      call("GET", "/api/status").then(function (r) {
        $("status").textContent = JSON.stringify(r.body, null, 2);
        renderAccount(r.body);
        renderTunnels(r.body);
        renderUpdate(r.body);
        renderClock(r.body);
      });
      loadPair();
      call("GET", "/api/apps").then(function (r) { if (r.ok) renderApps(r.body.apps); });
      call("GET", "/api/targets/review").then(function (r) { renderReview(r.body.items); });
      loadAccess("");
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    $("setup").addEventListener("submit", function (e) {
      e.preventDefault();
      // The server limit is in bytes; accented letters and symbols take 2 to 4.
      var bytes = new TextEncoder().encode($("setup-password").value).length;
      if (bytes < 10 || bytes > 72) { say("Password must be 10 to 72 bytes. Accented letters and symbols count as 2 to 4.", "error"); return; }
      call("POST", "/api/setup", { password: $("setup-password").value }).then(function (r) {
        result(r, "Password saved.", "Setup failed.");
        refresh();
      });
    });
    $("login").addEventListener("submit", function (e) {
      e.preventDefault();
      call("POST", "/api/auth/login", { password: $("login-password").value }).then(function (r) {
        if (r.ok) say(""); else say(r.body.error || "Sign-in failed.", "error");
        refresh();
      });
    });
    $("add-app").addEventListener("submit", function (e) {
      e.preventDefault();
      var name = $("app-name").value.trim();
      var host = $("app-host").value.trim();
      var port = parseInt($("app-port").value, 10);
      if (!name) { say("Please enter an app name.", "error"); return; }
      if (!host) { say("Please enter a host (IP, hostname, or container name).", "error"); return; }
      if (!port || port < 1 || port > 65535) { say("Please enter a valid port (1-65535).", "error"); return; }
      call("POST", "/api/apps/add", { name: name, host: host, port: port }).then(function (r) {
        if (!r.ok) { say(r.body.error || "Failed to add app.", "error"); return; }
        $("app-name").value = "";
        $("app-host").value = "";
        $("app-port").value = "";
        say("App added: " + name + ".");
        refresh();
      });
    });
    $("pair-open").addEventListener("click", function () {
      $("pair-dialog").showModal();
      (pairState === "pending" ? $("pair-code") : $("pair-name")).focus();
    });
    $("pair-close").addEventListener("click", function () { $("pair-dialog").close(); });
    $("pair-dialog").addEventListener("close", function () {
      if (view === "dashboard" && !$("pair-open").hidden) $("pair-open").focus();
    });
    $("pair-form").addEventListener("submit", function (e) {
      e.preventDefault();
      say("");
      call("POST", "/api/pair/start", { server_name: $("pair-name").value }).then(function (r) {
        if (!r.ok) { $("pair-error").textContent = r.body.error || "Could not start pairing."; return; }
        renderPair(r.body);
        $("pair-code").focus();
      });
    });
    $("pair-cancel").addEventListener("click", function () {
      call("POST", "/api/pair/cancel").then(function (r) {
        if (r.ok) renderPair(r.body); else $("pair-error").textContent = r.body.error || "Could not cancel pairing.";
        $("pair-name").focus();
      });
    });
    $("disconnect-open").addEventListener("click", function () {
      $("disconnect-dialog").showModal();
      $("disconnect-cancel").focus();
    });
    $("disconnect-cancel").addEventListener("click", function () { $("disconnect-dialog").close(); });
    $("disconnect-dialog").addEventListener("close", function () {
      if (view === "dashboard" && !$("disconnect-open").hidden) $("disconnect-open").focus();
    });
    $("disconnect-confirm").addEventListener("click", function () {
      $("disconnect-confirm").disabled = true;
      call("POST", "/api/disconnect").then(function (r) {
        $("disconnect-confirm").disabled = false;
        $("disconnect-dialog").close();
        if (!r.ok) say(r.body.error || "Failed to disconnect.", "error");
        else if (r.body.told) say("Disconnected from Seawise.io.");
        else say("Disconnected on this machine, but Seawise.io could not be reached. Remove this server on Seawise.io.", "warning");
        refresh();
        loadPair().then(function () { $("pair-open").hidden ? $("pair-heading").focus() : $("pair-open").focus(); });
      });
    });
    $("delete-cancel").addEventListener("click", function () { $("delete-dialog").close(); });
    $("delete-confirm").addEventListener("click", confirmDelete);
    $("delete-dialog").addEventListener("close", function () {
      if (pendingDelete) { pendingDelete.from.focus(); pendingDelete = null; }
    });
    $("kill-switch").addEventListener("click", function () {
      call("POST", "/api/kill-switch", { on: !killed }).then(function (r) {
        if (r.ok) say(r.body.on ? "All tunnels dropped." : "Tunnels restored."); else say(r.body.error || "Failed.", "error");
        refresh();
      });
    });
    $("access-newest").addEventListener("click", function () { loadAccess(""); });
    $("access-older").addEventListener("click", function () { if (accessCursor) loadAccess(accessCursor); });
    $("settings-open").addEventListener("click", function (e) {
      e.stopPropagation();
      if ($("settings-menu").hidden) openMenu(); else closeMenu(true);
    });
    $("settings-menu").addEventListener("keydown", function (e) {
      if (e.key === "Escape") { e.preventDefault(); closeMenu(true); }
    });
    document.addEventListener("click", function (e) {
      if (!$("settings").contains(e.target)) closeMenu(false);
    });
    $("settings").addEventListener("focusout", function (e) {
      if (e.relatedTarget && !$("settings").contains(e.relatedTarget)) closeMenu(false);
    });
    $("password-open").addEventListener("click", function () {
      closeMenu(false);
      $("password-form").reset();
      $("password-error").textContent = "";
      $("password-dialog").showModal();
      $("password-current").focus();
    });
    $("password-cancel").addEventListener("click", function () { $("password-dialog").close(); });
    $("password-dialog").addEventListener("close", function () {
      if (view === "dashboard") $("settings-open").focus();
    });
    $("password-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var next = $("password-new").value;
      var bytes = new TextEncoder().encode(next).length;
      if (bytes < 10 || bytes > 72) { $("password-error").textContent = "The new password must be 10 to 72 bytes. Accented letters and symbols count as 2 to 4."; return; }
      if (next !== $("password-confirm").value) { $("password-error").textContent = "The new passwords do not match."; return; }
      call("POST", "/api/auth/password", { current_password: $("password-current").value, password: next }).then(function (r) {
        if (!r.ok) { $("password-error").textContent = r.body.error || "Could not change the password."; return; }
        csrf = r.body.csrf || csrf;
        $("password-dialog").close();
        say("Password changed.");
      });
    });
    $("logout").addEventListener("click", function () {
      closeMenu(false);
      call("POST", "/api/auth/logout").then(function () { csrf = ""; refresh(); });
    });
    refresh();
  });
})();
