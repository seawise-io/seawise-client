"use strict";
(function () {
  var csrf = "";
  var accessCursor = "";
  var killed = false;
  var view = "";
  function $(id) { return document.getElementById(id); }
  // show switches the view; after a change, focus moves to the new view's
  // heading so keyboard and screen reader users are not left on a hidden
  // element.
  function show(id) {
    ["setup", "closed", "login", "dashboard"].forEach(function (x) { $(x).hidden = x !== id; });
    if (view && view !== id) $(id).querySelector("h2").focus();
    view = id;
  }
  function say(text) { $("message").textContent = text || ""; }
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
  function button(label, localID, action, name) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.setAttribute("aria-label", name ? label + " " + name : label);
    b.dataset.localId = localID;
    b.dataset.action = action;
    b.addEventListener("click", function () {
      call("POST", "/api/targets/review", { local_id: localID, action: action }).then(function (r) {
        say(r.ok ? "Saved." : (r.body.error || "Failed."));
        refresh();
      });
    });
    return b;
  }
  // renderReview rebuilds the list and keeps the keyboard focus on the
  // same button, or on the app's first button when its actions changed.
  function renderReview(items) {
    var ul = $("review");
    var active = document.activeElement;
    var keep = active && ul.contains(active) ? { id: active.dataset.localId, action: active.dataset.action } : null;
    ul.textContent = "";
    (items || []).forEach(function (it) {
      var li = document.createElement("li");
      var where = it.host + ":" + it.port;
      var name = it.name || "App at " + where;
      var notes = [];
      if (it.disabled) notes.push("turned off");
      if (it.refused) notes.push("connections refused: " + it.refused);
      else if (it.reasons && it.reasons.length) notes.push("reaches " + it.reasons.join(", "));
      if (it.server_disable_requested_at) notes.push("SeaWise asks to turn this app off; it keeps running until you accept");
      li.appendChild(document.createTextNode((it.name ? it.name + " (" + where + ")" : name) + ": " + notes.join("; ") + " "));
      if (it.server_disable_requested_at) {
        li.appendChild(button("Turn off as asked", it.local_id, "accept_server_disable", name));
        li.appendChild(button("Keep running", it.local_id, "dismiss_server_disable", name));
      }
      li.appendChild(it.disabled ? button("Turn on", it.local_id, "enable", name) : button("Turn off", it.local_id, "disable", name));
      ul.appendChild(li);
    });
    if (keep) {
      var buttons = Array.prototype.slice.call(ul.querySelectorAll("button"));
      var same = buttons.filter(function (b) { return b.dataset.localId === keep.id; });
      var exact = same.filter(function (b) { return b.dataset.action === keep.action; });
      (exact[0] || same[0] || $("review-heading")).focus();
    }
  }
  function deleteButton(app, name) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = "Delete";
    b.setAttribute("aria-label", "Delete " + name);
    b.dataset.localId = app.local_id;
    b.dataset.action = "delete";
    b.addEventListener("click", function () {
      if (!window.confirm("Delete \u201c" + name + "\u201d? This will stop exposing this app through Seawise.io.")) return;
      call("POST", "/api/apps/delete", { local_id: app.local_id }).then(function (r) {
        say(r.ok ? "Removed " + name + "." : (r.body.error || "Failed to delete app."));
        refresh();
      });
    });
    return b;
  }
  // renderApps rebuilds the app list; focus stays on the same button, or
  // moves to the list heading when the app is gone.
  function renderApps(apps) {
    var ul = $("apps");
    var active = document.activeElement;
    var keep = active && ul.contains(active) ? { id: active.dataset.localId, action: active.dataset.action } : null;
    apps = apps || [];
    ul.textContent = "";
    $("apps-count").textContent = apps.length ? apps.length + " app" + (apps.length !== 1 ? "s" : "") : "No apps added yet.";
    apps.forEach(function (a) {
      var li = document.createElement("li");
      var where = a.host + ":" + a.port;
      var name = a.name || "App at " + where;
      var state = a.status === "disabled" ? "turned off" : (a.subdomain || "syncing");
      li.appendChild(document.createTextNode((a.name ? a.name + " (" + where + ")" : name) + ": " + state + " "));
      if (a.status === "disabled") li.appendChild(button("Turn on", a.local_id, "enable", name));
      li.appendChild(deleteButton(a, name));
      ul.appendChild(li);
    });
    if (keep) {
      var buttons = Array.prototype.slice.call(ul.querySelectorAll("button"));
      var same = buttons.filter(function (b) { return b.dataset.localId === keep.id; });
      var exact = same.filter(function (b) { return b.dataset.action === keep.action; });
      (exact[0] || same[0] || $("apps-heading")).focus();
    }
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
  function renderTunnels(status) {
    killed = findHolds(status).indexOf("kill_switch") >= 0;
    var tunnel = findTunnel(status);
    var text = "Tunnels run for the apps listed in the status below.";
    if (killed) text = "All tunnels are dropped on this machine. Nothing is shared until you restore them.";
    else if (tunnel && tunnel.hold_text) text = "The tunnel is on hold: " + tunnel.hold_text + ". Nothing on this machine was changed.";
    else if (tunnel && !tunnel.up) text = "The tunnel is reconnecting.";
    $("tunnels").textContent = text;
    $("kill-switch").textContent = killed ? "Restore tunnels" : "Drop all tunnels";
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
      if (!r.ok) { say(r.body.error || "Could not load the access log."); return; }
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
  function refresh() {
    call("GET", "/api/auth/status").then(function (r) {
      var s = r.body || {};
      csrf = s.csrf || "";
      if (s.setup_required) { show(s.setup_timed_out ? "closed" : "setup"); return; }
      if (!s.authenticated) { show("login"); return; }
      show("dashboard");
      call("GET", "/api/status").then(function (r) {
        $("status").textContent = JSON.stringify(r.body, null, 2);
        renderTunnels(r.body);
        renderUpdate(r.body);
      });
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
      if (bytes < 10 || bytes > 72) { say("Password must be 10 to 72 bytes. Accented letters and symbols count as 2 to 4."); return; }
      call("POST", "/api/setup", { password: $("setup-password").value }).then(function (r) {
        say(r.ok ? "Password saved." : (r.body.error || "Setup failed."));
        refresh();
      });
    });
    $("login").addEventListener("submit", function (e) {
      e.preventDefault();
      call("POST", "/api/auth/login", { password: $("login-password").value }).then(function (r) {
        say(r.ok ? "" : (r.body.error || "Sign-in failed."));
        refresh();
      });
    });
    $("add-app").addEventListener("submit", function (e) {
      e.preventDefault();
      var name = $("app-name").value.trim();
      var host = $("app-host").value.trim();
      var port = parseInt($("app-port").value, 10);
      if (!name) { say("Please enter an app name."); return; }
      if (!host) { say("Please enter a host (IP, hostname, or container name)."); return; }
      if (!port || port < 1 || port > 65535) { say("Please enter a valid port (1-65535)."); return; }
      call("POST", "/api/apps/add", { name: name, host: host, port: port }).then(function (r) {
        if (!r.ok) { say(r.body.error || "Failed to add app."); return; }
        $("app-name").value = "";
        $("app-host").value = "";
        $("app-port").value = "";
        say("App added: " + name + ".");
        refresh();
      });
    });
    $("kill-switch").addEventListener("click", function () {
      call("POST", "/api/kill-switch", { on: !killed }).then(function (r) {
        say(r.ok ? (r.body.on ? "All tunnels dropped." : "Tunnels restored.") : (r.body.error || "Failed."));
        refresh();
      });
    });
    $("access-newest").addEventListener("click", function () { loadAccess(""); });
    $("access-older").addEventListener("click", function () { if (accessCursor) loadAccess(accessCursor); });
    $("logout").addEventListener("click", function () {
      call("POST", "/api/auth/logout").then(function () { csrf = ""; refresh(); });
    });
    refresh();
  });
})();
