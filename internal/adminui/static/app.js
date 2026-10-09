"use strict";
(function () {
  var csrf = "";
  var accessCursor = "";
  var killed = false;
  function $(id) { return document.getElementById(id); }
  function show(id) {
    ["setup", "login", "dashboard"].forEach(function (x) { $(x).hidden = x !== id; });
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
  function button(label, localID, action) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", function () {
      call("POST", "/api/targets/review", { local_id: localID, action: action }).then(function (r) {
        say(r.ok ? "Saved." : (r.body.error || "Failed."));
        refresh();
      });
    });
    return b;
  }
  function renderReview(items) {
    var ul = $("review");
    ul.textContent = "";
    (items || []).forEach(function (it) {
      var li = document.createElement("li");
      var notes = [];
      if (it.disabled) notes.push("turned off");
      if (it.refused) notes.push("connections refused: " + it.refused);
      else if (it.missing && it.missing.length) notes.push("connections refused until you confirm: " + it.missing.join(", "));
      if (it.reasons && it.reasons.length) notes.push("why: " + it.reasons.join(", "));
      else if (it.grandfathered) notes.push("set up before this version, still working");
      if (it.server_disable_requested_at) notes.push("SeaWise asks to turn this app off; it keeps running until you accept");
      if (it.server_public && !it.public) notes.push("public on SeaWise but private on this machine, so it is not shared until you make it public here");
      li.appendChild(document.createTextNode(it.name + " (" + it.host + ":" + it.port + "): " + notes.join("; ") + " "));
      if (!it.refused && (it.grandfathered || (it.missing && it.missing.length))) li.appendChild(button("Confirm", it.local_id, "confirm"));
      if (it.server_disable_requested_at) {
        li.appendChild(button("Turn off as asked", it.local_id, "accept_server_disable"));
        li.appendChild(button("Keep running", it.local_id, "dismiss_server_disable"));
      }
      if (it.server_public && !it.public) li.appendChild(button("Make public", it.local_id, "make_public"));
      if (it.public) li.appendChild(button("Make private", it.local_id, "make_private"));
      li.appendChild(it.disabled ? button("Turn on", it.local_id, "enable") : button("Turn off", it.local_id, "disable"));
      ul.appendChild(li);
    });
  }
  function findHolds(s) {
    if (!s || typeof s !== "object") return [];
    if (s.agent && Array.isArray(s.agent.Holds)) return s.agent.Holds;
    return findHolds(s.status);
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
    $("tunnels").textContent = killed ?
      "All tunnels are dropped on this machine. Nothing is shared until you restore them." :
      "Tunnels run for the apps listed in the status below.";
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
      $("access-older").disabled = !accessCursor;
    });
  }
  function refresh() {
    call("GET", "/api/auth/status").then(function (r) {
      var s = r.body || {};
      csrf = s.csrf || "";
      if (s.setup_required) { show("setup"); return; }
      if (!s.authenticated) { show("login"); return; }
      show("dashboard");
      call("GET", "/api/status").then(function (r) {
        $("status").textContent = JSON.stringify(r.body, null, 2);
        renderTunnels(r.body);
        renderUpdate(r.body);
      });
      call("GET", "/api/targets/review").then(function (r) { renderReview(r.body.items); });
      loadAccess("");
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    $("setup").addEventListener("submit", function (e) {
      e.preventDefault();
      call("POST", "/api/setup", { code: $("setup-code").value, password: $("setup-password").value }).then(function (r) {
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
