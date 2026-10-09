"use strict";
(function () {
  var csrf = "";
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
      else if (it.grandfathered) notes.push("set up before this version, still working");
      if (it.server_disable_requested_at) notes.push("SeaWise asks to turn this app off; it keeps running until you accept");
      li.appendChild(document.createTextNode(it.name + " (" + it.host + ":" + it.port + "): " + notes.join("; ") + " "));
      if (!it.refused && (it.grandfathered || (it.missing && it.missing.length))) li.appendChild(button("Confirm", it.local_id, "confirm"));
      if (it.server_disable_requested_at) {
        li.appendChild(button("Turn off as asked", it.local_id, "accept_server_disable"));
        li.appendChild(button("Keep running", it.local_id, "dismiss_server_disable"));
      }
      li.appendChild(it.disabled ? button("Turn on", it.local_id, "enable") : button("Turn off", it.local_id, "disable"));
      ul.appendChild(li);
    });
  }
  function refresh() {
    call("GET", "/api/auth/status").then(function (r) {
      var s = r.body || {};
      csrf = s.csrf || "";
      if (s.setup_required) { show("setup"); return; }
      if (!s.authenticated) { show("login"); return; }
      show("dashboard");
      call("GET", "/api/status").then(function (r) { $("status").textContent = JSON.stringify(r.body, null, 2); });
      call("GET", "/api/targets/review").then(function (r) { renderReview(r.body.items); });
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
    $("logout").addEventListener("click", function () {
      call("POST", "/api/auth/logout").then(function () { csrf = ""; refresh(); });
    });
    refresh();
  });
})();
