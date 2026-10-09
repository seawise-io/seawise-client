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
  function renderReview(items) {
    var ul = $("review");
    ul.textContent = "";
    (items || []).forEach(function (it) {
      var li = document.createElement("li");
      var text = it.name + " (" + it.host + ":" + it.port + ")";
      if (it.required && it.required.length) text += ": needs " + it.required.join(", ");
      if (it.refused) text += ": blocked, " + it.refused;
      li.appendChild(document.createTextNode(text + " "));
      ["confirm", "disable"].forEach(function (action) {
        if (action === "confirm" && it.refused) return;
        var b = document.createElement("button");
        b.type = "button";
        b.textContent = action === "confirm" ? "Confirm" : "Turn off";
        b.addEventListener("click", function () {
          call("POST", "/api/targets/review", { local_id: it.local_id, action: action }).then(function (r) {
            say(r.ok ? "Saved." : (r.body.error || "Failed."));
            refresh();
          });
        });
        li.appendChild(b);
      });
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
