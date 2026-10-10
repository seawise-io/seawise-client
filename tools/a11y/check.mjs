// Accessibility check of the agent admin UI: axe-core (WCAG 2.2 A and AA
// rules), keyboard reachability, visible focus, and reflow at 320 px, in
// every state of the page. Drives Chrome over --remote-debugging-pipe.
//
// usage: node check.mjs <url> <setup-code-file>
// env:   CHROME_BIN (default google-chrome), A11Y_NO_SANDBOX=1 where the
//        browser sandbox is unavailable.

import { spawn } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";

const [url, codeFile] = process.argv.slice(2);
if (!url || !codeFile) {
  console.error("usage: node check.mjs <url> <setup-code-file>");
  process.exit(2);
}
const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const axeVersion = JSON.parse(readFileSync(require.resolve("axe-core/package.json"), "utf8")).version;
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const WIDTHS = [1280, 320];
const PASSWORD = "correct horse battery";
const EXPECTED_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
  "form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const failures = [];
function fail(state, msg) { failures.push(`${state}: ${msg}`); }

// --- DevTools protocol over the pipe -----------------------------------
const profile = mkdtempSync(join(tmpdir(), "a11y-chrome-"));
const args = ["--headless=new", "--remote-debugging-pipe", `--user-data-dir=${profile}`, "--no-first-run",
  "--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--hide-scrollbars", "--mute-audio",
  "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps"];
if (process.env.A11Y_NO_SANDBOX === "1") args.push("--no-sandbox");
const chrome = spawn(process.env.CHROME_BIN || "google-chrome", args, { stdio: ["ignore", "ignore", "inherit", "pipe", "pipe"] });
const toChrome = chrome.stdio[3];
const fromChrome = chrome.stdio[4];
let nextId = 1;
const pending = new Map();
const listeners = [];
let buf = Buffer.alloc(0);
fromChrome.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  let i;
  while ((i = buf.indexOf(0)) >= 0) {
    const msg = JSON.parse(buf.subarray(0, i).toString("utf8"));
    buf = buf.subarray(i + 1);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`${msg.error.message} (${msg.error.code})`)) : resolve(msg.result);
    } else if (msg.method) {
      listeners.forEach((l) => l(msg));
    }
  }
});
let chromeExited = false;
chrome.on("exit", (code, signal) => {
  chromeExited = true;
  for (const { reject } of pending.values()) reject(new Error(`Chrome exited (${code ?? signal})`));
  pending.clear();
});
chrome.on("error", (e) => { chromeExited = true; console.error(`cannot start Chrome: ${e.message}`); });
fromChrome.on("error", () => {});
toChrome.on("error", () => {});
function send(method, params = {}, sessionId) {
  if (chromeExited) return Promise.reject(new Error("Chrome is not running"));
  const id = nextId++;
  const msg = { id, method, params };
  if (sessionId) msg.sessionId = sessionId;
  toChrome.write(JSON.stringify(msg) + "\0");
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}
function once(method, sessionId) {
  return new Promise((resolve) => {
    const l = (m) => {
      if (m.method === method && m.sessionId === sessionId) {
        listeners.splice(listeners.indexOf(l), 1);
        resolve(m.params);
      }
    };
    listeners.push(l);
  });
}

let session;
const cdp = (method, params) => send(method, params, session);
async function evaluate(expression) {
  const r = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`evaluate: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
  return r.result.value;
}
async function waitFor(expression, what) {
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    if (await evaluate(expression)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}`);
}
const KEYS = { Tab: 9, Enter: 13 };
async function press(key, modifiers = 0) {
  const base = { key, code: key, windowsVirtualKeyCode: KEYS[key], nativeVirtualKeyCode: KEYS[key], modifiers };
  await cdp("Input.dispatchKeyEvent", { type: "rawKeyDown", ...base });
  if (key === "Enter") await cdp("Input.dispatchKeyEvent", { type: "char", text: "\r", ...base });
  await cdp("Input.dispatchKeyEvent", { type: "keyUp", ...base });
}
const type = (text) => cdp("Input.insertText", { text });
async function focus(id) { await evaluate(`document.getElementById(${JSON.stringify(id)}).focus()`); }
async function width(w) {
  await cdp("Emulation.setDeviceMetricsOverride", { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
  await evaluate("new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))");
}

// --- Checks --------------------------------------------------------------
async function axe(state) {
  const violations = await evaluate(`axe.run(document, { runOnly: { type: "tag", values: ${JSON.stringify(TAGS)} }, resultTypes: ["violations"] })
    .then(r => r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.map(n => n.target.join(" ") + (n.failureSummary ? " | " + n.failureSummary.replace(/\\s+/g, " ") : "")) })))`);
  for (const v of violations) fail(state, `axe ${v.id} (${v.impact}): ${v.help}\n      ${v.nodes.join("\n      ")}`);
}

// Interactive elements a keyboard user must reach, in DOM order.
const FOCUSABLE = `Array.from(document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]'))
  .filter(e => !e.disabled && e.tabIndex >= 0 && e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden')`;
const DESCRIBE = `(e => e === document.body || !e ? 'body' : (e.id ? '#' + e.id : e.tagName.toLowerCase()) + (e.textContent ? '[' + e.textContent.trim().slice(0, 30) + ']' : ''))`;

async function keyboard(state) {
  const positive = await evaluate(`document.querySelectorAll('[tabindex]:not([tabindex="0"]):not([tabindex="-1"])').length`);
  if (positive) fail(state, `${positive} element(s) with a positive tabindex`);
  const expected = await evaluate(`${FOCUSABLE}.map(${DESCRIBE})`);
  // Start from the top of the page, as after a fresh load.
  await evaluate("window.scrollTo(0, 0)");
  for (const type of ["mousePressed", "mouseReleased"]) {
    await cdp("Input.dispatchMouseEvent", { type, x: 1, y: 1, button: "left", clickCount: 1 });
  }
  await evaluate("document.activeElement && document.activeElement !== document.body && document.activeElement.blur()");
  const seen = [];
  for (let i = 0; i < expected.length; i++) {
    await press("Tab");
    const info = await evaluate(`(() => {
      const e = document.activeElement;
      const name = ${DESCRIBE}(e);
      if (!e || e === document.body) return { name };
      const s = getComputedStyle(e);
      const parse = c => { const m = c.match(/[\\d.]+/g); return m ? m.slice(0, 3).map(Number) : null; };
      const lum = rgb => { const [r, g, b] = rgb.map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
      let bg = null;
      for (let n = e.parentElement; n && !bg; n = n.parentElement) {
        const c = getComputedStyle(n).backgroundColor;
        if (c && !/rgba\\(.*,\\s*0\\)$/.test(c) && c !== 'transparent') bg = parse(c);
      }
      bg = bg || [255, 255, 255];
      const outline = s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) >= 2;
      let ratio = 0;
      if (outline) { const a = lum(parse(s.outlineColor)), b = lum(bg); ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); }
      return { name, visible: e.matches(':focus-visible'), outline, ratio, shadow: s.boxShadow !== 'none',
        style: s.outlineStyle + ' ' + s.outlineWidth + ' ' + s.outlineColor };
    })()`);
    seen.push(info.name);
    if (info.name === "body") break;
    if (!(info.outline && info.ratio >= 3) && !info.shadow) {
      fail(state, `focus on ${info.name} not clearly visible (outline ${info.style}, contrast ${info.ratio.toFixed(2)})`);
    }
  }
  if (JSON.stringify(seen) !== JSON.stringify(expected)) {
    fail(state, `Tab order ${JSON.stringify(seen)}, expected ${JSON.stringify(expected)}`);
  }
}

async function reflow(state) {
  const r = await evaluate(`(() => {
    const w = window.innerWidth;
    const wide = Array.from(document.querySelectorAll('body *'))
      .filter(e => !(e.parentElement && e.parentElement.closest('.scroll')) && (e.getBoundingClientRect().right + window.scrollX > w || (e.scrollWidth > e.clientWidth && !e.classList.contains('scroll') && getComputedStyle(e).overflowX === 'visible')))
      .map(${DESCRIBE}).slice(0, 5);
    return { sw: document.documentElement.scrollWidth, w, wide };
  })()`);
  if (r.sw > r.w) fail(state, `page scrolls horizontally at ${r.w} px (content ${r.sw} px wide: ${r.wide.join(", ")})`);
}

// Names and text built by the script must never show missing data.
async function names(state) {
  const bad = await evaluate(`(() => {
    const out = [];
    for (const e of document.querySelectorAll('main *')) {
      if (!e.getClientRects().length) continue;
      const label = e.getAttribute('aria-label');
      if (label !== null && (label !== label.trim() || /\\b(undefined|null|NaN)\\b/.test(label))) out.push(label);
      for (const n of e.childNodes) {
        if (n.nodeType === 3 && (/\\b(undefined|null|NaN)\\b/.test(n.data) || /^ \\(/.test(n.data))) out.push(n.data);
      }
    }
    return out;
  })()`);
  for (const t of bad) fail(state, `text with missing data: ${JSON.stringify(t)}`);
}

async function checkState(state) {
  await names(state);
  for (const w of WIDTHS) {
    await width(w);
    const s = `${state} @${w}px`;
    if (w === 320) await reflow(s);
    await axe(s);
    await keyboard(s);
  }
  await width(WIDTHS[0]);
  console.log(`checked ${state}`);
}

// After a keyboard action the focus must stay somewhere useful, not fall
// back to the top of the page (WCAG 2.4.3).
async function focusKept(state) {
  const where = await evaluate(`${DESCRIBE}(document.activeElement)`);
  if (where === "body") fail(state, "focus lost to the page body");
  return where;
}

// --- Served page ---------------------------------------------------------
function get(u) {
  return new Promise((resolve, reject) => {
    // Loopback fixture with a self-signed certificate.
    https.get(u, { rejectUnauthorized: false }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ headers: res.headers, body }));
    }).on("error", reject);
  });
}
async function checkServed() {
  const { headers, body } = await get(url);
  if (headers["content-security-policy"] !== EXPECTED_CSP) fail("page", `CSP changed: ${headers["content-security-policy"]}`);
  if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(body)) fail("page", "inline script in the page");
  if (/\sstyle\s*=/i.test(body)) fail("page", "inline style attribute in the page");
  if (/\son[a-z]+\s*=/i.test(body)) fail("page", "inline event handler in the page");
}

// --- States --------------------------------------------------------------
const visible = (id) => `!document.getElementById(${JSON.stringify(id)}).hidden`;

async function main() {
  await checkServed();
  await send("Security.setIgnoreCertificateErrors", { ignore: true });
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  ({ sessionId: session } = await send("Target.attachToTarget", { targetId, flatten: true }));
  await cdp("Page.enable");
  await cdp("Runtime.enable");
  const cspErrors = [];
  listeners.push((m) => {
    if (m.sessionId === session && m.method === "Runtime.consoleAPICalled" && m.params.type === "error") cspErrors.push(JSON.stringify(m.params.args));
    if (m.sessionId === session && m.method === "Runtime.exceptionThrown") cspErrors.push(m.params.exceptionDetails.text);
  });
  await width(WIDTHS[0]);
  const loaded = once("Page.loadEventFired", session);
  await cdp("Page.navigate", { url });
  await loaded;
  await evaluate(axeSource);

  await waitFor(visible("setup"), "the setup form");
  await checkState("setup");

  // Set up with the keyboard only.
  await focus("setup-code");
  await type(readFileSync(codeFile, "utf8").trim());
  await press("Tab");
  await type(PASSWORD);
  await press("Enter");
  await waitFor(`${visible("dashboard")} && document.querySelectorAll('#review li').length > 0 && document.querySelectorAll('#access-rows tr').length > 0`, "the dashboard");
  await focusKept("dashboard, after setup");
  await checkState("dashboard");

  await focus("kill-switch");
  await press("Enter");
  await waitFor(`document.getElementById('kill-switch').textContent === 'Restore tunnels'`, "the kill switch");
  await checkState("dashboard, tunnels dropped");
  await focus("kill-switch");
  await press("Enter");
  await waitFor(`document.getElementById('kill-switch').textContent === 'Drop all tunnels'`, "tunnels restored");

  // Act on an app from the keyboard; focus stays on the list.
  await evaluate(`document.querySelector('#review li button').focus()`);
  await press("Enter");
  await waitFor(`document.getElementById('message').textContent === 'Saved.'`, "the review action");
  await new Promise((r) => setTimeout(r, 300));
  await focusKept("dashboard, after an app action");

  await focus("logout");
  await press("Enter");
  await waitFor(visible("login"), "the sign-in form");
  await focusKept("sign in, after signing out");
  await checkState("sign in");

  await focus("login-password");
  await type(PASSWORD);
  await press("Enter");
  await waitFor(visible("dashboard"), "the dashboard after sign-in");
  await focusKept("dashboard, after signing in");
  await focus("logout");
  await press("Enter");
  await waitFor(visible("login"), "the sign-in form");

  await focus("login-password");
  await type("wrong password");
  await press("Enter");
  await waitFor(`document.getElementById('message').textContent !== ''`, "the sign-in error");
  await checkState("sign in, error shown");

  for (const e of cspErrors) fail("page", `script error: ${e}`);
}

let code = 0;
try {
  await main();
} catch (e) {
  failures.push(`run: ${e.message}`);
} finally {
  if (!chromeExited) {
    const exited = new Promise((r) => chrome.once("exit", r));
    send("Browser.close").catch(() => {});
    const timer = setTimeout(() => chrome.kill("SIGKILL"), 5000);
    await exited;
    clearTimeout(timer);
  }
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch (e) {
    console.error(`could not remove ${profile}: ${e.message}`);
  }
}
if (failures.length) {
  console.error(`axe-core ${axeVersion}: ${failures.length} problem(s)\n  ${failures.join("\n  ")}`);
  code = 1;
} else {
  console.log(`axe-core ${axeVersion}: no violations (${TAGS.join(", ")}), keyboard, focus and reflow checks passed`);
}
process.exit(code);
