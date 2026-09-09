// Browser proof for desktop UI/IPC contracts. Native sockets are tested by Rust.
import { chromium } from "playwright";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";

const server = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "18440", "--strictPort"], { stdio: ["ignore", "pipe", "pipe"] });
const browser = await chromium.launch({ headless: true, executablePath: process.env.HOLDFAST_CHROMIUM || undefined, args: ["--no-sandbox"] });
try {
  for (let tries = 0; ; tries++) {
    try { await fetch("http://127.0.0.1:18440"); break; }
    catch (error) { if (tries === 100) throw error; await new Promise(r => setTimeout(r, 50)); }
  }
  const page = await browser.newPage({ viewport: { width: 1100, height: 720 } });
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.addInitScript(() => {
    let sequence = 0;
    const callbacks = new Map(); const listeners = new Map();
    window.hfCalls = []; window.hfFail = false; window.hfSocks = null;
    window.hfEmit = (event, payload) => callbacks.get(listeners.get(event))({ payload });
    window.__TAURI_INTERNALS__ = {
      transformCallback: callback => { callbacks.set(++sequence, callback); return sequence; },
      unregisterCallback: id => callbacks.delete(id),
      invoke: async (cmd, args) => {
        window.hfCalls.push({ cmd, args });
        if (cmd === "plugin:event|listen") { listeners.set(args.event, args.handler); return 1; }
        if (cmd === "bootstrap") return { servers: [{ key: "test", url: "https://example.test", displayName: "Example server", username: "alice", usesSshKey: true, rememberLogin: false, shells: [{ shell: "shell", name: "test shell" }], status: "connected", fileUploads: false }] };
        if (cmd === "attach_shell") {
          callbacks.get(args.output.id)({ index: 0, message: { data: btoa("ready"), attachmentId: 1, sequence: 0, requiresAck: false } });
          return { oldestHistoryLineId: 0, newestHistoryLineId: 0 };
        }
        if (cmd === "set_remember_login" && window.hfFail) throw new Error("simulated write failure");
        if (cmd === "start_socks") window.hfSocks = `127.0.0.1:${args.port}`;
        if (cmd === "stop_socks") window.hfSocks = null;
        if (["socks_status", "start_socks", "stop_socks"].includes(cmd)) return { supported: true, address: window.hfSocks };
        return 1;
      },
    };
  });
  await page.goto("http://127.0.0.1:18440");
  await page.waitForFunction(() => !document.querySelector("#attachment-action").disabled);
  assert.equal(await page.locator("#upload").isDisabled(), true);
  await page.evaluate(() => window.hfEmit("server-capabilities", { server: "test", fileUploads: true }));
  await page.waitForFunction(() => !document.querySelector("#upload").disabled);
  assert.equal(await page.getByRole("button", { name: "Login", exact: true }).count(), 0);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  const remember = page.locator("#login-settings-remember");
  assert.equal(await remember.isChecked(), false);
  await page.locator("#socks-port").fill("1088");
  await page.getByRole("button", { name: "Start SOCKS", exact: true }).click();
  await page.waitForFunction(() => document.querySelector("#socks-status").textContent.includes("127.0.0.1:1088"));
  assert.equal(await page.locator("#socks-port").isDisabled(), true);
  await page.getByRole("button", { name: "Stop SOCKS", exact: true }).click();
  await page.waitForFunction(() => document.querySelector("#socks-status").textContent === "Stopped");
  await remember.check(); await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.waitForFunction(() => !document.querySelector("#login-settings-dialog").open);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  assert.equal(await remember.isChecked(), true);
  await remember.uncheck(); await page.evaluate(() => { window.hfFail = true; });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.waitForFunction(() => document.querySelector("#connection-error").textContent.includes("simulated write failure"));
  assert.equal(await page.locator("#login-settings-dialog").evaluate(e => e.open), true);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  assert.equal(await remember.isChecked(), true);
  await page.screenshot({ path: process.env.HOLDFAST_UI_SCREENSHOT || "/tmp/holdfast-connect.png" });
  assert.deepEqual(errors, []);
  console.log("PASS: Connect preference, failed save, SOCKS start/stop, live upload capability");
} finally {
  await browser.close();
  server.kill();
  if (server.exitCode === null) await once(server, "exit");
}
