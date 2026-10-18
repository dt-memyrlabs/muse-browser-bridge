/* Panel window fix (2026-10-18): the worker's "state" answer used the last
 * focused window's active tab, so with the Muse chat window open, the panel
 * in a work window described the chat window (muse.ai, "nothing to share").
 * The panel now passes its own window id and the worker answers for it.
 *
 *   node test_panel_window.js     exit 0 = all passed
 */
"use strict";
const { install } = require("./fake_chrome");

let failures = 0, passes = 0;
function check(name, cond, detail) {
  if (cond) { passes++; console.log("PASS " + name); }
  else { failures++; console.log("FAIL " + name + (detail !== undefined ? "  -- " + JSON.stringify(detail).slice(0, 400) : "")); }
}
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const F = install({ fakeSocket: true });
  let hello;
  for (let i = 0; i < 200 && !hello; i++) { await tick(10); hello = F.sent.find((m) => m.t === "hello"); }
  F.FakeWS.last.deliver({ t: "welcome", ok: true });
  await tick(10);

  // Window 1 = the Muse chat window (last focused). Window 2 = work window.
  const chatTab = F.mkTab("https://muse.ai/chat", { windowId: 1, active: true });
  const workTab = F.mkTab("https://dashboard.stripe.com/acct/dashboard", { windowId: 2, active: true });
  F.setLastFocusedWindow(1);

  const stWork = await F.panel("state", { windowId: 2 });
  check("panel in work window describes the work tab",
    stWork.ok && stWork.current && stWork.current.tabId === workTab.id && stWork.current.host === "dashboard.stripe.com",
    stWork.current);
  check("work tab is shareable in its own panel",
    stWork.current && stWork.current.shareable === true, stWork.current);

  const stChat = await F.panel("state", { windowId: 1 });
  check("panel in chat window describes the muse.ai tab",
    stChat.ok && stChat.current && stChat.current.tabId === chatTab.id && stChat.current.host === "muse.ai",
    stChat.current);

  F.setLastFocusedWindow(2);
  const stWork2 = await F.panel("state", { windowId: 2 });
  check("window id wins when the work window is also last focused",
    stWork2.current && stWork2.current.tabId === workTab.id, stWork2.current);
  const stChat2 = await F.panel("state", { windowId: 1 });
  check("window id wins over last focused for the chat window too",
    stChat2.current && stChat2.current.tabId === chatTab.id, stChat2.current);

  const stFallback = await F.panel("state");
  check("no window id keeps the old last-focused behaviour (fallback)",
    stFallback.current && stFallback.current.tabId === workTab.id, stFallback.current);

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
