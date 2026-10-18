/* Tab groups at browser startup (DESIGN-GROUPS.md, the B040 extension):
 * ownership of stored tabs is dropped as always, then tabs still sitting
 * in a session's named group are re-adopted by that session — with the
 * site check re-run. A group tab whose site is no longer permitted is
 * not re-adopted and is taken out of the group; a controlled tab that is
 * in no group is dropped, exactly as before. Kept in its own file
 * because the fake-chrome harness supports one install per process.
 *
 *   node test_extension_groups_startup.js     exit 0 = all passed
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
  const { tabs, sent, mkTab, panel, FakeWS } = F;
  let hello;
  for (let i = 0; i < 200 && !hello; i++) { await tick(10); hello = sent.find((m) => m.t === "hello"); }
  FakeWS.last.deliver({ t: "welcome", ok: true });
  await tick(10);

  async function owner(tabId) {
    const all = await F.sw(`local.get("sessions", {})`);
    for (const v of Object.values(all)) if (v.tabs && Object.prototype.hasOwnProperty.call(v.tabs, String(tabId))) return v.chatName;
    return null;
  }
  async function pair(tabId, sid, name, attach) {
    await panel("share", { tabId });
    const req = sent.filter((m) => m.t === "pair_request").pop();
    FakeWS.last.deliver({ t: "pair_code", reqId: req.reqId, code: "ABCD2345", expiresIn: 300 });
    await tick(10);
    FakeWS.last.deliver({ t: "paired", reqId: req.reqId, sessionId: sid, chatName: name, ...(attach ? { attach: true } : {}) });
    await tick(40);
  }

  const s1 = mkTab("https://shop.example.com/admin", { active: true });
  await pair(s1.id, "sess-A", "Chat A");
  const s2 = mkTab("https://crm.example.com/", { active: true });
  await pair(s2.id, "sess-A", "Chat A", true);
  const s3 = mkTab("https://mail.example.org/", { active: true });
  await pair(s3.id, "sess-B", "Chat B");
  // an app-window tab: grouping is refused there, so it is owned but
  // ungrouped (the fallback in DESIGN-GROUPS.md)
  F.windowTypes[7] = "app";
  const s4 = mkTab("https://pwa.example.com/app", { windowId: 7 });
  await pair(s4.id, "sess-A", "Chat A", true);
  check("setup: the app-window tab is owned but in no group",
        (await owner(s4.id)) === "Chat A" && tabs.get(s4.id).groupId === -1,
        { owner: await owner(s4.id), tab: tabs.get(s4.id) });
  // revoke crm's site grant while its tab stays owned and grouped: at
  // startup the site check must refuse to bring that tab back
  await panel("revoke_site", { sessionId: "sess-A", host: "crm.example.com" });
  await tick(20);
  check("setup: both chats hold their grouped tabs before the restart",
        (await owner(s1.id)) === "Chat A" && (await owner(s3.id)) === "Chat B");

  await Promise.all(F.E.startup.fire());
  await tick(60);
  check("startup re-adopts a tab still in the session's group (site still permitted)",
        (await owner(s1.id)) === "Chat A" && F.pillOf[s1.id] === "Chat A", await owner(s1.id));
  check("startup re-adopts the other chat's group tab too",
        (await owner(s3.id)) === "Chat B");
  check("startup does NOT re-adopt a group tab whose site is no longer permitted...",
        !(await owner(s2.id)));
  check("...and that tab is taken out of the group",
        tabs.get(s2.id).groupId === -1);
  check("startup drops a controlled tab that is in no group (old B040 rule)",
        !(await owner(s4.id)));

  console.log(`\n${passes}/${passes + failures} passed`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error("CRASH", e); process.exit(2); });
