/* Tab groups (DESIGN-GROUPS.md): group membership is the control set.
 * Pair/attach move the tab into the session's "Muse · <chat name>" group;
 * Daniel dragging a tab into the group adopts it; dragging it out releases
 * it; at browser startup, tabs still in a named group are re-adopted with
 * their site checks re-run; tabs_create lands in the creator's group.
 *
 *   node test_extension_groups.js     exit 0 = all passed
 */
"use strict";
const { install } = require("./fake_chrome");

let failures = 0, passes = 0;
function check(name, cond, detail) {
  if (cond) { passes++; console.log("PASS " + name); }
  else { failures++; console.log("FAIL " + name + (detail !== undefined ? "  -- " + JSON.stringify(detail).slice(0, 400) : "")); }
}
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

async function boot() {
  const F = install({ fakeSocket: true });
  let hello;
  for (let i = 0; i < 200 && !hello; i++) { await tick(10); hello = F.sent.find((m) => m.t === "hello"); }
  F.FakeWS.last.deliver({ t: "welcome", ok: true });
  await tick(10);
  return F;
}
function helpers(F) {
  const { sent, panel, FakeWS } = F;
  async function owner(tabId) {
    const all = await F.sw(`local.get("sessions", {})`);
    for (const [sid, v] of Object.entries(all)) if (v.tabs && Object.prototype.hasOwnProperty.call(v.tabs, String(tabId))) return { sid, chat: v.chatName };
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
  let cmdSeq = 0;
  async function cmd(sid, action, args) {
    const id = "g" + (++cmdSeq);
    FakeWS.last.deliver({ t: "cmd", id, sessionId: sid, action, args: args || {}, ttlMs: 120000 });
    for (let i = 0; i < 400; i++) { const r = sent.find((m) => m.t === "result" && m.id === id); if (r) return r; await tick(5); }
    return { ok: false, error: "TEST_TIMEOUT" };
  }
  const groupOf = (tabId) => F.tabs.get(tabId).groupId;
  const groupsTitled = (title) => [...F.groups.values()].filter((g) => g.title === title);
  return { owner, pair, cmd, groupOf, groupsTitled };
}

(async () => {
  /* ------------------------------------------------ main flow */
  const F = await boot();
  const { tabs, mkTab, setGroup, mkGroup, moveToWindow } = F;
  const H = helpers(F);

  const t1 = mkTab("https://shop.example.com/admin", { active: true });
  await H.pair(t1.id, "sess-A", "Chat A");
  const gA = H.groupsTitled("Muse · Chat A");
  check("pair moves the tab into a group titled 'Muse · Chat A'",
        gA.length === 1 && H.groupOf(t1.id) === gA[0].id && gA[0].windowId === 1, { groups: gA, tab: tabs.get(t1.id) });
  const sessA = (await F.sw(`local.get("sessions", {})`))["sess-A"];
  check("...and the session records the group for that window",
        sessA && sessA.groups && Number(sessA.groups["1"]) === gA[0].id, sessA);

  // tabs_create lands in the creating session's group
  let r = await H.cmd("sess-A", "tabs_create", {});
  const created = r.ok && tabs.get(r.data.tabId);
  check("tabs_create lands the new tab in the session's group",
        !!created && created.groupId === gA[0].id && (await H.owner(created.id) || {}).chat === "Chat A", r);

  // attach-on-redeem: the second tab joins the SAME group
  const t2 = mkTab("https://crm.example.com/", { active: true });
  await H.pair(t2.id, "sess-A", "Chat A", true);
  check("attach moves the second tab into the same group",
        H.groupOf(t2.id) === gA[0].id && H.groupsTitled("Muse · Chat A").length === 1);

  // a tab in a second window gets the session's own group in that window
  const t3 = mkTab("https://docs.example.org/", { windowId: 2 });
  await H.pair(t3.id, "sess-A", "Chat A", true);
  const gA2 = H.groupsTitled("Muse · Chat A").find((g) => g.windowId === 2);
  check("a second window gets its own group for the same session",
        !!gA2 && gA2.id !== gA[0].id && H.groupOf(t3.id) === gA2.id, H.groupsTitled("Muse · Chat A"));

  // Chat B pairs its own tab: its own group, its own title
  const u1 = mkTab("https://mail.example.org/", { active: true });
  await H.pair(u1.id, "sess-B", "Chat B");
  const gB = H.groupsTitled("Muse · Chat B");
  check("chat B gets its own group", gB.length === 1 && H.groupOf(u1.id) === gB[0].id && gB[0].id !== gA[0].id);

  // cross-chat isolation around groups
  r = await H.cmd("sess-B", "get_page_text", { tabId: t1.id });
  check("chat B cannot act on a tab in chat A's group", !r.ok && r.error === "tab_not_shared", r);
  r = await H.cmd("sess-B", "tabs_context", {});
  check("chat B's tab list holds only its own grouped tab",
        r.ok && r.data.tabs.length === 1 && r.data.tabs[0].tabId === u1.id, r);

  /* ------------------------------------------------ drag in / out */
  // drag-in adopts: a loose tab dropped into A's group becomes A's
  const loose = mkTab("https://notes.example.net/page");
  setGroup(loose.id, gA[0].id);
  await tick(60);
  const lo = await H.owner(loose.id);
  const sessA2 = (await F.sw(`local.get("sessions", {})`))["sess-A"];
  check("a tab dragged into the group is adopted by the session",
        !!lo && lo.chat === "Chat A" && F.pillOf[loose.id] === "Chat A", lo);
  check("...and its site is granted to that session", !!(sessA2 && sessA2.sites["notes.example.net"]), sessA2 && sessA2.sites);

  // drag-in transfer: B's tab dragged into A's group leaves B
  setGroup(u1.id, gA[0].id);
  await tick(60);
  const sessB = (await F.sw(`local.get("sessions", {})`))["sess-B"];
  check("a tab dragged from B's group into A's transfers (one tab, one session)",
        (await H.owner(u1.id) || {}).chat === "Chat A" && !sessB,
        { owner: await H.owner(u1.id), sessB });

  // drag-out releases: ungroup
  setGroup(t2.id, -1);
  await tick(60);
  check("a tab dragged out of the group (ungrouped) is released",
        !(await H.owner(t2.id)) && !F.pillOf[t2.id]);

  // drag-out into a group of Daniel's own: released, but the tab keeps
  // the group Daniel put it in
  const mine = mkGroup("Daniel's own", 1);
  setGroup(loose.id, mine.id);
  await tick(60);
  check("a tab moved into a non-session group is released...",
        !(await H.owner(loose.id)) && !F.pillOf[loose.id]);
  check("...and it stays in Daniel's own group (not ungrouped by the release)",
        H.groupOf(loose.id) === mine.id);

  // a non-web tab dragged in is refused and taken back out of the group
  const nw = mkTab("chrome://extensions/");
  setGroup(nw.id, gA[0].id);
  await tick(60);
  check("a non-web tab dragged into the group is refused and removed from it",
        !(await H.owner(nw.id)) && H.groupOf(nw.id) === -1, tabs.get(nw.id));

  // moving a controlled tab to another window ungroups it: released
  moveToWindow(t3.id, 5);
  await tick(60);
  check("a controlled tab moved to another window leaves the group and is released",
        !(await H.owner(t3.id)) && tabs.get(t3.id).windowId === 5 && H.groupOf(t3.id) === -1);

  // rename a foreign group to a session's title: its tabs are adopted
  const alien = mkGroup("Random", 3);
  const at = mkTab("https://alien.example.com/", { windowId: 3 });
  setGroup(at.id, alien.id);
  await tick(30);
  await chrome.tabGroups.update(alien.id, { title: "Muse · Chat A" });
  await tick(60);
  check("renaming a group to a session's title adopts its tabs",
        (await H.owner(at.id) || {}).chat === "Chat A", await H.owner(at.id));
  // rename it away again: its tabs are released
  await chrome.tabGroups.update(alien.id, { title: "Something else" });
  await tick(60);
  check("renaming a session's group away releases its tabs",
        !(await H.owner(at.id)) && H.groupOf(at.id) === alien.id);

  // cross-window drag-in where only onAttached fires (no groupId update
  // event): the tab must still be adopted
  const gAx = H.groupsTitled("Muse · Chat A")[0];
  const cw = mkTab("https://cross.example.com/", { windowId: 9 });
  tabs.get(cw.id).groupId = gAx.id; tabs.get(cw.id).windowId = gAx.windowId;
  F.E.tabsAttached.fire(cw.id, { newWindowId: gAx.windowId, newPosition: 0 });
  await tick(80);
  check("a tab that lands in the group with only an attach event is adopted",
        (await H.owner(cw.id) || {}).chat === "Chat A", await H.owner(cw.id));

  // panel remove takes the tab out of the group too
  await F.panel("remove_tab", { tabId: t1.id });
  await tick(40);
  check("panel Remove ungroups the tab as well as releasing it",
        !(await H.owner(t1.id)) && H.groupOf(t1.id) === -1);

  console.log(`\n${passes}/${passes + failures} passed`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error("CRASH", e); process.exit(2); });
