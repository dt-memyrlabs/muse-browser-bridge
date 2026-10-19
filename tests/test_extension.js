/* Tests for v2/extension/sw.js against a fake chrome.* API (no browser).
 * Covers the security rules: chat isolation, site permission, drag vs child
 * tabs, redirects, approvals only from the side panel, no relay backdoors,
 * disconnect paths, what gets gated (clicks, drags, keys, typing, paste),
 * re-check after approval, deadlines and cancel, reconnect reconciliation.
 * What a real page reports is covered by the live suite.
 *
 *   node test_extension.js     exit 0 = all passed
 */
"use strict";
const { install } = require("./fake_chrome");

let failures = 0, passes = 0;
function check(name, cond, detail) {
  if (cond) { passes++; console.log("PASS " + name); }
  else { failures++; console.log("FAIL " + name + (detail !== undefined ? "  -- " + JSON.stringify(detail).slice(0, 500) : "")); }
}
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

const F = install({ fakeSocket: true });
const { tabs, groups, sent, inputs, E, page, mkTab, setGroup, setUrl, FakeWS, panel } = F;

/* ---------------------------------------------------------------- helpers */
let cmdSeq = 0;
function cmdStart(sessionId, action, args, extra) {
  const id = "c" + (++cmdSeq);
  FakeWS.last.deliver({ t: "cmd", id, sessionId, action, args: args || {}, ttlMs: 120000, ...(extra || {}) });
  return id;
}
async function result(id, ms = 4000) {
  for (let i = 0; i < ms / 5; i++) {
    const r = sent.find((m) => m.t === "result" && m.id === id);
    if (r) return r;
    await tick(5);
  }
  return { ok: false, error: "TEST_TIMEOUT" };
}
const cmd = (sid, action, args, extra) => result(cmdStart(sid, action, args, extra));
// Which chat owns a tab (by the stored tab lists), and what its pill shows.
async function owner(tabId) {
  const all = await F.sw(`local.get("sessions", {})`);
  for (const v of Object.values(all)) if (v.tabs && Object.prototype.hasOwnProperty.call(v.tabs, String(tabId))) return v.chatName;
  return null;
}
const pillOn = (tabId) => F.pillOf[tabId] || null;
async function pendingPrompts() { return (await panel("state")).prompts; }
async function waitPrompt(n = 1) {
  for (let i = 0; i < 200; i++) { const p = await pendingPrompts(); if (p.length >= n) return p; await tick(5); }
  return [];
}
async function answer(allow) {
  const pr = await waitPrompt(1);
  if (pr.length) await panel(allow ? "approve" : "deny", { id: pr[0].id });
  return pr[0];
}
async function pair(url, name) {
  const t = mkTab(url, { active: true });
  for (const x of tabs.values()) if (x.id !== t.id) x.active = false;
  const r = await panel("share", { tabId: t.id });
  const req = sent.filter((m) => m.t === "pair_request").pop();
  FakeWS.last.deliver({ t: "pair_code", reqId: req.reqId, code: "ABCD2345", expiresIn: 300 });
  await tick(10);
  const sid = "sess-" + name;
  FakeWS.last.deliver({ t: "paired", reqId: req.reqId, sessionId: sid, chatName: name });
  await tick(30);
  return { tab: tabs.get(t.id), sid, shareOk: r && r.ok };
}
const clicks = () => inputs.filter((i) => i.method === "Input.dispatchMouseEvent" && i.params.type === "mousePressed").length;
const keys = () => inputs.filter((i) => i.method === "Input.dispatchKeyEvent" && i.params.type !== "keyUp").length;
const risky = { tag: "button", text: "Pay now", isSubmit: false, fp: "button|pay" };
const plain = { tag: "button", text: "Show details", fp: "button|details" };

/* ------------------------------------------------------------------ tests */
(async () => {
  let hello;
  for (let i = 0; i < 200 && !hello; i++) { await tick(10); hello = sent.find((m) => m.t === "hello"); }
  check("worker says hello with a signed device key", hello && hello.sig && hello.pubJwk && hello.pubJwk.x, hello);
  FakeWS.last.deliver({ t: "welcome", ok: true });
  await tick(10);

  // pairing
  const A = await pair("https://shop.example.com/admin", "Chat A");
  check("share from the side panel starts pairing", A.shareOk);
  check("the paired page becomes the chat's tab and shows the chat's pill",
        (await owner(A.tab.id)) === "Chat A" && pillOn(A.tab.id) === "Chat A", [await owner(A.tab.id), pillOn(A.tab.id)]);
  const B = await pair("https://mail.example.org/inbox", "Chat B");
  check("the second chat owns only its own tab", (await owner(B.tab.id)) === "Chat B" && (await owner(A.tab.id)) === "Chat A");

  // isolation
  let r = await cmd(A.sid, "tabs_context");
  check("chat A sees only its own tabs", r.ok && r.data.tabs.length === 1 && r.data.tabs[0].tabId === A.tab.id, r);
  r = await cmd(A.sid, "get_page_text", { tabId: B.tab.id });
  check("chat A cannot act on chat B's tab (tab_not_shared)", !r.ok && r.error === "tab_not_shared", r);
  r = await cmd(A.sid, "tabs_close", { tabIds: [B.tab.id] });
  check("chat A cannot close chat B's tab", !r.ok && r.error === "tab_not_shared" && tabs.has(B.tab.id), r);
  const loose = mkTab("https://bank.example.net/");
  r = await cmd(A.sid, "get_page_text", { tabId: loose.id });
  check("a tab in no group is out of reach", !r.ok && r.error === "tab_not_shared", r);
  r = await cmd("sess-unknown", "tabs_context");
  check("unknown session refused", !r.ok && r.error === "session_not_found", r);

  // no backdoors, and no inherited names dispatch as tools
  for (const a of ["set_policy", "approve", "grant_site", "dump_audit", "eval", "constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
    r = await cmd(A.sid, a, { host: "bank.example.net", policy: "allow" });
    check(`relay command "${a}" does not exist (exact unknown_action)`, !r.ok && r.error === "unknown_action" && r.detail.startsWith(a + ". Tools: "), r);
  }
  r = await cmd(A.sid, "tabs_list", {});
  check("tabs_list (another agent's name) works as tabs_context", r.ok && Array.isArray(r.data.tabs), r);
  r = await cmd(A.sid, "nosuchtool", {});
  check("an unknown tool's error lists the real tools", !r.ok && /Tools: .*tabs_context.*get_page_text/.test(r.detail), r);
  r = await cmd(A.sid, "browser_batch", { actions: [{ name: "constructor", input: {} }] });
  check("inherited names are not tools inside a batch either", r.ok && r.data.results[0].error === "unknown_action", r);

  // navigate to a new site asks; approval only from the side panel
  let navP = cmd(A.sid, "navigate", { url: "https://pay.example.com/checkout" });
  let pr = await waitPrompt(1);
  check("opening a new site asks in the side panel, naming the chat",
        pr.length === 1 && /pay\.example\.com/.test(pr[0].title) && pr[0].title.includes("Chat A"), pr);
  const fromPage = await panel("approve", { id: pr[0].id }, { id: "extid", url: "https://evil.example/", tab: { id: 5 } });
  check("approve from a web page / content script is refused", fromPage && fromPage.error === "forbidden", fromPage);
  const fromOther = await panel("approve", { id: pr[0].id }, { id: "otherext", url: "chrome-extension://otherext/x.html" });
  check("approve from another extension is refused", fromOther && fromOther.error === "forbidden", fromOther);
  check("prompt still pending after forged approvals", (await pendingPrompts()).length === 1);
  await panel("deny", { id: pr[0].id });
  r = await navP;
  check("Deny -> denied_by_user, nothing opened", !r.ok && r.error === "denied_by_user", r);

  navP = cmd(A.sid, "navigate", { url: "https://pay.example.com/checkout" });
  await answer(true);
  r = await navP;
  check("Allow -> the new tab is chat A's, with its pill", r.ok && (await owner(r.data.tabId)) === "Chat A" && pillOn(r.data.tabId) === "Chat A", r);
  const payTab = r.ok ? r.data.tabId : null;
  r = await cmd(A.sid, "navigate", { url: "https://pay.example.com/other" });
  check("already-permitted site opens without asking", r.ok && (await pendingPrompts()).length === 0, r);
  // navigate to the page a tab is already on never reloads it; active:true only brings it forward
  let setUrls = 0;
  const origUpdate = chrome.tabs.update;
  chrome.tabs.update = async (id, p) => { if (p.url) setUrls++; if (p.active) tabs.get(id).active = true; return origUpdate(id, p.url ? p : { url: tabs.get(id).url }); };
  tabs.get(payTab).active = false;
  r = await cmd(A.sid, "navigate", { url: "https://pay.example.com/checkout/", tabId: payTab, active: true });
  check("navigate to the URL a tab already has does not reload it, and active:true brings it forward",
        r.ok && r.data.reloaded === false && setUrls === 0 && tabs.get(payTab).active === true, [r, setUrls]);
  chrome.tabs.update = origUpdate;

  // redirect after approval: next action pauses for permission
  setUrl(payTab, "https://tracker.example.biz/landing");
  let actP = cmd(A.sid, "get_page_text", { tabId: payTab });
  pr = await waitPrompt(1);
  check("tab that moved to a new site: next action asks first", pr.length === 1 && /tracker\.example\.biz/.test(pr[0].title), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...and Deny blocks it", !r.ok && r.error === "denied_by_user", r);
  const st1 = await panel("state");
  check("redirected site was not silently permitted", !st1.chats.find((c) => c.chatName === "Chat A").sites.includes("tracker.example.biz"));

  // a read whose document moved to another site mid-read is thrown away
  const origText = page.text;
  page.text = (t) => { t.url = "https://elsewhere.example.net/"; return "secret text of elsewhere"; };
  r = await cmd(A.sid, "get_page_text", { tabId: A.tab.id });
  check("text read from a document that moved to another site is refused (tab_navigated)",
        !r.ok && r.error === "tab_navigated" && !JSON.stringify(r).includes("secret text"), r);
  tabs.get(A.tab.id).url = "https://shop.example.com/admin";
  page.text = origText;

  // a navigation to another site still committing: wait, then check the new site
  tabs.get(A.tab.id).pendingUrl = "https://other.example.net/";
  setTimeout(() => { const t = tabs.get(A.tab.id); t.url = "https://other.example.net/"; t.pendingUrl = undefined; }, 300);
  actP = cmd(A.sid, "get_page_text", { tabId: A.tab.id });
  pr = await waitPrompt(1);
  check("a tab mid-way to another site is not read as the old site; the new site asks",
        pr.length === 1 && /other\.example\.net/.test(pr[0].title), pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  tabs.get(A.tab.id).url = "https://shop.example.com/admin";

  // a tab Daniel opens from a chat's tab (Ctrl+T, his own click) does NOT join the chat
  const own = mkTab("https://daniels-own.example/", { openerTabId: A.tab.id });
  await tick(30);
  check("a tab Daniel opens from a chat's tab stays his (the chat did not just act there)", !(await owner(own.id)));
  // STAGING-ONLY adaptation (SEC-23, as in MERGE-REPORT): only a SAME-host
  // popup from a chat's tab joins the chat; a cross-host popup stays
  // unshared. The shipped section asserted the pre-fix behaviour.
  page.point = () => ({ tag: "a", text: "open", href: "https://evil-child.example/", fp: "a|open" });
  await cmd(A.sid, "computer", { action: "left_click", coordinate: [5, 5], tabId: A.tab.id });
  const cross = mkTab("https://evil-child.example/", { openerTabId: A.tab.id });
  await tick(30);
  check("a cross-host popup from a chat's tab does NOT join the chat (SEC-23)", !(await owner(cross.id)));
  const child = mkTab("https://shop.example.com/popup", { openerTabId: A.tab.id });
  await tick(30);
  check("a same-host tab opened from a chat's tab joins that chat", (await owner(child.id)) === "Chat A");
  setUrl(child.id, "https://evil-child.example/");
  await tick(10);
  let sites = (await panel("state")).chats.find((c) => c.chatName === "Chat A").sites;
  check("...but does not grant its site", !sites.includes("evil-child.example"), sites);
  const ntp = mkTab("chrome://newtab/", { openerTabId: A.tab.id });
  await tick(30);
  check("a new tab on a browser page (Ctrl+T) never joins, even right after the chat clicked", !(await owner(ntp.id)));
  r = await cmd(A.sid, "tabs_context");
  const ct = r.ok && r.data.tabs.find((t) => t.tabId === child.id);
  check("tabs_context shows an unpermitted tab without its URL or title",
        ct && ct.permitted === false && ct.site === "evil-child.example" && !("url" in ct) && !("title" in ct), ct);
  actP = cmd(A.sid, "get_page_text", { tabId: child.id });
  pr = await waitPrompt(1);
  check("acting on that child tab asks first", pr.length === 1, pr);
  await panel("deny", { id: pr[0].id });
  await actP;

  // closing a tab on a site the chat was never given asks
  actP = cmd(A.sid, "tabs_close", { tabIds: [child.id] });
  pr = await waitPrompt(1);
  check("closing a tab on an unpermitted site asks", pr.length === 1 && /evil-child/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...and Deny keeps it open", !r.ok && tabs.has(child.id), r);

  // Daniel gives a tab to a connected chat from the panel: usable at once, no prompt
  const given = mkTab("https://docs.example.io/page");
  r = await cmd(A.sid, "get_page_text", { tabId: given.id });
  check("a tab not given to the chat is out of reach", !r.ok && r.error === "tab_not_shared", r);
  const ra = await panel("add_tab", { sessionId: A.sid, tabId: given.id });
  check("the panel gives the tab to the chat, and it shows the pill", ra.ok && (await owner(given.id)) === "Chat A" && pillOn(given.id) === "Chat A", ra);
  r = await cmd(A.sid, "get_page_text", { tabId: given.id });
  check("...the chat reads it with no prompt (Daniel chose it)", r.ok && (await pendingPrompts()).length === 0, r);
  // one tab, one chat: giving it to chat B takes it from chat A
  await panel("add_tab", { sessionId: B.sid, tabId: given.id });
  r = await cmd(A.sid, "get_page_text", { tabId: given.id });
  check("giving a tab to another chat takes it from the first", !r.ok && r.error === "tab_not_shared" && (await owner(given.id)) === "Chat B", r);
  await panel("add_tab", { sessionId: A.sid, tabId: given.id });
  // the pill's ✕ (a message from the page's content script) stops sharing that tab only
  const fromPill = { id: "extid", url: "https://docs.example.io/page", tab: { id: given.id }, frameId: 0 };
  const rp = await panel("pill_remove", {}, fromPill);
  r = await cmd(A.sid, "get_page_text", { tabId: given.id });
  check("the pill's ✕ stops sharing that tab at once", rp.ok && !r.ok && r.error === "tab_not_shared" && !pillOn(given.id), r);
  check("...and only that tab", (await owner(A.tab.id)) === "Chat A");
  const rf = await panel("approve", { id: "x" }, fromPill);
  check("a content script can do nothing else (approve is refused)", rf && rf.error === "forbidden", rf);
  await panel("add_tab", { sessionId: A.sid, tabId: given.id });
  const rr = await panel("remove_tab", { tabId: given.id });
  check("'Stop sharing this tab' in the panel does the same", rr.ok && !(await owner(given.id)), rr);

  /* ---- what input is gated ---- */
  const T = A.tab.id;
  // plain click: no prompt, one click
  page.point = () => plain;
  let c0 = clicks();
  r = await cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  check("a plain click goes through with no prompt", r.ok && clicks() === c0 + 1, r);

  // risky click: asks; Deny -> no click
  page.point = () => risky;
  c0 = clicks();
  actP = cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a Pay button asks before clicking", pr.length === 1 && /Pay now/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...Deny -> no click reached the page", !r.ok && r.error === "denied_by_user" && clicks() === c0, r);

  // a long block of text is not an action label: a WhatsApp chat row whose
  // preview says "final order" opens with no prompt (seen live 2026-09-27)
  page.point = () => ({ tag: "div", text: "SproutsOG 2.0 <> HB 9:35 am Healthy Buddha : final order ic-1234, please send the invoice", fp: "div|row" });
  let c1 = clicks();
  r = await cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  check("a chat-list row with 'order' in its preview clicks with no prompt", r.ok && clicks() === c1 + 1 && (await pendingPrompts()).length === 0, r);

  // the accessibility name alone is enough (icon button, closed shadow root)
  page.point = () => ({ tag: "x-pay", text: "", fp: "x-pay|" });
  page.axAtPoint = [{ nodeId: "a", role: { value: "StaticText" }, name: { value: "" }, backendDOMNodeId: 900, parentId: "b" },
                    { nodeId: "b", role: { value: "button" }, name: { value: "Delete item" } }];
  actP = cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a button named only in the accessibility tree ('Delete item') asks", pr.length === 1 && /Delete item/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  page.axAtPoint = [];

  // a frame from another site always asks
  page.point = () => ({ crossOriginFrame: true, frameHost: "evil.test", tag: "iframe", fp: "iframe|evil.test" });
  actP = cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a click inside another site's frame asks", pr.length === 1 && /evil\.test/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  await actP;

  // after Allow the point is read again; if it changed, nothing is clicked
  let calls = 0;
  page.point = () => (++calls === 1 ? risky : { ...risky, text: "Pay $900 now", fp: "button|pay900" });
  c0 = clicks();
  actP = cmd(A.sid, "computer", { action: "left_click", coordinate: [100, 100], tabId: T });
  await answer(true);
  r = await actP;
  check("the element changed during the prompt -> target_changed, no click", !r.ok && r.error === "target_changed" && clicks() === c0, r);

  // Allow on an unchanged target clicks once; a double-click says so
  page.point = () => risky;
  c0 = clicks();
  actP = cmd(A.sid, "computer", { action: "double_click", coordinate: [100, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a risky double-click prompt says how many clicks", pr.length === 1 && /2 times/.test(pr[0].title), pr);
  await panel("approve", { id: pr[0].id });
  r = await actP;
  check("...Allow -> the clicks happen", r.ok && clicks() === c0 + 2, r);

  // a ref whose centre is covered by another element is refused
  page.ax[T] = [{ nodeId: "1", role: { value: "RootWebArea" }, name: { value: "" }, childIds: ["2", "3"], backendDOMNodeId: 1 },
                { nodeId: "2", parentId: "1", role: { value: "button" }, name: { value: "Save" }, backendDOMNodeId: 2 },
                { nodeId: "3", parentId: "1", role: { value: "checkbox" }, name: { value: "Agree" }, backendDOMNodeId: 3 }];
  r = await cmd(A.sid, "read_page", { tabId: T });
  const saveRef = r.ok && (r.data.tree.match(/button "Save" \[(ref_\d+)\]/) || [])[1];
  const agreeRef = r.ok && (r.data.tree.match(/checkbox "Agree" \[(ref_\d+)\]/) || [])[1];
  page.point = () => ({ ...plain, covered: true });
  c0 = clicks();
  r = await cmd(A.sid, "computer", { action: "left_click", ref: saveRef });
  check("a ref covered by another element -> target_covered, no click", !r.ok && r.error === "target_covered" && clicks() === c0, r);
  page.point = () => plain;
  r = await cmd(A.sid, "computer", { action: "left_click", ref: saveRef });
  check("a ref with no tabId acts on the ref's own tab", r.ok, r);
  r = await cmd(A.sid, "computer", { action: "left_click", ref: saveRef, tabId: payTab });
  check("a ref used with another tab's id -> ref_other_tab", !r.ok && r.error === "ref_other_tab", r);
  r = await cmd(A.sid, "read_page", { tabId: T });
  const saveRef2 = r.ok && (r.data.tree.match(/button "Save" \[(ref_\d+)\]/) || [])[1];
  check("an unchanged element keeps its ref across reads", saveRef2 === saveRef, [saveRef, saveRef2]);

  // drags: a zero-length drag is a click and is gated; a real drag checks both ends
  page.point = () => risky;
  c0 = clicks();
  actP = cmd(A.sid, "computer", { action: "left_click_drag", start_coordinate: [100, 100], coordinate: [101, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a zero-length drag onto a Pay button asks (it is a click)", pr.length === 1 && /Pay now/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...Deny -> no press reached the page", !r.ok && clicks() === c0, r);
  page.point = (t, a) => (a.x < 150 ? plain : risky);
  actP = cmd(A.sid, "computer", { action: "left_click_drag", start_coordinate: [100, 100], coordinate: [300, 100], tabId: T });
  pr = await waitPrompt(1);
  check("a drag that ends on a risky element asks", pr.length === 1 && pr[0].title === "Drag", pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  page.point = () => plain;
  c0 = clicks();
  r = await cmd(A.sid, "computer", { action: "left_click_drag", start_coordinate: [100, 100], coordinate: [300, 100], tabId: T });
  const log = (await panel("state")).audit;
  check("a plain drag goes through and is in the activity log", r.ok && clicks() === c0 + 1 && log.some((l) => l.action === "left_click_drag"), r);

  // keys
  page.focus = () => ({ kind: "element", tag: "button", text: "Pay now", actionable: true, fp: "button|pay" });
  let k0 = keys();
  actP = cmd(A.sid, "computer", { action: "key", text: "space", tabId: T });
  pr = await waitPrompt(1);
  check("Space on a focused Pay button asks", pr.length === 1 && /Space/.test(pr[0].title), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...Deny -> no key reached the page", !r.ok && keys() === k0, r);
  actP = cmd(A.sid, "computer", { action: "key", text: "ctrl+Enter", tabId: T });
  pr = await waitPrompt(1);
  check("ctrl+Enter on a focused Pay button asks", pr.length === 1, pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  // focus moves during the sequence: each key is checked where focus is then
  page.focus = () => ({ kind: "element", tag: "button", text: "Pay now", actionable: true, fp: "button|pay" });
  k0 = keys();
  actP = cmd(A.sid, "computer", { action: "key", text: "Tab Enter", tabId: T });
  pr = await waitPrompt(1);
  check("Tab then Enter: the Enter lands on a Pay button and asks", pr.length === 1 && /Enter/.test(pr[0].title), pr);
  check("...the Tab already went through before the prompt", keys() === k0 + 1);
  await panel("deny", { id: pr[0].id });
  await actP;
  // Enter in a field of a script-driven login (no <form>, has a password)
  page.focus = () => ({ kind: "element", tag: "input", isField: true, inForm: true, formHasPassword: true, fp: "input|user" });
  actP = cmd(A.sid, "computer", { action: "key", text: "Enter", tabId: T });
  pr = await waitPrompt(1);
  check("Enter in a field next to a password field asks", pr.length === 1 && /password/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  // repeat: one approval, and the prompt states the count
  page.focus = () => ({ kind: "element", tag: "button", text: "Pay now", actionable: true, fp: "button|pay" });
  k0 = keys();
  actP = cmd(A.sid, "computer", { action: "key", text: "Enter", repeat: 3, tabId: T });
  pr = await waitPrompt(1);
  check("a repeated Enter says how many presses", pr.length === 1 && /3 times/.test(pr[0].title), pr);
  await panel("approve", { id: pr[0].id });
  r = await actP;
  check("...one Allow covers them, and all three are sent", r.ok && keys() === k0 + 3 && (await pendingPrompts()).length === 0, r);
  // paste always asks
  page.focus = () => ({ kind: "element", tag: "input", isField: true, fp: "input|q" });
  actP = cmd(A.sid, "computer", { action: "key", text: "ctrl+v", tabId: T });
  pr = await waitPrompt(1);
  check("paste from the clipboard asks", pr.length === 1 && /clipboard/i.test(pr[0].title), pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  // plain keys don't ask
  k0 = keys();
  r = await cmd(A.sid, "computer", { action: "key", text: "Tab shift+Tab a b", tabId: T });
  check("ordinary keys in an ordinary field go through without a prompt", r.ok && keys() === k0 + 4, r);
  // typing key by key into a password field asks, and hides the text
  page.focus = () => ({ kind: "element", tag: "input", isField: true, isPassword: true, fp: "input|pw" });
  k0 = keys();
  actP = cmd(A.sid, "computer", { action: "key", text: "h u n t e r", tabId: T });
  pr = await waitPrompt(1);
  check("typing a password key by key asks, showing only the length",
        pr.length === 1 && /password/i.test(pr[0].title) && /6 characters/.test(pr[0].detail) && !/hunter/.test(JSON.stringify(pr)), pr);
  await panel("deny", { id: pr[0].id });
  r = await actP;
  check("...Deny -> no key reached the page", !r.ok && keys() === k0, r);
  // typing into another site's frame, or where focus can't be seen, asks
  page.focus = () => ({ kind: "crossOriginFrame", frameHost: "evil.test", fp: "iframe|evil.test" });
  actP = cmd(A.sid, "computer", { action: "type", text: "hello", tabId: T });
  pr = await waitPrompt(1);
  check("typing into another site's frame asks", pr.length === 1 && /evil\.test/.test(pr[0].detail) && !/hello/.test(pr[0].detail), pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  page.focus = () => ({ kind: "unknown", fp: "unknown" });
  actP = cmd(A.sid, "computer", { action: "type", text: "hello", tabId: T });
  pr = await waitPrompt(1);
  check("typing where focus cannot be seen asks", pr.length === 1, pr);
  await panel("deny", { id: pr[0].id });
  await actP;
  // text that never reaches the field fails loudly (a background tab dropped it, 2026-09-27)
  page.focus = () => ({ kind: "element", tag: "input", isField: true, fp: "input|q", len: 3 });
  r = await cmd(A.sid, "computer", { action: "type", text: "Z", tabId: T });
  check("typing that leaves the field unchanged returns not_typed, not ok", !r.ok && r.error === "not_typed", r);
  const inserted = () => inputs.filter((i) => i.method === "Input.insertText").length;
  page.focus = () => ({ kind: "element", tag: "input", isField: true, fp: "input|q", len: inserted() });
  r = await cmd(A.sid, "computer", { action: "type", text: "Z", tabId: T });
  check("...and typing that changes the field returns ok", r.ok, r);
  // a wheel scroll Chrome never answers falls back to scrolling the page directly
  tabs.get(T).active = true;
  page.hangWheel = true; page.scrollMoves = true;
  const s0 = Date.now();
  r = await cmd(A.sid, "computer", { action: "scroll", tabId: T, coordinate: [5, 5], scroll_direction: "up", scroll_amount: 5 });
  const took = Date.now() - s0;
  check("an unanswered wheel scroll falls back to a direct scroll after about 3 s, not a 15 s timeout",
        r.ok && r.data.via === "direct" && r.data.scrolled === true && took >= 2500 && took < 6000, { r, took });
  page.hangWheel = false;
  r = await cmd(A.sid, "computer", { action: "scroll", tabId: T, coordinate: [5, 5], scroll_direction: "down" });
  check("...and an answered wheel scroll stays a normal wheel scroll", r.ok && !r.data.via, r);
  page.focus = () => ({ kind: "none", fp: "none" });
  r = await cmd(A.sid, "computer", { action: "key", text: "notakey+x", tabId: T });
  check("a bad key name -> bad_key with the key in detail", !r.ok && r.error === "bad_key" && /notakey/.test(r.detail), r);

  // form_input: checkbox "false" unchecks; password asks
  page.node = () => ({ tag: "input", type: "checkbox", isField: true, fp: "input|checkbox" });
  page.elements[3] = { tagName: "INPUT", checked: true, dispatchEvent() {} };
  r = await cmd(A.sid, "form_input", { ref: agreeRef, value: "false" });
  check('form_input value "false" unchecks a checkbox', r.ok && page.elements[3].checked === false, [r, page.elements[3].checked]);
  r = await cmd(A.sid, "form_input", { ref: agreeRef, value: true });
  check("form_input value true checks it", r.ok && page.elements[3].checked === true, r);
  page.node = () => ({ tag: "button", type: "", isField: false, fp: "button" });
  r = await cmd(A.sid, "form_input", { ref: saveRef, value: "x" });
  check("form_input on a button -> not_a_field", !r.ok && r.error === "not_a_field", r);

  /* ---- deadlines and cancel ---- */
  const id1 = cmdStart(A.sid, "navigate", { url: "https://new-site.example/" });
  pr = await waitPrompt(1);
  FakeWS.last.deliver({ t: "cancel", id: id1 });
  r = await result(id1);
  check("cancel from the relay closes the prompt and stops the call",
        !r.ok && r.error === "canceled" && (await pendingPrompts()).length === 0 && ![...tabs.values()].some((t) => /new-site/.test(t.url)), r);
  r = await cmd(A.sid, "navigate", { url: "https://new-site.example/" }, { ttlMs: 5000 });
  check("with too little time left, no prompt is opened (no_time_to_ask)",
        !r.ok && r.error === "no_time_to_ask" && (await pendingPrompts()).length === 0, r);
  const id2 = cmdStart(A.sid, "navigate", { url: "https://new-site.example/" }, { ttlMs: 9000 });
  pr = await waitPrompt(1);
  check("a prompt never outlives the relay's deadline", pr.length === 1 && pr[0].expiresAt - Date.now() < 9000, pr);
  await panel("deny", { id: pr[0].id });
  await result(id2);

  /* ---- result size ---- */
  const bigText = page.text;
  page.text = () => "x".repeat(13000000);
  r = await cmd(A.sid, "get_page_text", { tabId: T });
  check("a reply over 12 MB is refused with result_too_large, not sent", !r.ok && r.error === "result_too_large", { ok: r.ok, error: r.error });
  page.text = bigText;
  const shotCalls = [];
  page.shot = (p) => { shotCalls.push(p.format); return p.format === "png" ? "A".repeat(7000000) : "B".repeat(1000); };
  r = await cmd(A.sid, "screenshot", { tabId: T });
  check("an oversized PNG screenshot is resent as JPEG", r.ok && r.data.image.startsWith("data:image/jpeg") && shotCalls.join() === "png,jpeg", shotCalls);
  page.shot = "iVBORw0KGgo=";

  /* ---- Chrome's "being debugged" Cancel stops the chat ---- */
  const D = await pair("https://crm.example.com/", "Chat D");
  let sb = sent.length;
  E.dbgDetach.fire({ tabId: D.tab.id }, "canceled_by_user");
  await tick(50);
  r = await cmd(D.sid, "tabs_context");
  check("Cancel on Chrome's debugging bar disconnects that chat",
        !r.ok && r.error === "session_not_found" && sent.slice(sb).some((m) => m.t === "revoke" && m.sessionId === D.sid), r);

  /* ---- reconnect: both sides agree ---- */
  const G = await pair("https://gone.example.com/", "Chat G");
  await panel("share", { tabId: loose.id });
  const deadShare = sent.filter((m) => m.t === "pair_request").pop().reqId;
  FakeWS.last.deliver({ t: "pair_code", reqId: deadShare, code: "DEAD2345", expiresIn: 300 });
  await tick(10);
  const noCode = mkTab("https://nocode.example.com/");
  await panel("share", { tabId: noCode.id });
  const waitingShare = sent.filter((m) => m.t === "pair_request").pop().reqId;
  await F.sw(`local.set("inflight", { "old-cmd": "some-old-worker" })`);
  for (const k of Object.keys(F.sessionStore)) delete F.sessionStore[k]; // an extension reload wipes storage.session
  sb = sent.length;
  FakeWS.last.deliver({ t: "welcome", ok: true, sessions: [A.sid, B.sid], reqIds: [] });
  await tick(60);
  r = await cmd(G.sid, "tabs_context");
  check("a session the relay no longer has is dropped on reconnect, and its pill goes", !r.ok && r.error === "session_not_found" && !(await owner(G.tab.id)) && !pillOn(G.tab.id), r);
  const shares = await F.sw(`local.get("shares", {})`);
  check("a code the relay forgot is cleared on reconnect", !shares[deadShare], Object.keys(shares));
  check("a share still waiting for a code asks again", sent.slice(sb).some((m) => m.t === "pair_request" && m.reqId === waitingShare));
  check("a command a previous worker left unanswered gets worker_restarted",
        sent.slice(sb).some((m) => m.t === "result" && m.id === "old-cmd" && m.error === "worker_restarted"));
  await panel("cancel_share", { reqId: waitingShare });

  // a share whose code request cannot be sent fails at once (no stuck "Getting a code…")
  FakeWS.last.readyState = 3;
  const lone = mkTab("https://lone.example.com/");
  const rs = await panel("share", { tabId: lone.id });
  check("share with the socket down fails at once (relay_offline)", rs && !rs.ok && rs.error === "relay_offline", rs);
  FakeWS.last.readyState = 1;

  // relay refused a code
  await panel("share", { tabId: lone.id });
  const refusedReq = sent.filter((m) => m.t === "pair_request").pop().reqId;
  FakeWS.last.deliver({ t: "pair_error", reqId: refusedReq, error: "too_many_codes" });
  await tick(20);
  const st2 = await panel("state");
  check("a refused code request clears the share", !(await F.sw(`local.get("shares", {})`))[refusedReq], st2.share);

  /* ---- disconnect paths ---- */
  const sentBefore = sent.length;
  await panel("disconnect", { sessionId: A.sid });
  check("disconnect tells the relay", sent.slice(sentBefore).some((m) => m.t === "revoke" && m.sessionId === A.sid));
  r = await cmd(A.sid, "tabs_context");
  check("disconnected chat is dead", !r.ok && r.error === "session_not_found", r);
  check("its tabs are released and lose the pill", !(await owner(A.tab.id)) && !pillOn(A.tab.id));
  r = await cmd(B.sid, "tabs_context");
  check("other chat still works", r.ok && r.data.tabs.length === 1, r);

  FakeWS.last.deliver({ t: "revoked", sessionId: B.sid });
  await tick(30);
  r = await cmd(B.sid, "tabs_context");
  check("revoked by relay -> session gone", !r.ok && r.error === "session_not_found", r);

  const C = await pair("https://crm2.example.com/", "Chat C");
  sb = sent.length;
  await chrome.tabs.remove(C.tab.id);
  await tick(30);
  r = await cmd(C.sid, "tabs_context");
  check("closing a chat's last tab ends the chat (Daniel's rule, 2026-10-18)", !r.ok && r.error === "session_not_found", r);
  r = await cmd(C.sid, "navigate", { url: "https://crm2.example.com/next" });
  check("...and a tabless chat can no longer open tabs: it pairs again first", !r.ok && r.error === "session_not_found", r);

  // pairing refused if the page changed before the code was used
  const Dp = mkTab("https://a.example.com/", { active: true });
  for (const x of tabs.values()) if (x.id !== Dp.id) x.active = false;
  await panel("share", { tabId: Dp.id });
  const req = sent.filter((m) => m.t === "pair_request").pop();
  setUrl(Dp.id, "https://b.example.com/");
  const sd = sent.length;
  FakeWS.last.deliver({ t: "paired", reqId: req.reqId, sessionId: "sess-D2", chatName: "D" });
  await tick(30);
  check("pairing refused when the page moved to another site before pairing",
        !(await owner(Dp.id)) && sent.slice(sd).some((m) => m.t === "revoke" && m.sessionId === "sess-D2"));

  // pairing refusals say why
  let sn = sent.length;
  FakeWS.last.deliver({ t: "paired", reqId: "no-such-share", sessionId: "sess-X", chatName: "X" });
  await tick(30);
  const nack = sent.slice(sn).find((m) => m.t === "paired_nack" && m.sessionId === "sess-X");
  check("a pairing for an unknown share is refused with share_not_found and what to do",
        nack && /^share_not_found: .*side panel/.test(nack.error), nack);
  // any tab in any window can be shared as it is: an app window too (no groups, no copies)
  const Pw = mkTab("https://pwa.example.com/app", { active: true, windowId: 7 });
  F.windowTypes[7] = "app";
  const rsw = await panel("share", { tabId: Pw.id });
  check("a page in an app window can be shared", rsw && rsw.ok, rsw);
  const pwReq = sent.filter((m) => m.t === "pair_request").pop().reqId;
  sn = sent.length;
  FakeWS.last.deliver({ t: "paired", reqId: pwReq, sessionId: "sess-PW", chatName: "Pwa" });
  await tick(60);
  check("...the tab itself becomes the chat's, with its pill, and the pairing succeeds",
        (await owner(Pw.id)) === "Pwa" && pillOn(Pw.id) === "Pwa" && sent.slice(sn).some((m) => m.t === "paired_ack" && m.sessionId === "sess-PW"), sent.slice(sn));
  r = await cmd("sess-PW", "get_page_text");
  check("...and the chat reads that tab", r.ok && r.data.tabId === Pw.id, r);

  // a code the relay still holds survives a reconnect; the chat can use it
  const K = mkTab("https://keep.example.com/", { active: true });
  await panel("share", { tabId: K.id });
  const keepReq = sent.filter((m) => m.t === "pair_request").pop().reqId;
  FakeWS.last.deliver({ t: "pair_code", reqId: keepReq, code: "KEEP2345", expiresIn: 300 });
  await tick(20);
  FakeWS.last.deliver({ t: "welcome", ok: true, sessions: Object.keys(await F.sw(`local.get("sessions", {})`)), reqIds: [keepReq] });
  await tick(60);
  check("a code the relay still holds is kept after a reconnect", !!(await F.sw(`local.get("shares", {})`))[keepReq]);
  // an extension reload wipes storage.session; shares and chats are in storage.local
  for (const k of Object.keys(F.sessionStore)) delete F.sessionStore[k];
  sn = sent.length;
  FakeWS.last.deliver({ t: "paired", reqId: keepReq, sessionId: "sess-K", chatName: "Keeper" });
  await tick(60);
  check("a code shown before an extension reload still pairs after it",
        sent.slice(sn).some((m) => m.t === "paired_ack" && m.sessionId === "sess-K") && (await owner(K.id)) === "Keeper",
        sent.slice(sn));
  r = await cmd("sess-K", "tabs_context");
  check("...and the chat works", r.ok && r.data.tabs.length === 1, r);

  const cp = mkTab("chrome://settings/", { active: true });
  const rs2 = await panel("share", { tabId: cp.id });
  check("chrome:// pages cannot be shared", rs2 && !rs2.ok && rs2.error === "not_shareable", rs2);

  // every relay start attempt leaves a timed record, even when the error text repeats
  chrome.runtime.sendNativeMessage = async () => { throw new Error("Specified native messaging host not found."); };
  await panel("start_relay");
  await panel("start_relay");
  const starts = (F.localStore.audit || []).filter((e) => e.action === "start relay");
  check("each failed relay start is logged with its error (2 attempts, 2 entries)",
        starts.length === 2 && starts.every((e) => e.outcome === "failed" && /not found/.test(e.detail)), starts);
  check("...and the saved error carries the time of the attempt", /^\S+.* Specified native/.test(F.localStore.relayStartError || ""), F.localStore.relayStartError);
  chrome.runtime.sendNativeMessage = async () => ({ ok: true, started: true, running: true });
  await panel("start_relay");
  check("a successful start clears the error and logs 'started'",
        F.localStore.relayStartError === "" && (F.localStore.audit || []).some((e) => e.action === "start relay" && e.detail === "started"), F.localStore.relayStartError);

  console.log(`\n${passes}/${passes + failures} passed`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error("CRASH", e); process.exit(2); });
