# HISTORICAL DOCUMENT — v1 design, not the shipped system

> **This file is the design for the v1 product. It is kept for history
> only. It does not describe the system in this tree.**
>
> The v1 design below describes a Meta-hosted relay, 6-digit pairing
> codes, Chrome tab groups as the sandbox, and an allow / ask / never
> per-site policy. **None of that is what shipped.** The v2 system in
> this tree uses a local relay, 8-character pairing codes, per-chat
> tokens with per-chat tab lists (tab groups are not used), and a
> per-chat permitted-site set with panel prompts. The security model
> of the shipped system is described in `SECURITY.md` — read that
> instead. Do not rely on any claim in this file.

---

# Muse Browser Bridge — Design

## Problem

Muse agents run server-side. They cannot see or act inside the user's own
browser: no logged-in sessions, no SSO, no 2FA flows, no captchas, no intranet
apps, no WhatsApp Web, no store-admin panels. The cloud "managed browser" is
logged out by design, so entire classes of tasks die at the login screen.

Users keep hitting this wall on things that are trivially easy *in their own
browser* and impossible *from the background*.

## Solution

A first-party Chrome extension the user installs and pairs with their Muse
agent. The agent gains eyes and hands inside the user's real browser —
their tabs, their sessions — under a strict, user-controlled approval model.

## Architecture

```
User's Chrome (MV3 extension: service worker + content scripts)
        │  outbound WSS only — no inbound ports, no firewall/NAT config,
        │  works on any OS, reconnects after reboot/sleep
        ▼
Muse Relay (Meta-hosted): a dumb pipe
  - routes commands to the paired device, enforces rate limits
  - never stores page content; results pass through to the agent
        ▼
Muse agent runtime (skill: muse-browser-bridge)
```

Outbound websocket from the extension is the key choice: nothing to install
besides the extension, no localhost server to keep alive, no Tailscale.

## Pairing

1. User opens the extension popup → "Pair with Muse".
2. Relay issues a 6-digit code (5-minute TTL), shown in the popup.
3. User pastes the code to their agent in chat.
4. Agent presents the code to the relay; relay binds the extension's device
   key to the user's Muse identity and returns a device token.
5. Token lives in `chrome.storage.local`. Re-pair requires a fresh code.

Device identity is a per-install keypair (SubtleCrypto). The key is pinned
at the first hello: a later hello for the same device with a different key
is rejected, and a reconnect with the same key keeps its pairing (no reset).
The hello signature is self-signed over `deviceId:minute` — a ~2-minute
replay window, not a relay-issued challenge. No shared secrets in chat
beyond the one-time code.

## Protocol (JSON over WSS, v1)

- `hello {deviceId, pubJwk, sig}` → `welcome {ok}`. The relay verifies the
  ECDSA P-256 signature over `deviceId:minute`; stale (>~2 min) or bad
  signatures are rejected before any pairing can happen.
- `pair_request {}` → `pair_code {code, expiresIn}`.
- Agent → relay (HTTPS): `POST /pair {code}` binds the device. Rate-limited
  (10/min per IP); codes are 6-digit with 5-minute TTL.
- Agent → relay: `POST /cmd {deviceToken, action, args}` → relay pushes
  `cmd {id, action, args}` → extension runs it → `result {id, ok, data|error}`.
- Tier-2 actions: extension emits `approval_needed {id, action, summary}`,
  holds the command, and waits for the popup decision; 60s timeout = deny.
  **Approvals are accepted ONLY from the extension's own popup/notification
  (user gesture). The relay has no approval message the extension will honor
  — a compromised relay or agent cannot approve its own actions.**
- `heartbeat {tabs, version}` every 30s; relay exposes `GET /status`, which
  requires a paired device's token (`?token=`) — device IDs are not public.

## Tab access: Muse tab groups are the sandbox (not blanket access)

Pairing alone lets the agent see nothing. The agent can only touch tabs
inside the user's **Muse tab groups** — nothing else, ever. Each chat
session gets its own group: the default session uses "Muse", named
sessions use "Muse · <name>" (e.g. "Muse · House Hunt"). Pairing stays one
per browser (device trust); the session only selects which group a command
may touch.

Honest scope: these are **session labels**, not a security boundary. The
session name comes from the command args and every chat shares the same
device token, so a chat holding the token could pass another session's
name on purpose. What the labels do: stop one chat from acting in
another's group by accident — `list_tabs` and every action are scoped to
the command's session, and a tab bound to another session returns
`tab_not_shared` even if the caller guesses its id. A real boundary would
need a separate token per session, issued at pairing; that's a possible
later step if the user wants it.

A tab gets into a group exactly three ways: (a) the user drags it in (or
the popup's "Add to Muse group", the same gesture behind a button); (b) the
agent's `navigate`, but only when it lands on the host the user approved
(or a pre-approved `allow` host). Every tab-scoped action checks group
membership first: tabs outside the session's group return `tab_not_shared`.

So the user always knows which group the agent is controlling: the group
the agent is acting in turns **orange with a ● prefix** in the tab bar
(reverting to blue after 60s idle), and the popup lists every session's
group with the active one marked.

- The extension never moves a tab into the group on the agent's behalf:
  there is no agent-facing "group this tab" action, so the agent cannot
  pull the user's own tabs into its sandbox. Group membership is a
  user-driven grant, as legible as a shared folder.
- Dragging a tab OUT of the group revokes access instantly — and the tab
  visibly leaves the sandbox. Access also dies on tab close and on unpair
  (bindings are session-scoped in `chrome.storage.session`; the tabs
  themselves stay grouped, and re-pairing re-binds them).
- Each binding records an **approved host**. A grouped tab that navigates
  to a different host is ungrouped — it visibly leaves the sandbox —
  unless the new host is the approved host or its policy is `allow`, in
  which case the binding follows it. This is deliberately strict about
  host, not "site": a same-site redirect such as `example.com` →
  `www.example.com` ungroups the tab. (P18: the stress suite avoids
  testing on hosts that redirect this way.) There is no blank-host free pass for
  agent-added tabs: an approved `navigate` binds the approved host
  up-front, so a redirect to any other host ungroups the tab. (A
  *user-added* tab still on a blank page follows the user's own first
  navigation, since only the user can drive a URL into it.)
- New tabs and popups opened from a grouped page (target=_blank,
  middle-click, window.open) are treated as a navigation *from* the
  opener: they may stay only on the opener's approved host (or an `allow`
  host); anything else is ungrouped immediately and never enters the
  sandbox. Chrome auto-groups such children — the extension tracks the
  opener via `tabs.onCreated` so the user-drag rule can never claim them.
- The group's identity is its session-stored id, not its title. Any
  extension can title a group "Muse" and Chrome can restore saved groups,
  so a titled group is never auto-bound on boot — the popup asks the user
  to confirm it once ("Use this Muse group").
- `list_tabs` returns only grouped tabs. The popup lists every tab in the
  group with one-click remove; the toolbar badge shows the group-tab count.
- The approval prompt names the tab, the URL, and the target element
  (tag, visible text, label). `type` prompts show the text being typed
  (truncated to ~120 chars) — password fields show a character count only,
  and `fill_form` shows each field the same way. A clicked link's prompt
  shows the destination host. The approval carries an element fingerprint
  that is re-checked when the action runs: if the page re-rendered and the
  target changed, the action is refused (`target_changed`). After approval
  the extension also re-verifies the tab is still shared and still on the
  same host before acting (TOCTOU fail-closed).
- `screenshot` captures the grouped tab's own window (`captureVisibleTab`
  with the tab's `windowId`), never the last-focused window: the tab is
  activated within its window, verified as the visible tab, and only then
  captured — otherwise the call fails closed with `not_capturable`.
- Enter inside a form dispatches a cancellable keydown first and only
  calls `requestSubmit()` when the page didn't handle the key itself
  (no double-submit); the result reports whether the form actually
  validates (`submitted: form.checkValidity()`), not a blanket true.

## Action tiers

| Tier | Approval | Actions |
|------|----------|---------|
| 0 | none | `ping`, `status`, `list_tabs` (shared tabs only) |
| 1 | paired + tab in Muse group | `read_page` (password fields masked), `screenshot`, `scroll`, `wait_for`, `reload`, `go_back`, `go_forward`, `close_tabs`; `navigate` prompts unless the target host's policy is `allow` |
| 2 | per-action popup prompt, 60s default-deny | `click`, `double_click`, `right_click`, `hover`, `type`, `press_key`, `fill_form` |

Per-site policy in the popup: allow / ask / never. `never` blocks every
action on the host — including reads. The user can pre-approve trusted
sites (their store admin) and hard-block others (their bank).

Element targeting: `read_page` returns numbered `interactables`; actions
accept `ref:N` (preferred), `css:…`, or visible-text match where an exact
match always beats a substring ("Pay" never hits "PayPal"). Queries pierce
shadow DOM.

## Never exposed

- Cookie / token / session exfiltration — no such action exists.
- Password-field value readback. `type` may fill a password with approval,
  but its value is never returned to the agent.
- Silent keylogging, clipboard reads, or screenshots of tabs outside the
  Muse group.

## User controls

- Popup shows: pairing state, relay, tabs Muse can see (add to / remove
  from the Muse group), pending approvals, site policies, audit log.
- Every action lands in an audit log (last 200, exportable JSON).
- One-click **Unpair** wipes token and bindings; the agent gets `unpaired`.
  Tabs stay grouped (the user's organization is theirs); re-pairing
  re-binds them.
- The toolbar badge shows the Muse-group tab count while a session is live.

## Reference implementation (this repo)

- `extension/` — the full MV3 extension (this design, working code).
- `relay/server.py` — a local test relay implementing the same protocol,
  so the extension is testable end-to-end today without Meta infra.
- `agent/` — agent-side client + skill for driving the bridge.
- `PROPOSAL_TO_META.md` — the submission document.

## Rollout sketch

1. Dogfood: reference build on real machines (done here).
2. Chrome Web Store beta under Meta publisher; pairing via Muse account.
3. GA; per-site policies sync; E2E-encrypted command channel (v2).
4. Firefox port (same protocol).

## Non-goals (v1)

- Background / headless operation — the point is the *user's* browser.
- Mobile browsers. Cross-browser sync of policies.
- Trusted (OS-level) input via `chrome.debugger` / CDP: needed for Google
  Docs, canvas apps, and file pickers, but the debugger banner UX is a
  product decision for Meta. v1 uses synthetic events, which cover normal
  web apps; the gap is documented, not hidden.
- Arbitrary JS execution (`run_js`), console/network inspection: powerful
  for debugging, but each widens the trust surface the security model just
  narrowed. Revisit post-v1 with explicit user consent per invocation.
- Cross-frame (iframe) automation: content script covers the top frame;
  embedded payment/login iframes stay out of reach in v1.
