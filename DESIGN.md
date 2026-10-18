# Attach-on-redeem — design

Goal: when a chat that is already connected is handed a fresh pairing code,
redeeming the code attaches the code's tab to that chat's existing session.
Today the chat must first disconnect (killing its session, its tabs and its
site grants), then pair from scratch. After this change the same code, given
to the already-connected chat, simply adds the tab.

Worked in staging only: this directory is a copy of the merged fixed tree
(`security-review-2026-10-05/fixed/`). Nothing here is deployed.

## The current redemption flow, as the code implements it

### 1. Code issue (extension → relay)

- The user opens the side panel on a tab and clicks "Generate a code"
  (`sidepanel.js`: `send("share", { tabId })`).
- `sw.js startShare(tabId)` records
  `shares[reqId] = { tabId, host, title, code: "", created, expires }`
  (reqId = `crypto.randomUUID()`), cancels any earlier share for the same
  tab (`pair_cancel`), and sends `{t:"pair_request", reqId}` over the
  device WebSocket.
- `relay.py on_pair_request()` mints the code (8 chars, single use, 5 min
  TTL) and stores `codes[code] = {"deviceId", "reqId", "expires"}`; it
  replies `{t:"pair_code", reqId, code, expiresIn}`. The relay never learns
  which tab the code is for — the reqId → tab binding lives only in the
  extension.

### 2. Redemption (chat → relay)

- `client.py pair <CODE> --chat NAME` first reads its token file. If a token
  is there, it asks `GET /status`; if the token is live it refuses with
  `token_file_in_use` and never calls `/pair` at all. That refusal is the
  whole reason a connected chat cannot redeem a second code today.
- Otherwise it posts `POST /pair {code, chatName}` — loopback listener only
  (`/pair` on the tailnet listener answers `pair_local_only`).
- `relay.py pair()` normalises the code, checks it exists, is unexpired and
  not cancelled, waits up to `device_wait` for the device socket, then
  consumes the code and calls `complete_pair(deviceId, reqId, chatName)`.
- `complete_pair()` mints a **new** `sessionId` and a **new** token, stores
  `sessions[sessionId] = {deviceId, tokenHash, chatName, created, lastUsed}`
  (chat names are made unique per device), sends
  `{t:"paired", reqId, sessionId, chatName}` to the extension, and waits up
  to 10 s for `paired_ack` / `paired_nack` (`pair_acks`). A nack or timeout
  rolls the new session back out of state.
- `client.py` writes the returned token into its token file and prints
  `{ok, chat, sessionId, tokenFile}`.

### 3. The extension learns the tab belongs to a session

- `sw.js onPaired(msg)` validates the session id, then consumes the share:
  `shares[msg.reqId]` gives the tab and the host recorded at share time. It
  refuses (`paired_nack`, relay rolls the session back) when the share is
  gone (`share_not_found`), the tab was closed (`tab_closed`), or the tab
  moved to another host (`page_changed`).
- SEC-22: if `msg.sessionId` already exists locally it nacks with
  `session_exists` and changes nothing.
- Otherwise it creates
  `sessions[sessionId] = { chatName, tabs: {}, sites: { [host]: true }, created }`,
  calls `attachTab(sessionId, tab)`, and acks.

### 4. Tab ownership rules (existing, must not move)

- `attachTab(sessionId, tab)` is the only way a pairing gives a tab to a
  session. It **transfers**: the tab is removed from whichever session held
  it (stored state and the `memOwner` mirror, synchronously), the previous
  owner's work on the tab is cancelled (`cancelTabWork`), and if that was
  its last tab its tabless prompts are settled (`cancelIfNoTabs` /
  `cancelIfSessionEmpty`). One tab, at most one session — by transfer,
  never by sharing.
- Only a consumed share (a code the user generated on that tab in the
  panel) or the panel's own `add_tab` can move a tab into a session; a chat
  command cannot.

## The change

### relay/relay.py

- `POST /pair` accepts an optional `token` field in the body. The handler
  resolves it with `state.session_by_token()` **after** pruning expired
  sessions, exactly like `/cmd`. Loopback-only stays: the tailnet listener
  still refuses `/pair` outright, token or not.
- `pair(code, chat_name, token=None)`: code validation, device wait and
  code consumption are unchanged. Before creating anything it calls the new
  `attach_target(token, device_id)`:
  - no token, unknown token, or expired token → `None` → today's flow
    (`complete_pair`, new session) exactly;
  - token resolves to a session on a **different device** → the pair is
    refused with the new error `token_device_mismatch`. Falling through to
    a fresh session here would break per-chat isolation silently and
    strand the chat between two sessions; refusing sends the chat back to
    the user with a clear reason. The code is **not** consumed by a refused
    attach (see below), so the user can hand it to the right chat.
  - token resolves to a live session on the **same device** → attach path.
- Attach path (`complete_attach(rec, session)`): no new session, no new
  token, no name de-dup. It registers a `pair_acks` entry for the existing
  session id and sends the extension
  `{t:"paired", reqId, sessionId: <existing>, chatName: <existing>, attach: true}`,
  then waits for the ack exactly as `complete_pair` does. On nack/timeout
  **nothing is rolled back** — the session pre-exists and is not ours to
  delete; the pair simply fails with the extension's reason
  (`pair_rejected` + detail, same shape as today).
- When is the code consumed? Unchanged rule — inside `pair()`, once the
  device is present and the code re-validated, **before** either completion
  path runs. A failed ack therefore still burns the code, exactly as a
  nacked fresh pairing does today. A refused attach (device mismatch)
  returns **before** consumption: the code stays live for its rightful
  chat. Single-use is preserved: a code that reaches a completion path can
  never be redeemed twice.
- On a successful attach the relay touches the session (`lastUsed`) — an
  attach is use, and it must reset the 7-day idle expiry just as a command
  does.
- Response: the handler returns
  `{ok: true, attached: true, sessionId, chatName}` for the attach path —
  deliberately **no `token` field**: the redeeming chat already holds the
  token, and re-issuing it would put a session secret on the wire a second
  time for nothing. The fresh path's response is byte-identical to today.

### extension/sw.js — `onPaired`

- New early branch, before the SEC-22 duplicate check: if `msg.attach` is
  true **and** `sessions[msg.sessionId]` already exists locally, run the
  attach flow:
  - consume the share by `msg.reqId` and run the same three refusal checks
    (`share_not_found`, `tab_closed`, `page_changed`) → nack with the same
    reason strings, change nothing;
  - `attachTab(msg.sessionId, tab)` — the existing transfer machinery, so
    a tab owned by another session moves under the existing rules;
  - add the share's host to the session's `sites` (the code grants the
    tab's site, same as a fresh pairing does for its first tab);
  - audit `"tab added"` (the same action string the panel's `add_tab`
    uses), and `ack(true)`.
- If `msg.attach` is true but the session does **not** exist locally, fall
  through to the existing fresh-pairing code untouched. This is not an
  error case: the relay prunes sessions the browser forgot at hello, but a
  session the relay still holds while the extension lost it (e.g. storage
  cleared without a restart hello in between) heals by becoming a normal
  pairing under the relay's session id. The SEC-22 `session_exists` guard
  keeps applying to every non-attach `paired`, exactly as today.
- Race note: the attach branch runs inside the same `pairingNow`
  serialisation as the rest of `onPaired`, and the relay registers one
  `pair_acks` entry per redemption; two chats redeeming codes for the same
  session id concurrently is impossible (only the token holder can name
  that session, and it redeems one code at a time).

### agent/client.py — `pair`

- If the token file already holds a **live** token (`GET /status` ok), the
  client now redeems **with** that token: `POST /pair {code, chatName,
  token}` and, on an `attached` answer, leaves the token file byte-for-byte
  unchanged and prints
  `{ok: true, attached: true, chat, sessionId, tokenFile}`.
- If the relay answers without `attached` (the token died between the
  status check and the redemption — expired or pruned), the answer is a
  fresh pairing: the client writes the new token as it always has.
- `token_file_in_use` is kept, but only for `--force`-less pairing where
  the relay did **not** confirm the attach (e.g. the relay answered a fresh
  session for a different chat while this file holds a live token): in that
  case the client refuses to overwrite the live token, reports
  `token_file_in_use`, and first revokes the unasked-for fresh session with
  the token it was just issued, so neither side keeps an orphan. Rationale: the refusal's real protection was never
  "one pair per chat" — it is "never silently destroy a live session's only
  credential". The attach path cannot destroy it (no write happens). The
  one remaining silent-destroy case is a fresh token landing in a file that
  already holds a live one, so the refusal stays exactly there. `--force`
  keeps its current meaning: pair anyway and overwrite.
- Everything else in `pair` is unchanged: dead/absent token → plain
  `/pair`, token written, same output shape as today.

### sidepanel.js / sidepanel.html

- No change. The panel already offers "Generate a code" on any unshared
  tab, including while chats are connected (the share section is independent
  of the chats list), and the connected chat's row already reflects the new
  tab through the normal `state` refresh.

## Invariants check

- **Code single-use:** consumed in `pair()` before either completion path;
  the only non-consuming exits are validation failures (as today) and the
  new device-mismatch refusal, which happens before the completion paths
  and exists precisely so the code can still serve its own chat.
- **One tab, one session:** the extension side of an attach is the existing
  `attachTab` transfer — nothing new is written.
- **Only the user's manual share moves a tab:** an attach still requires a
  live share recorded by `startShare` for that exact tab and host; the
  token only chooses **which existing session** receives it.
- **Per-chat isolation:** the relay attaches only to the session the
  presented token itself resolves to; there is no way to name another
  session. The cross-session test proves token A cannot pull a tab into
  token B's session (it lands in A's, or the pair is refused).
- **No new authority:** `/pair` stays loopback-only; a token is required
  for the attach path and it is the same credential the chat already uses
  for `/cmd` and `/status`. Chat tokens remain stored only as SHA-256.

## Tests

- The three shipped suites, with the staging adaptations documented in
  `MERGE-REPORT.md` (venv python, default relay ports for the stack test,
  challenge + enroll-secret seeding in the harnesses, native-host stub).
  One stack-suite assertion encodes the behaviour this change replaces
  ("pairing into a folder that already holds a live token is refused"); it
  is updated in the staging copy to assert the attach outcome instead, and
  the `--token-file` companion check stays.
- New `tests/test_attach.py` (relay level, fake device): attach happy
  path; no new session created; code burned by a failed attach; code NOT
  burned by a device-mismatch refusal; cross-token isolation (A's token +
  code issued for B's flow attaches to A only); dead token falls back to a
  fresh pairing; attach to a session whose device is a different device is
  refused.
- New stack-level checks (in the adapted `test_stack.js`): the real
  extension attaches the second tab to the same session — both tabs answer
  under one token, `tabs_context` shows both, the token file is unchanged.
