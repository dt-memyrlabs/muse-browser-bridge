# Muse Browser Bridge v2 — Security Model

This document describes the security model of the v2 system in this
tree (extension version 2.3.5), as fixed in the October 2026 security
review pass. Every statement here can be checked against the code:
`relay/relay.py`, `extension/sw.js`, `extension/policy.js`,
`extension/manifest.json`, `native/relay_host.py`, and
`agent/client.py`.

`DESIGN-v1.md` is the earlier v1 design. It describes a different
system (a hosted relay, tab groups, an allow / ask / never policy)
that was never shipped. Do not use it to judge this code.

## What the system is

Three parts, all on the user's own machine:

- A Chrome extension (`extension/`) that holds the user's tabs and
  acts in them with real input through `chrome.debugger`.
- A local relay (`relay/relay.py`, Python) that routes commands
  between chats and the extension. The extension side is a WebSocket
  on `ws://127.0.0.1:19822`; the chat side is HTTP on
  `http://127.0.0.1:20822`.
- A chat-side client (`agent/client.py`) that a Muse chat runs to
  pair and to send commands.

By default the relay also opens a second chat-side HTTP listener on
the machine's Tailscale address when one is found (`--bind auto`).
`--bind off` gives a loopback-only relay. The second listener may
only bind a loopback address or an address in the Tailscale range
100.64.0.0/10; any other explicit `--bind` value (including
`0.0.0.0`, a LAN address, or a public address) makes the relay
refuse to start. Pairing (`POST /pair`) is refused on the second
listener: pairing is a local act.

Neither listener uses TLS. The device WebSocket is plain `ws://` and
the chat API is plain HTTP, on loopback and on the Tailscale
address alike. The protection on the wire is the transport itself:
loopback, or the user's own tailnet. Do not expose either listener
any other way.

The relay's `/fixture/` test pages are test scaffolding. They are
served only when the relay is started with `--fixtures`; by default
the route answers 404 on both listeners.

## The trust boundary, stated plainly

**Any program running as you, on your machine, is inside the
boundary. This system does not defend against it.**

Concretely, a program running under your user account can read the
chat token files, the relay's `state.json`, and the enrollment
secret file; it can call the relay's local API itself; and it can
read the extension's stored device key from your browser profile.
The controls in this document divide up access between *chats*,
between *sites*, and between *actions that ask and actions that do
not*. They do not create a boundary between you and software that
already runs as you. If that is not an acceptable posture, do not
install this bridge.

Two narrower boundaries do exist against weaker attackers:

- A web page cannot use the bridge. The relay accepts a device
  WebSocket connection only with no `Origin` header or a
  `chrome-extension://` origin. The chat HTTP API rejects any
  request whose `Host` header does not name the listener's own
  address (or `localhost` on the loopback listener), and rejects
  any request that carries an `Origin` header — a browser page
  sends one on every POST, the local client sends none.
- A device cannot enroll with the relay just by connecting, when
  the relay is started the shipped way (see "Device identity"
  below).

## What installing the extension means

The manifest asks for `<all_urls>` host access and the `tabs`,
`storage`, `alarms`, `sidePanel`, `notifications`, `debugger`,
`clipboardWrite`, `nativeMessaging`, and `scripting` permissions,
all of them mandatory. There is no reduced-permission mode.

That means the extension itself can, at the browser level, reach
every page in the profile it is installed in, and drive it with
trusted input via `chrome.debugger`. The per-chat limits described
below — which tabs a chat may touch, which sites it may use, which
actions ask first — are policy enforced by the extension's own
JavaScript (`extension/sw.js` and `extension/policy.js`). They are
not a browser sandbox. Chrome does not confine the extension to
the shared tabs; the extension confines itself, and a bug in that
code is a bug in the boundary. Install this extension only in a
browser profile whose full contents you are willing to place
behind that code.

Two narrowings are structural, not just policy:

- The manifest requests no `cookies` permission, and no tool
  returns cookies, browsing history, or stored browser passwords
  to a chat.
- The worker's CDP dispatcher (`cdp()` in `sw.js`) allow-lists the
  20 DevTools methods its own call sites use and refuses any
  other. `Runtime.evaluate` is not on the list. There is no tool
  that runs chat-supplied JavaScript; the only code the worker
  runs in a page is its own fixed functions — the page probe, the
  pill, and small fixed helpers for scrolling and setting fields —
  in an isolated world that page scripts cannot modify.

## Pairing and per-chat tokens

Pairing is by code only. There is no code-free pairing path.

1. In the side panel, the user clicks "Share this page with a Muse
   chat". The extension asks the relay for a code for that tab.
2. The relay issues an 8-character code from a 31-symbol alphabet
   with no look-alike characters. A code lives for 5 minutes, is
   used at most once, and stops working if the user cancels or
   replaces the share in the panel (a cancelled code is refused
   with `bad_or_expired_code` and consumed). Failed pairing
   attempts are braked globally at 30 per minute; a device may
   hold at most 10 open codes and request at most 20 codes per
   minute; the relay remembers at most 50 devices.
3. The user gives the code to one chat. The chat calls
   `POST /pair` on the loopback listener with the code and a chat
   name.
4. The relay creates a session: a random session id and a chat
   token of 32 random bytes. It sends a `paired` message to the
   extension, and reports success to the chat only after the
   extension acknowledges that it recorded the session with the
   shared tab attached. If the acknowledgement does not arrive
   within 10 seconds, the session is rolled back.
5. The token is returned to the chat once, in the `/pair` response.
   The relay stores only its SHA-256 hash (in `state.json`) and
   never logs tokens or codes. The chat's client saves the token
   to its token file (see "Storage").

Each chat gets its own token and its own session. The extension
never sees chat tokens; it knows sessions by id. A token names
exactly one session: every `/cmd` and `/status` call is resolved
from the token's hash, and the extension checks, for every
command, that the tab named belongs to that session and that the
tab's site is permitted for that session. A second `paired`
message for a session id the extension already holds is refused
(`paired_nack`) instead of resetting the live session.

The shared tab's site is permitted for that chat by the act of
sharing it. Sharing grants the tab's whole host (hostname plus
port, as `hostOf` computes it) for the life of the session, unless
the user removes it sooner (see "Ending access").

## Device identity and enrollment

The extension generates an ECDSA P-256 keypair on first run and
stores it in `chrome.storage.local` (the private key as a JWK, in
plaintext — see "Known limits"). The relay pins the public key the
first time a device says hello; a later hello for the same device
id with a different key is refused (`key_mismatch`).

Hello is not replayable. On each WebSocket connection the relay
first sends a fresh random challenge nonce. The hello must sign
`deviceId + ":" + nonce` with the device key; a captured hello
cannot be reused on another connection.

Enrollment is additionally gated when the relay is started with
`--enroll-secret-file`, which is how the native-messaging host
(`native/relay_host.py`) starts it. The host creates a per-install
secret file next to the relay state (a cryptographic random value,
if absent) and hands the secret itself to the extension in its
native-messaging start answer; the worker stores it in
`chrome.storage.local`. The hello must then also carry
`proof = hex HMAC-SHA256(secret, deviceId + ":" + nonce)`. A hello
with no proof, a proof made with the wrong secret, or a proof
replayed against a fresh nonce is refused. The secret never
crosses the WebSocket and is never logged. A relay started by hand
without `--enroll-secret-file` does not enforce this gate — that
is a weaker posture, and it is the operator's choice, not the
default path.

## What a connected chat can see

A chat can only ever name its own tabs. A command against another
chat's tab, or any tab that was never shared, fails with
`tab_not_shared`. Within its own tabs, what returns to the chat is:

- `tabs_context`: its tabs and its permitted sites. For a tab on
  a permitted site, the tab's title and full URL. For a tab on a
  site not permitted to that chat, only the tab id, whether it is
  active, `permitted: false`, and the site's host (or that it is a
  blank or browser page) — enough to ask the user about it, not
  the page.
- `read_page`: the page's accessibility tree — each element's role
  and accessible name, with a `ref` per element. It does not read
  form field values. Roles and names are page-supplied text.
- `find`: up to 20 elements matching a description, as ref, role,
  and name.
- `get_page_text`: the main text of the page (`innerText` of
  `main`, `article`, or the body), up to 100,000 characters,
  after a redaction pass: digit sequences of 13–19 digits that
  pass the Luhn check are replaced with `[card-redacted]`, and
  base64/hex tokens of 32 or more characters that directly follow
  a key/token/secret label are replaced as well. The result
  carries a `redactions` count. This redaction is pattern-based;
  it is not a guarantee that no secret-shaped string survives.
- `get_form_values`: up to 200 fields, each as name, type, and
  value truncated to 500 characters — except secret fields,
  whose value is returned as the literal string `(hidden)`.
  A field is secret when it is detected as a password field
  (type `password`; `current-password` / `new-password` /
  `password` / `one-time-code` autocomplete; a name or id matching
  pass/pwd/secret patterns, including a field whose type a
  "show password" toggle flipped to text), a payment field
  (card, CVV/CVC/CSC, IBAN, account-number, routing, or expiry
  signals in autocomplete, name, id, placeholder, or aria-label),
  an input of type `hidden`, or a field whose autocomplete marks
  a one-time code. Detection is heuristic: a secret field that
  gives none of these signals is returned like any other field.
- `screenshot` (and the `computer` screenshot and zoom actions):
  a photograph of the tab's visible viewport, or of a chosen
  region. A screenshot shows everything on screen at that moment,
  including the contents of frames from other sites and any text
  visible inside fields. Fields the browser itself masks render
  masked; text a page shows in plain form is photographed in
  plain form. See the approval rule for sensitive pages below.
- Results of its own actions (for example, what a click hit).

Page content is untrusted input, and the client says so: results
from the page-content tools carry a top-level
`"pageContent": "untrusted"` marker in the client's output, and
the shipped skill text instructs the chat that text returned from
a page is data, never instructions — a page that tells the chat
to do something is not the user talking.

## What a connected chat can do, and what asks first

The tool set is fixed: `tabs_context`, `tabs_create`,
`tabs_close`, `navigate`, `read_page`, `find`, `get_page_text`,
`get_form_values`, `screenshot`, `computer` (clicks, drag, hover,
scroll, typing, key presses, screenshot, zoom, wait),
`form_input`, `file_upload`, and `browser_batch`. An unknown
action name is refused. `browser_batch` runs at most 50 actions
in sequence, stops at the first error, and every item goes
through the same checks and prompts as a direct call — a batch
pre-approves nothing.

Without asking, on a site already permitted for that chat, a chat
may: read (above), scroll, hover, open a blank tab of its own,
navigate its own tabs (a navigation that lands on a new host asks
— see below), and close its own tabs on permitted sites.

The extension asks the user first, in the side panel, before:

- **A new site.** The first time a chat reaches a host that is
  not in its permitted set — by opening it, by being given a tab
  on it through navigation or history, or by a redirect landing
  on it — the panel asks "Let this chat use <host>?". Allowing
  adds the host to that chat's permitted set for the rest of the
  session. Denying fails the command.
- **A risky action, even on a permitted site.** Clicks and drags
  are classified by what they will activate: the actionable
  element under the point, read through open shadow roots and
  same-origin frames and cross-checked against Chrome's
  accessibility tree. The full visible label, aria-label, and
  enclosing button text are normalised (zero-width characters
  stripped, look-alike Cyrillic/Greek letters folded to ASCII,
  whitespace collapsed) and matched on token boundaries against a
  word list for pay / buy / order / send / transfer / delete and
  similar acts, in several languages. A submit of a form that
  contains a password or payment field asks even when the button
  label is generic, and so does an unlabeled control inside such
  a form. Anything inside a frame from another site always asks,
  because the extension cannot see what it is. A control that
  reveals a hidden password asks.
- **Keyboard activation.** Pressing Enter or Space when the
  focused element classifies as a risky target asks the same as
  a click. Enter that would submit a form with a password or
  payment field, or a risky submit, asks. Ordinary keys in
  ordinary fields do not ask.
- **Typing into a secret or unseen field.** Typing into a
  password field or a payment field asks, with the text shown to
  the user only as a character count. Typing when the extension
  cannot see which field has focus — including focus inside a
  cross-origin frame — asks the same way. Pasting from the
  clipboard always asks.
- **`form_input` in a sensitive context.** Filling a payment
  field asks; filling any field whose form contains a password
  or payment field asks; filling a field whose form's submit is
  classified risky asks. The prompt shows the field's label and,
  for non-secret fields, the value about to be filled. Password
  and payment values are shown only as a character count — in
  the prompt and in the audit log. Other fields fill without
  asking.
- **Screenshots of sensitive pages.** If the page contains a
  password field or a payment field (same detection as above,
  on the top document), capture waits for approval. Pages
  without such fields capture without asking.
- **`file_upload`. Always.** The prompt shows each file's full
  path and its size, and uploads to the named host. The size is
  the size the caller supplies with the call; the worker cannot
  stat local files, so an unsupplied size is shown as
  "size unknown" rather than invented. Some paths are refused
  outright, before any prompt: anything inside a `.muse-bridge`
  directory, any file named `.muse-bridge-token` (including its
  sidecar files), anything inside a `.ssh` directory, and
  browser profile directories. In particular, a chat cannot
  upload its own token file, even with the user's click.
- **Closing a tab on a site the chat was not given.**

Prompts show the chat's name, the action, the target element's
description (tag, label, and destination host for a link), the
site host, and for site grants the host being granted. A prompt
waits at most 60 seconds. No answer is a No.

New tabs a page opens (popups, `target=_blank`) join the opening
chat only when the opener is that chat's tab and the new tab's
initial host equals the opener tab's host. Anything else stays
unshared until the user shares it. Even an auto-attached tab
grants no site: a new host still asks.

## How approvals work

Approvals exist only in the extension's own user interface.

- The relay has no message that approves an action, grants a
  site, or sets a policy, and the extension would not honour
  one. A compromised relay or a chat cannot approve its own
  actions.
- The worker accepts panel messages — including `approve` and
  `deny` — only from its own extension pages: the sender must be
  this extension, and the sender's URL must be one of the
  extension's own page URLs. Web pages get `forbidden`. The one
  other page message is the pill's `pill_remove`, which can only
  unshare the tab it was sent from.
- Clicking a prompt's notification only opens the side panel.
  The decision itself is a click on Allow or Deny in the panel.
- Prompts fail closed. Timeout, the session ending, the tab being
  removed or transferred, or the command's deadline passing all
  settle a pending prompt as a refusal, and an action cancelled
  this way delivers a cancellation to the chat, not data.
- After an approval, the extension re-reads the target (or the
  focused element) and compares its fingerprint with the one the
  user approved, and re-checks that the tab is still this chat's
  and still on the same host. If anything changed, the action is
  refused with `target_changed` and nothing is dispatched.
- Every command carries a deadline (the relay's command timeout
  is 120 seconds). When the relay gives up, it tells the
  extension to cancel, and the extension checks the deadline
  before acting and after every prompt, so nothing acts after
  the chat was told "timeout".

## Sessions: lifetime, expiry, and ending access

- A session ends at once when: the user clicks Disconnect for
  that chat in the panel; the chat disconnects itself
  (`POST /revoke`); the user presses Cancel on Chrome's "being
  debugged" bar for one of its tabs; or the relay learns on a
  later hello that the extension no longer holds the session.
  Ending a session removes its pills, detaches the debugger from
  its tabs, settles its pending prompts as refusals, and cancels
  its in-flight commands.
- A session also expires after **7 days without a command**.
  The relay records a `lastUsed` time per session, updated on
  every `/cmd` and `/status`, prunes expired sessions when a
  device says hello and before answering `/cmd`, and an expired
  token answers `bad_token`. The extension drops its side when
  the relay's `revoked` notice (or the hello reconciliation)
  reaches it.
- Removing one tab (the pill's ✕, or Remove in the panel) ends
  that chat's access to that tab only, and cancels any prompt or
  in-flight command tied to that tab.
- Removing one site (the ✕ beside a permitted site under the
  chat in the panel) removes that host from the chat's permitted
  set. The chat keeps its tabs, but the next command touching
  that host must ask for the site again.
- A browser restart keeps sessions and their permitted sites,
  but clears tab ownership: stored tab ids are not trusted after
  a restart (Chrome reassigns them), so a chat starts with no
  tabs and the user gives them again from the panel.

## Storage and logs

- Relay state (`state.json`, next to `relay.py` unless `--state`
  says otherwise): pinned device public keys, and per session the
  device id, chat name, creation and last-used times, and the
  SHA-256 hash of the chat token. Plaintext tokens are never
  stored relay-side. The file is written atomically.
- Extension storage (`chrome.storage.local`): the device
  identity (including the private key, in plaintext), the
  enrollment secret, sessions with their tab/host lists and
  permitted sites, pending share records, and the audit log.
- Audit log: the extension keeps the last 300 entries locally and
  the panel shows the most recent 40 as "Recent activity". An
  entry records the time, chat name, action, a short detail, and
  the outcome. Prompt decisions are recorded. Actions record the
  target description and host — secret values only as a
  character count. Reads are recorded too: `read_page`, `find`,
  `get_page_text`, `get_form_values`, and screenshots each write
  one entry with the chat, tool, host, and result size only —
  never field values, page text, or image data. Failed reads
  write no entry. The audit log lives on the same machine, under
  the same trust boundary as everything else here: it is a
  record for the user, not a tamper-proof log.
- Relay console log: one line per command — session prefix,
  action, and ok or the error code. It never logs arguments,
  page content, codes, or tokens.
- Chat-side files, next to the chat's token file: the token file
  itself (`.muse-bridge-token` by default; the client writes it
  asking for owner-only permissions, mode 0600), screenshots in
  `mbb-shots/` (files older than 24 hours are deleted on each
  client run), and oversized command results in `mbb-output/`,
  which are kept until the user deletes them. Tool arguments may
  be passed to the client on stdin instead of the command line,
  so typed secrets need not appear in the process list.

## Known limits

Read these as part of the model, not as footnotes.

1. **Local programs are trusted.** Restated from the boundary
   section because everything else depends on it: software
   running as you can read the token files, `state.json`, the
   enrollment secret, and the device key, and can drive the
   relay directly. The enrollment gate stops a program that
   cannot read the secret file; a same-user program can read
   it. Whoever can *write* `state.json` can mint a session or
   replace a pinned device key.
2. **A copied token is the chat.** Anyone holding a chat's token
   can act as that chat from anywhere the relay is reachable —
   which includes the Tailscale listener, where `/cmd` is
   accepted (only `/pair` is refused there). The per-chat
   boundary holds only as long as token files stay separate.
   Chats run in the same user account, typically with shell and
   file access: a chat that reads another chat's token file can
   act in that chat's tabs. The relay and extension enforce
   scope per token; nothing enforces it per file.
3. **Plaintext local transport.** Loopback traffic is HTTP and
   WebSocket without TLS, and so is the Tailscale listener. On
   the tailnet, protection is the tailnet itself; the relay does
   not check a tailnet identity.
4. **Detection is heuristic.** Password, payment, and risky-label
   classification read names, labels, autocomplete values, and
   visible text. A page can build a secret field or a dangerous
   button that gives none of the signals, and then the matching
   mask or prompt does not fire. Closed shadow roots and
   cross-origin frames are blind spots: when the extension
   detects them it asks, but detection itself is best-effort.
5. **Screenshots see what the screen shows.** Including
   cross-origin frames and plainly visible field contents. The
   sensitive-page prompt checks the top document's fields; a
   payment frame embedded from another site is not itself
   detected.
6. **Redaction is pattern-based.** `get_page_text` redacts
   Luhn-valid card numbers and labelled long tokens. Other
   secret formats pass through.
7. **Site grants are whole-host and session-long.** Allowing a
   host allows that host (every path, and that port) for that
   chat until the session ends, the site is removed in the
   panel, or the session expires. There is no per-action site
   policy and no "never" list: a site the user never allows can
   be asked about again by a later command, and protection
   against a specific site is to keep denying, or disconnect.
8. **The user is the last gate.** An Allow click authorises the
   action as described. Prompts reduce risk; they do not make
   an approved action safe, and a user who approves everything
   has the bridge's full power with none of its friction.
9. **The device key has no rotation path.** It is stored in
   plaintext in the browser profile, and there is no panel
   control to rotate or revoke it. Compromise of the profile is
   compromise of the device identity; uninstalling the extension
   discards it.
10. **Prompts are per action, attention is finite.** Busy pages
    can produce many prompts. `browser_batch` does not bypass
    prompts, but it can queue up to 50 gated actions in one
    call, each asking in turn.

## Reporting a problem

This is an independent open-source project that works with Muse
chats; it is not a Meta or Anthropic product. Report security
issues to the project maintainers through the repository's
security contact, with the file and function your report is
about. Claims in this document are meant to be checkable — if
you find one the code contradicts, that is a bug in this
document or in the code, and either way it should be reported.
