#!/usr/bin/env python3
"""Attach-on-redeem tests for relay/relay.py (new with the feature).

A chat that already holds a live token redeems a fresh pairing code WITH
that token: the code's tab must join the token's existing session — no new
session, no new token. A token must never attach a tab to another chat's
session, and a token for a different device's session refuses the pair
without consuming the code.

Runs the real relay as a subprocess with fake extension devices, same
harness style as test_relay.py.

  python test_attach.py       exit 0 = all passed, 1 = any failure
"""
import asyncio
import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import websockets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY = os.path.join(HERE, "..", "relay", "relay.py")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"), flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def b64u(n):
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


class Device:
    """Speaks the extension side of the protocol (challenge-aware hello)."""

    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.device_id = "dev-" + os.urandom(8).hex()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ws = None
        self.inbox = []
        self.handler = None
        self.ack_pairs = "paired_ack"  # or "paired_nack", or None

    def jwk(self):
        n = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64u(n.x), "y": b64u(n.y)}

    def sig(self):
        der = self.key.sign(f"{self.device_id}:{self.nonce}".encode(), ec.ECDSA(SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()

    async def connect(self):
        self.ws = await websockets.connect(self.ws_url + "/device")
        challenge = json.loads(await asyncio.wait_for(self.ws.recv(), 5))
        self.nonce = challenge.get("nonce")
        await self.ws.send(json.dumps({"t": "hello", "deviceId": self.device_id,
                                       "pubJwk": self.jwk(), "sig": self.sig(),
                                       "liveSessions": []}))
        return json.loads(await asyncio.wait_for(self.ws.recv(), 5))

    async def pump(self):
        try:
            async for raw in self.ws:
                m = json.loads(raw)
                if m.get("t") == "cmd" and self.handler:
                    await self.ws.send(json.dumps({"t": "result", "id": m["id"], **self.handler(m)}))
                else:
                    if m.get("t") == "paired" and self.ack_pairs:
                        await self.ws.send(json.dumps({"t": self.ack_pairs, "sessionId": m["sessionId"],
                                                       **({"error": "share_not_found: test"} if self.ack_pairs == "paired_nack" else {})}))
                    self.inbox.append(m)
        except websockets.exceptions.ConnectionClosed:
            pass

    async def wait_for(self, t, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            for m in self.inbox:
                if m.get("t") == t:
                    self.inbox.remove(m)
                    return m
            await asyncio.sleep(0.05)
        return None

    async def code(self, req_id):
        await self.ws.send(json.dumps({"t": "pair_request", "reqId": req_id}))
        pc = await self.wait_for("pair_code")
        return pc and pc["code"]


def http(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": "connection_failed", "detail": str(e)}


def start_relay(ws_port, http_port, state):
    p = subprocess.Popen([sys.executable, RELAY, "--ws-port", str(ws_port), "--http-port", str(http_port),
                          "--state", state, "--device-wait", "1"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    end = time.time() + 10
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", http_port), 0.3).close()
            return p
        except OSError:
            if p.poll() is not None:
                break
            time.sleep(0.1)
    return p


async def ah(*a, **k):
    return await asyncio.to_thread(http, *a, **k)


def session_count(state):
    return len(json.load(open(state))["sessions"])


async def main():
    tmp = tempfile.mkdtemp()
    state = os.path.join(tmp, "state.json")
    wsp, hp = free_port(), free_port()
    relay = start_relay(wsp, hp, state)
    WS, H = f"ws://127.0.0.1:{wsp}", f"http://127.0.0.1:{hp}"
    try:
        d1 = Device(WS)
        w = await d1.connect()
        check("device 1 hello accepted", w.get("ok") is True, w)
        pump1 = asyncio.create_task(d1.pump())
        d1.handler = lambda m: {"ok": True, "data": m["sessionId"]}

        # two chats pair fresh on device 1
        code_a = await d1.code("ra")
        st, b = await ah("POST", H + "/pair", {"code": code_a, "chatName": "Chat A"})
        tokA, sidA = b.get("token"), b.get("sessionId")
        await d1.wait_for("paired")
        check("chat A pairs fresh", st == 200 and tokA and sidA, (st, b))
        code_b = await d1.code("rb")
        st, b = await ah("POST", H + "/pair", {"code": code_b, "chatName": "Chat B"})
        tokB, sidB = b.get("token"), b.get("sessionId")
        await d1.wait_for("paired")
        check("chat B pairs fresh, different session", st == 200 and sidB and sidB != sidA, (st, b))
        check("two sessions in state", session_count(state) == 2, session_count(state))

        # --- attach happy path ---
        code3 = await d1.code("r3")
        st, b = await ah("POST", H + "/pair", {"code": code3, "chatName": "Ignored Name", "token": tokA})
        check("redeem with a live token attaches (attached: true, same session, session's own name)",
              st == 200 and b.get("attached") is True and b.get("sessionId") == sidA and b.get("chatName") == "Chat A", (st, b))
        check("the attach answer carries NO token", "token" not in b, b)
        paired = await d1.wait_for("paired")
        check("the device was told: paired, attach: true, the EXISTING session id, this code's reqId",
              paired and paired.get("attach") is True and paired.get("sessionId") == sidA and paired.get("reqId") == "r3", paired)
        check("no new session was created", session_count(state) == 2, session_count(state))
        st, b = await ah("POST", H + "/cmd", {"token": tokA, "action": "tabs_context", "args": {}})
        check("the token still routes after the attach", b.get("data") == sidA, b)

        # --- a token only ever attaches to its OWN session ---
        code4 = await d1.code("r4")
        st, b = await ah("POST", H + "/pair", {"code": code4, "chatName": "Chat A", "token": tokB})
        check("token B attaches to session B, never to A's (isolation)",
              st == 200 and b.get("attached") is True and b.get("sessionId") == sidB, (st, b))
        paired = await d1.wait_for("paired")
        check("...and the device heard session B's id", paired and paired.get("sessionId") == sidB, paired)

        # --- a nacked attach: code is burned, the session is NOT rolled back ---
        d1.ack_pairs = "paired_nack"
        code5 = await d1.code("r5")
        st, b = await ah("POST", H + "/pair", {"code": code5, "chatName": "Chat A", "token": tokA})
        check("an attach the extension refuses returns pair_rejected with its reason",
              st == 400 and b.get("error") == "pair_rejected" and "share_not_found" in (b.get("detail") or ""), (st, b))
        await d1.wait_for("paired")
        d1.ack_pairs = "paired_ack"
        st, b = await ah("POST", H + "/cmd", {"token": tokA, "action": "tabs_context", "args": {}})
        check("the session survives a refused attach (no rollback of a pre-existing session)",
              b.get("data") == sidA, b)
        st, b = await ah("POST", H + "/pair", {"code": code5, "chatName": "Chat A"})
        check("the refused attach still consumed the code (single use)", st == 400 and b.get("error") == "bad_or_expired_code", (st, b))

        # --- token for a different device's session: refused, code kept ---
        d2 = Device(WS)
        w = await d2.connect()
        check("device 2 hello accepted", w.get("ok") is True, w)
        pump2 = asyncio.create_task(d2.pump())
        code6 = await d2.code("r6")
        st, b = await ah("POST", H + "/pair", {"code": code6, "chatName": "Chat A", "token": tokA})
        check("a code from device 2 redeemed with device 1's token is refused (token_device_mismatch)",
              st == 400 and b.get("error") == "token_device_mismatch", (st, b))
        st, b = await ah("POST", H + "/pair", {"code": code6, "chatName": "Device 2 chat"})
        check("...and the code was NOT consumed: it still pairs its own device fresh",
              st == 200 and b.get("token") and b.get("sessionId") not in (sidA, sidB), (st, b))
        await d2.wait_for("paired")

        # --- a dead token falls back to a fresh pairing, exactly as before ---
        code7 = await d1.code("r7")
        st, b = await ah("POST", H + "/pair", {"code": code7, "chatName": "Chat C",
                                               "token": "dead-token-that-names-nothing-0000000000"})
        check("an unknown token is ignored: fresh session, fresh token, no attached flag",
              st == 200 and b.get("token") and b.get("sessionId") not in (sidA, sidB) and "attached" not in b, (st, b))
        await d1.wait_for("paired")

        pump1.cancel()
        pump2.cancel()
        await d1.ws.close()
        await d2.ws.close()
    finally:
        relay.terminate()

    # --- unit level: expired sessions and device match in attach_target ---
    spec = importlib.util.spec_from_file_location("relay_mod", RELAY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    st_obj = mod.State(os.path.join(tmp, "unit-state.json"))
    import hashlib
    live_tok, dead_tok = "l" * 43, "d" * 43
    now = int(time.time())
    st_obj.sessions["sid-live"] = {"deviceId": "dev-1", "tokenHash": hashlib.sha256(live_tok.encode()).hexdigest(),
                                   "chatName": "Live", "created": now, "lastUsed": now}
    st_obj.sessions["sid-old"] = {"deviceId": "dev-1", "tokenHash": hashlib.sha256(dead_tok.encode()).hexdigest(),
                                  "chatName": "Old", "created": now - mod.SESSION_TTL - 10, "lastUsed": now - mod.SESSION_TTL - 10}
    r = mod.Relay(st_obj)
    t, m = r.attach_target(live_tok, "dev-1")
    check("unit: a live token on the same device is an attach target", t and t["sessionId"] == "sid-live" and m is False, (t, m))
    t, m = r.attach_target(live_tok, "dev-2")
    check("unit: the same token against another device is a mismatch", t is None and m is True, (t, m))
    t, m = r.attach_target(dead_tok, "dev-1")
    check("unit: an expired session's token is no target (fresh pairing follows)", t is None and m is False, (t, m))
    t, m = r.attach_target(None, "dev-1")
    check("unit: no token, no target", t is None and m is False, (t, m))

    fails = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(fails)}/{len(results)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
