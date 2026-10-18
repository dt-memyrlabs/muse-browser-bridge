#!/usr/bin/env python3
"""Muse Browser Bridge — native messaging host.

Chrome runs this when the extension calls
chrome.runtime.sendNativeMessage("com.memyr.muse_bridge", {cmd: "start"}).
It starts relay/relay.py hidden if the relay's ports are not open yet,
answers with one message, and exits. The relay keeps running on its own.
This is the standard native-messaging mechanism for local helpers.

Protocol: each message is a 4-byte little-endian length, then UTF-8 JSON.
"""
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_DIR = os.path.join(os.path.dirname(HERE), "relay")
PORTS = (19822, 20822)  # extension side, chat side
# The enrollment secret lives next to the relay's state file (relay.py's
# default --state is RELAY_DIR/state.json). Only this host and the relay
# read it; the extension learns it from this host's start answer and proves
# knowledge of it in its hello, so a random local program cannot enroll a
# device with the relay.
ENROLL_SECRET_PATH = os.path.join(RELAY_DIR, "enroll_secret.txt")

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    n = struct.unpack("<I", raw)[0]
    if n > 1_000_000:
        return None
    try:
        return json.loads(sys.stdin.buffer.read(n) or b"{}")
    except ValueError:
        return None


def send_message(obj):
    body = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(body)) + body)
    sys.stdout.buffer.flush()


def port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), 0.3).close()
        return True
    except OSError:
        return False


def _valid_enroll_secret(value):
    """Only the format this host generates counts as an existing secret:
    64 hex chars (secrets.token_hex(32)). Anything else in the file --
    empty, whitespace-only, a short string, a planted known value -- is
    not a secret this install generated, so it is replaced, not trusted:
    a 1-char or attacker-known "secret" would make the hello proof
    trivially forgeable."""
    return isinstance(value, str) and len(value) == 64 and \
        all(c in "0123456789abcdefABCDEF" for c in value)


def _protect_enroll_secret_file():
    try:
        os.chmod(ENROLL_SECRET_PATH, 0o600)
    except OSError:
        pass


def ensure_enroll_secret():
    """Read the enrollment secret, creating it (cryptographic random) if
    the file is absent or does not hold a valid generated secret.
    Returns the secret string; the returned value is always the file's
    content afterwards, so repeated calls are stable."""
    try:
        with open(ENROLL_SECRET_PATH, encoding="utf-8") as f:
            existing = f.read().strip()
        if _valid_enroll_secret(existing):
            _protect_enroll_secret_file()
            return existing
    except (OSError, UnicodeError):
        existing = None
    secret = secrets.token_hex(32)
    try:
        # "x" so two hosts racing at first install cannot overwrite each
        # other: the loser re-reads the winner's value instead.
        with open(ENROLL_SECRET_PATH, "x", encoding="utf-8") as f:
            f.write(secret + "\n")
        _protect_enroll_secret_file()
        return secret
    except FileExistsError:
        pass
    # The file exists but held no valid secret (empty / whitespace /
    # planted): overwrite it. The old code fell through this branch and
    # returned a fresh random value WITHOUT writing it, so every call
    # returned a different secret and the file stayed empty.
    try:
        with open(ENROLL_SECRET_PATH, "w", encoding="utf-8") as f:
            f.write(secret + "\n")
        _protect_enroll_secret_file()
    except OSError:
        return secret
    # Prefer what is on disk now: a racing host may have written its own.
    try:
        with open(ENROLL_SECRET_PATH, encoding="utf-8") as f:
            on_disk = f.read().strip()
        if _valid_enroll_secret(on_disk):
            return on_disk
    except (OSError, UnicodeError):
        pass
    return secret


def start_relay():
    # The secret is read or created whether or not the relay is already
    # running: the extension needs it in this answer either way.
    enroll_secret = ensure_enroll_secret()
    if all(port_open(p) for p in PORTS):
        return {"ok": True, "started": False, "running": True, "enrollSecret": enroll_secret}
    exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(exe):
        exe = sys.executable
    out = open(os.path.join(RELAY_DIR, "relay_out.txt"), "ab")
    err = open(os.path.join(RELAY_DIR, "relay_err.txt"), "ab")
    args = [exe, os.path.join(RELAY_DIR, "relay.py"),
            "--enroll-secret-file", ENROLL_SECRET_PATH]
    if sys.platform == "win32":
        try:
            # Leave Chrome's job object if there is one, so the relay outlives this host.
            subprocess.Popen(args, cwd=RELAY_DIR, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True,
                             creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        except OSError:
            subprocess.Popen(args, cwd=RELAY_DIR, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True,
                             creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
    else:
        # creationflags is Windows-only (it raises ValueError on POSIX);
        # start a new session so the relay outlives this host there.
        subprocess.Popen(args, cwd=RELAY_DIR, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True,
                         start_new_session=True)
    for _ in range(60):
        if all(port_open(p) for p in PORTS):
            return {"ok": True, "started": True, "running": True, "enrollSecret": enroll_secret}
        time.sleep(0.1)
    return {"ok": False, "started": True, "running": False, "enrollSecret": enroll_secret,
            "error": "the relay did not open its ports within 6 s; see relay/relay_err.txt"}


def main():
    msg = read_message() or {}
    if msg.get("cmd") == "start":
        try:
            send_message(start_relay())
        except Exception as e:
            # The start response includes the secret even when starting
            # the relay itself failed: the spec gives the extension the
            # secret in this answer, read or created whether or not the
            # relay was already running. The old blanket handler in
            # __main__ answered such failures with no enrollSecret.
            answer = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            try:
                answer["enrollSecret"] = ensure_enroll_secret()
            except Exception:
                pass
            send_message(answer)
    elif msg.get("cmd") == "status":
        send_message({"ok": True, "running": all(port_open(p) for p in PORTS)})
    else:
        send_message({"ok": False, "error": "unknown_cmd"})


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # always answer Chrome
        send_message({"ok": False, "error": f"{type(e).__name__}: {e}"})
