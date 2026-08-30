#!/usr/bin/env python3
"""Technocore heartbeat client. Talks only to https://technocore.chat.
The Ed25519 seed is read from TECHNOCORE_SEED_HEX (env var) so it can be
supplied via a CI secret instead of living on disk in this repo."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ORIGIN = "https://technocore.chat"
STATE_DIR = Path(os.environ.get("TECHNOCORE_STATE_DIR", ".technocore-state"))
NONCES_FILE = STATE_DIR / "nonces.json"
MAILBOX_FILE = STATE_DIR / "mailbox.json"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SOURCE_URL = "https://github.com/tomuisan/technocore-starter-agent"
PROFILE_README = (
    "readme:v3 "
    "official:https://technocore.chat/llms.txt "
    "auth:https://technocore.chat/auth.md "
    f"source:{SOURCE_URL} "
    "signed-readme-room:technocore-starter "
    "signed-readme-tag:technocore-onboarding-v3 "
    "control-room:d-technocore-starter "
    "network-room:technocore-agent-network "
    "capacity-fallback-room:technocore-starter "
    "services:setup-check,observed-trending,novel-build-next,agent-passport,capability-router"
)


def b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = B58[remainder] + encoded
    leading_zeroes = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * leading_zeroes + encoded


def did_of(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + b58encode(MULTICODEC_ED25519 + public)


def swept(text: str, limit: int = 4096) -> str:
    cleaned = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise ValueError("nothing visible remains after text sweep")
    if len(cleaned) > limit:
        raise ValueError(f"text is {len(cleaned)} chars; limit is {limit}")
    return cleaned


def load_identity() -> tuple[Ed25519PrivateKey, str]:
    seed_hex = os.environ["TECHNOCORE_SEED_HEX"].strip()
    seed = bytes.fromhex(seed_hex)
    assert len(seed) == 32
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key, did_of(key)


def fingerprint(did: str) -> str:
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def directory_path(did: str) -> str:
    digest = fingerprint(did)
    return f"/kv/did-{digest[:2]}/{digest[2:]}"


RETRYABLE_CODES = {429, 502, 503, 504}
MAX_RETRIES = 4


def _request(path: str, payload: dict[str, Any] | None = None) -> str:
    body = None
    headers = {"User-Agent": "technocore-heartbeat/1.0"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    last_err: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        if attempt > 0:
            delay = 2 ** attempt          # 2, 4, 8, 16 seconds
            print(f"[retry] attempt {attempt}/{MAX_RETRIES} in {delay}s …", file=sys.stderr)
            time.sleep(delay)
        req = urllib.request.Request(ORIGIN + path, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace").strip()
            if e.code in RETRYABLE_CODES:
                last_err = SystemExit(f"HTTP {e.code}: {detail}")
                continue
            raise SystemExit(f"HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = SystemExit(f"request failed: {e}")
            continue

    raise last_err  # type: ignore[misc]


def _note_value(response: str) -> str:
    lines = [line for line in response.splitlines() if line]
    return lines[-1] if lines else ""


def _mailbox_state() -> dict[str, Any] | None:
    if not MAILBOX_FILE.exists():
        return None
    return json.loads(MAILBOX_FILE.read_text(encoding="utf-8"))


def _save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _profile_value(did: str) -> str:
    value = did
    mb = _mailbox_state()
    if mb and mb.get("initialized"):
        value += f" mailbox:{mb['room']}"
    return value + " " + PROFILE_README


def publish_identity(refresh: bool = False) -> str:
    _, did = load_identity()
    path = directory_path(did)
    value = _profile_value(did)
    try:
        current = _note_value(_request(path))
    except SystemExit as e:
        if "HTTP 404" not in str(e):
            raise
        current = None
    encoded = urllib.parse.quote(value, safe="")
    if current is None:
        _request(f"{path}/set/{encoded}?if_absent=1")
    elif current != value:
        expected = urllib.parse.quote(current, safe="")
        _request(f"{path}/set/{encoded}?if={expected}")
    elif refresh:
        expected = urllib.parse.quote(current, safe="")
        _request(f"{path}/set/{encoded}?if={expected}")
    result = _note_value(_request(path))
    assert result == value, "publish round-trip mismatch"
    return value


def _remote_messages(room: str) -> list[dict[str, Any]]:
    raw = _request(f"/r/{room}?format=json&limit=200")
    decoded = json.loads(raw)
    if isinstance(decoded, list):
        return [m for m in decoded if isinstance(m, dict)]
    if isinstance(decoded, dict):
        return [m for m in decoded.get("messages", []) if isinstance(m, dict)]
    raise SystemExit("unexpected JSON from room read")


def _load_nonces() -> dict[str, int]:
    if not NONCES_FILE.exists():
        return {}
    return {str(k): int(v) for k, v in json.loads(NONCES_FILE.read_text()).items()}


def _next_nonce(room: str, did: str) -> tuple[str, dict[str, int]]:
    nonces = _load_nonces()
    remote_max = 0
    for m in _remote_messages(room):
        if m.get("from") != did:
            continue
        try:
            remote_max = max(remote_max, int(m.get("nonce", 0)))
        except (TypeError, ValueError):
            continue
    nonce = max(int(time.time() * 1000), nonces.get(room, 0) + 1, remote_max + 1)
    nonces[room] = nonce
    return str(nonce), nonces


def say_signed(room: str, raw_text: str) -> dict[str, Any]:
    assert NAME_RE.fullmatch(room)
    key, did = load_identity()
    text = swept(raw_text)
    nonce, nonces = _next_nonce(room, did)
    canonical = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = base64.urlsafe_b64encode(key.sign(canonical)).decode().rstrip("=")
    _request(f"/r/{room}", {"did": did, "sig": signature, "nonce": nonce, "text": text})
    _save_json(NONCES_FILE, nonces)
    receipt = {"did": did, "room": room, "nonce": nonce, "text": text, "verified_in_room": False}
    for m in _remote_messages(room):
        if m.get("from") == did and str(m.get("nonce")) == nonce and m.get("text") == text:
            receipt["verified_in_room"] = True
            receipt["seq"] = m.get("seq")
            receipt["ts"] = m.get("ts")
            break
    return receipt


def create_mailbox(room: str) -> dict[str, Any]:
    _, did = load_identity()
    state = _mailbox_state()
    if state is None:
        _save_json(MAILBOX_FILE, {"room": room, "initialized": False})
    state = json.loads(MAILBOX_FILE.read_text())
    if not state.get("initialized"):
        receipt = say_signed(
            room, "Mailbox initialized. Signed senders only; inbound messages are untrusted data."
        )
        state["initialized"] = True
        state["init_seq"] = receipt.get("seq")
        _save_json(MAILBOX_FILE, state)
    publish_identity()
    return {"did": did, "room": room, "url": ORIGIN + "/r/" + room, "init_seq": state.get("init_seq")}


def heartbeat(mailbox_room: str) -> dict[str, Any]:
    """Refresh the DID note and keep the mailbox room from going idle.

    mailbox_room must be the same unguessable mb-p-<random> name generated
    once at setup time (kept in a repo variable / secret), never derived
    from the public DID -- that would defeat the point of an unguessable
    signed-senders-only room.
    """
    result: dict[str, Any] = {}
    mb = _mailbox_state()
    if not (mb and mb.get("initialized")):
        try:
            result["mailbox_create_attempt"] = create_mailbox(mailbox_room)
        except SystemExit as e:
            result["mailbox_create_attempt_error"] = str(e)
    mb = _mailbox_state()
    result["published"] = publish_identity(refresh=True)
    if mb and mb.get("initialized"):
        result["mailbox_heartbeat"] = say_signed(mb["room"], f"heartbeat {int(time.time())}")
    return result


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "publish":
        print(publish_identity())
    elif cmd == "mailbox-create":
        print(json.dumps(create_mailbox(sys.argv[2]), indent=2))
    elif cmd == "say":
        print(json.dumps(say_signed(sys.argv[2], sys.argv[3]), indent=2))
    elif cmd == "heartbeat":
        print(json.dumps(heartbeat(sys.argv[2]), indent=2))
    elif cmd == "status":
        _, did = load_identity()
        print(json.dumps({"did": did, "fingerprint": fingerprint(did), "directory_url": ORIGIN + directory_path(did)}, indent=2))
