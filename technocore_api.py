import base64
import hashlib
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import (
    E2E_ROOM_PREFIX,
    MAX_MESSAGE_CHARS,
    MAX_NOTE_CHARS,
    MESSAGES_LIMIT,
    REQUEST_TIMEOUT,
    ROOMS_LIMIT,
    ROOM_NAME_RE,
    TECHNOCORE_API,
    WATCH_FETCH_LIMIT,
)
from crypto_utils import b64url_decode, sweep_text
from database import get_e2e_key


class DirectoryProfileConflictError(Exception):
    """Raised when a DID directory note contains a different identity."""


def create_signature(seed, room, nonce, text):
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    canonical = f"{room}|{nonce}|{text}"
    raw_signature = private_key.sign(canonical.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")


def send_signed_message(room, text, did, seed, nonce):
    if not ROOM_NAME_RE.fullmatch(room):
        raise ValueError("Invalid Technocore room name")

    cleaned_text = sweep_text(text)
    signature = create_signature(seed, room, nonce, cleaned_text)
    safe_room = quote(room, safe="")

    response = requests.post(
        f"{TECHNOCORE_API}/r/{safe_room}",
        json={
            "text": cleaned_text,
            "did": did,
            "sig": signature,
            "nonce": str(nonce),
        },
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return cleaned_text


def send_e2e_ciphertext(room, ciphertext_line):
    if not ROOM_NAME_RE.fullmatch(room) or not room.startswith(E2E_ROOM_PREFIX):
        raise ValueError("Invalid E2E room name")
    if not isinstance(ciphertext_line, str) or len(ciphertext_line) > MAX_MESSAGE_CHARS:
        raise ValueError("Invalid E2E ciphertext")

    safe_room = quote(room, safe="")
    response = requests.post(
        f"{TECHNOCORE_API}/r/{safe_room}",
        json={"from": "e2e", "text": ciphertext_line},
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()


def get_rooms():
    response = requests.get(
        f"{TECHNOCORE_API}/rooms",
        params={"format": "json", "limit": ROOMS_LIMIT},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def get_room_messages(room_name, limit=MESSAGES_LIMIT):
    if not ROOM_NAME_RE.fullmatch(room_name):
        raise ValueError("Invalid room name")

    safe_room_name = quote(room_name, safe="")
    response = requests.get(
        f"{TECHNOCORE_API}/r/{safe_room_name}",
        params={"format": "json", "limit": limit},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def get_room_updates(room_name, since, limit=WATCH_FETCH_LIMIT):
    if not ROOM_NAME_RE.fullmatch(room_name):
        raise ValueError("Invalid room name")

    safe_room_name = quote(room_name, safe="")
    response = requests.get(
        f"{TECHNOCORE_API}/r/{safe_room_name}",
        params={
            "format": "json",
            "since": int(since),
            "limit": limit,
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def did_directory_location(did):
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    shard = fingerprint[:2]
    key = fingerprint[2:]
    namespace = f"did-{shard}"
    path = f"/kv/{namespace}/{key}"
    legacy_path = f"/kv/did/{fingerprint}"

    return {
        "fingerprint": fingerprint,
        "shard": shard,
        "key": key,
        "namespace": namespace,
        "path": path,
        "legacy_path": legacy_path,
    }


def build_did_directory_value(identity, mailbox=None):
    parts = [identity["did"]]

    e2e_key = get_e2e_key(identity["telegram_user_id"])
    if e2e_key:
        parts.append(f"x25519:{e2e_key['public_key']}")

    # Only advertise a mailbox that actually exists on Technocore.
    if mailbox and mailbox["is_active"]:
        parts.append(f"mailbox:{mailbox['room']}")

    value = " ".join(parts)

    if len(value) > MAX_NOTE_CHARS:
        raise ValueError("DID directory profile is too large")

    return value


def strip_budget_footer(text):
    # Technocore can append a low-budget status line to text replies.
    lines = text.rstrip("\n").splitlines()
    if lines and lines[-1].startswith("# budget: "):
        lines.pop()
    return "\n".join(lines).rstrip("\n")


def strip_note_read_banner(text):
    """Remove Technocore's server-added untrusted-content banner from note reads.

    GET /kv/<ns>/<key> intentionally prefixes caller-controlled note data with
    an untrusted-content warning. That warning is transport metadata, not part
    of the stored note value, so it must not participate in DID comparisons or
    compare-and-set (CAS) writes.
    """

    cleaned = strip_budget_footer(text)

    if cleaned.startswith("!! UNTRUSTED CONTENT"):
        _banner, separator, note_value = cleaned.partition("\n\n")
        if separator:
            return note_value.rstrip("\n")

    return cleaned


def get_note(namespace, key):
    if not ROOM_NAME_RE.fullmatch(namespace) or not ROOM_NAME_RE.fullmatch(key):
        raise ValueError("Invalid Technocore note path")

    safe_namespace = quote(namespace, safe="")
    safe_key = quote(key, safe="")
    response = requests.get(
        f"{TECHNOCORE_API}/kv/{safe_namespace}/{safe_key}",
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return strip_note_read_banner(response.text)


def get_did_directory_profile(did):
    location = did_directory_location(did)

    value = get_note(location["namespace"], location["key"])
    if value is not None:
        return {
            "value": value,
            "path": location["path"],
            "legacy": False,
            "location": location,
        }

    legacy_value = get_note("did", location["fingerprint"])
    if legacy_value is not None:
        return {
            "value": legacy_value,
            "path": location["legacy_path"],
            "legacy": True,
            "location": location,
        }

    return {
        "value": None,
        "path": location["path"],
        "legacy": False,
        "location": location,
    }


def parse_did_directory_value(value, expected_did=None):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("DID directory profile is empty")

    parts = value.strip().split()
    did = parts[0]
    if not did.startswith("did:key:z6Mk"):
        raise ValueError("Directory entry does not begin with an Ed25519 did:key")
    if expected_did is not None and did != expected_did:
        raise ValueError("Directory DID does not match requested DID")

    result = {"did": did, "x25519": None, "mailbox": None}
    for token in parts[1:]:
        if token.startswith("x25519:"):
            if result["x25519"] is not None:
                raise ValueError("Duplicate x25519 field")
            public_key = token[len("x25519:"):]
            public_raw = b64url_decode(public_key)
            if len(public_raw) != 32:
                raise ValueError("Invalid X25519 public key")
            result["x25519"] = public_key
        elif token.startswith("mailbox:"):
            if result["mailbox"] is not None:
                raise ValueError("Duplicate mailbox field")
            mailbox = token[len("mailbox:"):]
            if not ROOM_NAME_RE.fullmatch(mailbox) or not mailbox.startswith("mb-"):
                raise ValueError("Invalid mailbox field")
            result["mailbox"] = mailbox

    return result


def set_did_directory_note(namespace, key, value, current_value=None):
    safe_namespace = quote(namespace, safe="")
    safe_key = quote(key, safe="")

    payload = {"value": value}
    if current_value is None:
        payload["if_absent"] = True
    else:
        payload["if"] = current_value

    response = requests.post(
        f"{TECHNOCORE_API}/kv/{safe_namespace}/{safe_key}",
        json=payload,
        headers={"Accept": "text/plain"},
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 409:
        actual = strip_note_read_banner(response.text)
        raise DirectoryProfileConflictError(actual)

    response.raise_for_status()


def publish_did_directory_profile(identity, mailbox=None):
    location = did_directory_location(identity["did"])
    target_value = build_did_directory_value(identity, mailbox)
    current_value = get_note(location["namespace"], location["key"])

    if current_value == target_value:
        return {
            "status": "unchanged",
            "value": target_value,
            "path": location["path"],
        }

    if current_value is not None and not current_value.startswith(identity["did"]):
        raise DirectoryProfileConflictError(current_value)

    try:
        set_did_directory_note(
            location["namespace"],
            location["key"],
            target_value,
            current_value=current_value,
        )
    except DirectoryProfileConflictError as error:
        # A race may have changed the note after our read. Never overwrite a
        # different DID automatically.
        actual = str(error)
        if actual != target_value and not actual.startswith(identity["did"]):
            raise

        if actual == target_value:
            return {
                "status": "unchanged",
                "value": target_value,
                "path": location["path"],
            }

        # Same DID, but another update won the race. Retry once with CAS.
        set_did_directory_note(
            location["namespace"],
            location["key"],
            target_value,
            current_value=actual,
        )

    return {
        "status": "published" if current_value is None else "updated",
        "value": target_value,
        "path": location["path"],
    }
