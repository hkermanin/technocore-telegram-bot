import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

TECHNOCORE_API = "https://technocore.chat"
ROOMS_LIMIT = 5
MESSAGES_LIMIT = 10
MAILBOX_MESSAGES_LIMIT = 20
WATCH_FETCH_LIMIT = 200
WATCH_POLL_INTERVAL = 30
MAX_WATCHES_PER_USER = 5
REQUEST_TIMEOUT = 10
TELEGRAM_TEXT_LIMIT = 3900
DATABASE_PATH = "technocore.db"

ROOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192


class DirectoryProfileConflictError(Exception):
    """Raised when a DID directory note contains a different identity."""


SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32
SALT_SIZE = 16
AES_NONCE_SIZE = 12
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_ATTEMPTS = 3

BACKUP_FORMAT = "technocore-gateway-backup"
BACKUP_VERSION = 1
MAX_BACKUP_SIZE = 50_000

load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

(
    CREATE_PASSWORD,
    CONFIRM_PASSWORD,
    IMPORT_FILE,
    IMPORT_PASSWORD,
    SEND_TEXT,
    SEND_PASSWORD,
    MAILBOX_TARGET,
    MAILBOX_TEXT,
    MAILBOX_PASSWORD,
    MAILBOX_ACTIVATE_PASSWORD,
) = range(10)


# =========================================================
# Database
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS identities (
                telegram_user_id INTEGER PRIMARY KEY,
                did TEXT NOT NULL UNIQUE,
                encrypted_seed BLOB NOT NULL,
                salt BLOB NOT NULL,
                encryption_nonce BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nonces (
                telegram_user_id INTEGER NOT NULL,
                room TEXT NOT NULL,
                last_nonce INTEGER NOT NULL,
                PRIMARY KEY (telegram_user_id, room)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mailboxes (
                telegram_user_id INTEGER PRIMARY KEY,
                room TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_read_seq INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS room_watches (
                telegram_user_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                room TEXT NOT NULL,
                last_seq INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                PRIMARY KEY (telegram_user_id, room)
            )
            """
        )

        mailbox_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(mailboxes)"
            ).fetchall()
        }

        if "is_active" not in mailbox_columns:
            connection.execute(
                """
                ALTER TABLE mailboxes
                ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0
                """
            )

        connection.commit()


def get_identity(telegram_user_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT telegram_user_id, did, encrypted_seed, salt,
                   encryption_nonce, created_at
            FROM identities
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        ).fetchone()


def save_identity(
    telegram_user_id,
    did,
    encrypted_seed,
    salt,
    encryption_nonce,
    created_at=None,
):
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO identities (
                telegram_user_id, did, encrypted_seed, salt,
                encryption_nonce, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                telegram_user_id,
                did,
                encrypted_seed,
                salt,
                encryption_nonce,
                created_at,
            ),
        )
        connection.commit()


def get_next_nonce(telegram_user_id, room):
    clock_nonce = time.time_ns()

    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT last_nonce
            FROM nonces
            WHERE telegram_user_id = ? AND room = ?
            """,
            (telegram_user_id, room),
        ).fetchone()

        if row:
            nonce = max(clock_nonce, row["last_nonce"] + 1)
            connection.execute(
                """
                UPDATE nonces
                SET last_nonce = ?
                WHERE telegram_user_id = ? AND room = ?
                """,
                (nonce, telegram_user_id, room),
            )
        else:
            nonce = clock_nonce
            connection.execute(
                """
                INSERT INTO nonces (telegram_user_id, room, last_nonce)
                VALUES (?, ?, ?)
                """,
                (telegram_user_id, room, nonce),
            )

        connection.commit()

    return nonce


def get_mailbox(telegram_user_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT
                telegram_user_id,
                room,
                created_at,
                last_read_seq,
                is_active
            FROM mailboxes
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        ).fetchone()


def save_mailbox(telegram_user_id, room, is_active=False):
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO mailboxes (
                telegram_user_id,
                room,
                created_at,
                last_read_seq,
                is_active
            )
            VALUES (?, ?, ?, 0, ?)
            """,
            (
                telegram_user_id,
                room,
                created_at,
                1 if is_active else 0,
            ),
        )
        connection.commit()


def mark_mailbox_active(telegram_user_id):
    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE mailboxes
            SET is_active = 1
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        )
        connection.commit()


def update_mailbox_last_read(telegram_user_id, last_seq):
    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE mailboxes
            SET last_read_seq = ?
            WHERE telegram_user_id = ?
            """,
            (last_seq, telegram_user_id),
        )
        connection.commit()


def get_room_watch(telegram_user_id, room):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT telegram_user_id, chat_id, room, last_seq, created_at
            FROM room_watches
            WHERE telegram_user_id = ? AND room = ?
            """,
            (telegram_user_id, room),
        ).fetchone()


def get_user_watches(telegram_user_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT telegram_user_id, chat_id, room, last_seq, created_at
            FROM room_watches
            WHERE telegram_user_id = ?
            ORDER BY created_at ASC
            """,
            (telegram_user_id,),
        ).fetchall()


def get_all_watches():
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT telegram_user_id, chat_id, room, last_seq, created_at
            FROM room_watches
            ORDER BY room ASC, created_at ASC
            """
        ).fetchall()


def save_room_watch(telegram_user_id, chat_id, room, last_seq):
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO room_watches (
                telegram_user_id, chat_id, room, last_seq, created_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(telegram_user_id, room) DO UPDATE SET
                chat_id = excluded.chat_id,
                last_seq = excluded.last_seq
            """,
            (telegram_user_id, chat_id, room, last_seq, created_at),
        )
        connection.commit()


def update_room_watch_seq(telegram_user_id, room, last_seq):
    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE room_watches
            SET last_seq = ?
            WHERE telegram_user_id = ? AND room = ?
            """,
            (last_seq, telegram_user_id, room),
        )
        connection.commit()


def delete_room_watch(telegram_user_id, room):
    with get_db_connection() as connection:
        connection.execute(
            """
            DELETE FROM room_watches
            WHERE telegram_user_id = ? AND room = ?
            """,
            (telegram_user_id, room),
        )
        connection.commit()


# =========================================================
# DID / Cryptography
# =========================================================

def base58btc_encode(raw):
    alphabet = (
        "123456789"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz"
    )

    if not raw:
        return ""

    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded

    return "1" * leading_zeroes + encoded


def create_did_from_private_key(private_key):
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    multicodec_key = MULTICODEC_ED25519 + public_key_bytes
    return f"did:key:z{base58btc_encode(multicodec_key)}"


def generate_identity():
    seed = secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return seed, create_did_from_private_key(private_key)


def did_from_seed(seed):
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return create_did_from_private_key(private_key)


def derive_encryption_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_seed(seed, password):
    salt = secrets.token_bytes(SALT_SIZE)
    encryption_nonce = secrets.token_bytes(AES_NONCE_SIZE)
    encryption_key = derive_encryption_key(password, salt)
    encrypted_seed = AESGCM(encryption_key).encrypt(
        encryption_nonce,
        seed,
        None,
    )
    return encrypted_seed, salt, encryption_nonce


def decrypt_seed(encrypted_seed, salt, encryption_nonce, password):
    encryption_key = derive_encryption_key(password, salt)
    return AESGCM(encryption_key).decrypt(
        encryption_nonce,
        encrypted_seed,
        None,
    )


# =========================================================
# Technocore signing
# =========================================================

def sweep_text(text):
    cleaned = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()

    if not cleaned:
        raise ValueError("Message is empty after sweep")

    if len(cleaned) > MAX_MESSAGE_CHARS:
        raise ValueError("Message is too long")

    return cleaned


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


# =========================================================
# Backup
# =========================================================

def encode_base64(value):
    return base64.b64encode(value).decode("ascii")


def decode_base64(value):
    if not isinstance(value, str):
        raise ValueError("Invalid base64 field")
    return base64.b64decode(value, validate=True)


def create_backup_data(identity, mailbox=None):
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "did": identity["did"],
        "key_type": "Ed25519",
        "created_at": identity["created_at"],
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "mailbox": mailbox["room"] if mailbox else None,
        "mailbox_active": bool(mailbox["is_active"]) if mailbox else False,
        "encryption": {
            "cipher": "AES-256-GCM",
            "kdf": {
                "name": "scrypt",
                "n": SCRYPT_N,
                "r": SCRYPT_R,
                "p": SCRYPT_P,
                "length": SCRYPT_KEY_LENGTH,
            },
            "salt": encode_base64(identity["salt"]),
            "nonce": encode_base64(identity["encryption_nonce"]),
            "encrypted_seed": encode_base64(identity["encrypted_seed"]),
        },
    }


def create_backup_file(identity, mailbox=None):
    content = json.dumps(
        create_backup_data(identity, mailbox),
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
    buffer = io.BytesIO(content)
    buffer.seek(0)
    return buffer


def validate_backup_data(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid backup")
    if data.get("format") != BACKUP_FORMAT:
        raise ValueError("Unknown backup format")
    if data.get("version") != BACKUP_VERSION:
        raise ValueError("Unsupported backup version")
    if data.get("key_type") != "Ed25519":
        raise ValueError("Unsupported key type")

    did = data.get("did")
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk"):
        raise ValueError("Invalid DID")

    encryption = data.get("encryption")
    if not isinstance(encryption, dict):
        raise ValueError("Missing encryption data")
    if encryption.get("cipher") != "AES-256-GCM":
        raise ValueError("Unsupported cipher")

    expected_kdf = {
        "name": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "length": SCRYPT_KEY_LENGTH,
    }
    if encryption.get("kdf") != expected_kdf:
        raise ValueError("Unsupported KDF settings")

    salt = decode_base64(encryption.get("salt"))
    encryption_nonce = decode_base64(encryption.get("nonce"))
    encrypted_seed = decode_base64(encryption.get("encrypted_seed"))

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt")
    if len(encryption_nonce) != AES_NONCE_SIZE:
        raise ValueError("Invalid nonce")
    if len(encrypted_seed) != 48:
        raise ValueError("Invalid encrypted seed")

    created_at = data.get("created_at")
    if not isinstance(created_at, str):
        created_at = datetime.now(timezone.utc).isoformat()

    mailbox = data.get("mailbox")
    if mailbox is not None:
        if (
            not isinstance(mailbox, str)
            or not ROOM_NAME_RE.fullmatch(mailbox)
            or not mailbox.startswith("mb-")
        ):
            raise ValueError("Invalid mailbox in backup")

    mailbox_active = data.get("mailbox_active", False)
    if not isinstance(mailbox_active, bool):
        mailbox_active = False

    return {
        "did": did,
        "encrypted_seed": encrypted_seed,
        "salt": salt,
        "encryption_nonce": encryption_nonce,
        "created_at": created_at,
        "mailbox": mailbox,
        "mailbox_active": mailbox_active,
    }


# =========================================================
# Technocore read API
# =========================================================

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


# =========================================================
# Technocore DID directory notes
# =========================================================

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
        actual = strip_budget_footer(response.text)
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


# =========================================================
# Keyboards
# =========================================================

def main_menu_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔥 Browse Rooms", callback_data="show_rooms")],
            [InlineKeyboardButton("🔔 Watched Rooms", callback_data="watched_rooms")],
            [InlineKeyboardButton("📬 Mailbox", callback_data="mailbox_menu")],
            [
                InlineKeyboardButton("🪪 Create DID", callback_data="create_did"),
                InlineKeyboardButton("👤 My Identity", callback_data="my_identity"),
            ],
            [InlineKeyboardButton("🌐 DID Profile", callback_data="did_profile")],
            [InlineKeyboardButton("♻️ Import Backup", callback_data="import_backup")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about")],
        ]
    )


def identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📦 Export Backup", callback_data="export_backup")],
            [InlineKeyboardButton("🌐 DID Profile", callback_data="did_profile")],
            [InlineKeyboardButton("📬 Mailbox", callback_data="mailbox_menu")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def no_identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🪪 Create DID", callback_data="create_did")],
            [InlineKeyboardButton("♻️ Import Backup", callback_data="import_backup")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def did_profile_keyboard(has_remote_profile=False):
    publish_label = (
        "🔄 Update Directory Profile"
        if has_remote_profile
        else "📡 Publish Directory Profile"
    )

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(publish_label, callback_data="publish_did_profile")],
            [InlineKeyboardButton("🔄 Refresh Profile", callback_data="did_profile")],
            [InlineKeyboardButton("👤 My Identity", callback_data="my_identity")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def mailbox_keyboard(mailbox):
    if not mailbox:
        return InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📬 Generate Mailbox Address", callback_data="create_mailbox")],
                [InlineKeyboardButton("✉️ Send to Mailbox", callback_data="send_mailbox")],
                [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
            ]
        )

    is_active = (
        bool(mailbox["is_active"])
        if not isinstance(mailbox, bool)
        else mailbox
    )

    if not is_active:
        return InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("⚡ Activate Mailbox", callback_data="activate_mailbox")],
                [InlineKeyboardButton("✉️ Send to Mailbox", callback_data="send_mailbox")],
                [InlineKeyboardButton("🔄 Check Status", callback_data="mailbox_menu")],
                [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
            ]
        )

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📥 Read Mailbox", callback_data="read_mailbox")],
            [InlineKeyboardButton("✉️ Send to Mailbox", callback_data="send_mailbox")],
            [InlineKeyboardButton("🔄 Refresh", callback_data="mailbox_menu")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def mailbox_read_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔄 Refresh Inbox", callback_data="read_mailbox")],
            [InlineKeyboardButton("✉️ Send to Mailbox", callback_data="send_mailbox")],
            [InlineKeyboardButton("📬 Mailbox Menu", callback_data="mailbox_menu")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def rooms_keyboard(room_names):
    keyboard = [
        [InlineKeyboardButton(room_name, callback_data=f"room:{index}")]
        for index, room_name in enumerate(room_names)
    ]
    keyboard.append([InlineKeyboardButton("🔄 Refresh", callback_data="show_rooms")])
    keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data="home")])
    return InlineKeyboardMarkup(keyboard)


def room_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("✍️ Send Signed Message", callback_data="send_signed")],
            [InlineKeyboardButton("🔔 Watch This Room", callback_data="watch_current_room")],
            [InlineKeyboardButton("🔔 Watched Rooms", callback_data="watched_rooms")],
            [InlineKeyboardButton("⬅️ Back to Rooms", callback_data="show_rooms")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def watched_rooms_keyboard(watches):
    keyboard = []

    for watch in watches:
        room = watch["room"]
        keyboard.append(
            [InlineKeyboardButton(f"🔕 Stop: {room}", callback_data=f"stopwatch:{room}")]
        )

    keyboard.append([InlineKeyboardButton("🔥 Browse Rooms", callback_data="show_rooms")])
    keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data="home")])
    return InlineKeyboardMarkup(keyboard)


def watch_notification_keyboard(room):
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📖 Open Room", callback_data=f"openwatch:{room}")],
            [InlineKeyboardButton("🔕 Stop Watching", callback_data=f"stopwatch:{room}")],
        ]
    )


# =========================================================
# Helpers
# =========================================================

def shorten_sender(sender):
    if len(sender) <= 36:
        return sender
    return f"{sender[:22]}...{sender[-8:]}"


def format_messages(title, messages):
    if not messages:
        return f"{title}\n\nNo messages found."

    text = f"{title}\n\n"
    shown = 0

    for message in messages:
        sender = shorten_sender(message.get("from", "unknown"))
        content = message.get("text", "")
        timestamp = message.get("ts", "")
        seq = message.get("seq", "?")

        if len(content) > 500:
            content = content[:500] + "..."

        block = f"#{seq}\n👤 {sender}\n"
        if timestamp:
            block += f"🕒 {timestamp}\n"
        block += f"\n{content}\n\n────────────\n\n"

        if len(text) + len(block) > TELEGRAM_TEXT_LIMIT:
            text += "… More messages were omitted to fit Telegram's message limit."
            break

        text += block
        shown += 1

    if shown == 0:
        return f"{title}\n\nMessages were too large to display."

    return text


def build_rooms_menu(context):
    rooms_data = get_rooms()
    room_names = [
        room["room"]
        for room in rooms_data.get("rooms", [])
        if "room" in room
    ]
    context.user_data["room_names"] = room_names
    total_rooms = rooms_data.get("total", "?")

    return (
        "🔥 Active Technocore Rooms\n\n"
        f"Technocore currently has {total_rooms} rooms.\n\n"
        "Choose a room to read its latest messages:",
        rooms_keyboard(room_names),
    )


async def delete_sensitive_message(update):
    try:
        if update.message:
            await update.message.delete()
    except Exception:
        pass


def identity_text(identity):
    return (
        "👤 Your Technocore Identity\n\n"
        f"DID:\n{identity['did']}\n\n"
        f"Created:\n{identity['created_at']}\n\n"
        "🔐 Your private seed is stored encrypted.\n\n"
        "Your password is NOT stored."
    )


def did_profile_text(identity, mailbox, remote_profile):
    location = did_directory_location(identity["did"])
    expected_value = build_did_directory_value(identity, mailbox)
    remote_value = remote_profile.get("value") if remote_profile else None

    lines = [
        "🌐 Technocore DID Profile",
        "",
        "DID:",
        identity["did"],
        "",
        f"Fingerprint: {location['fingerprint']}",
        "Directory path:",
        location["path"],
        "",
    ]

    if mailbox and mailbox["is_active"]:
        lines.extend([
            "📬 Active mailbox advertised:",
            mailbox["room"],
            "",
        ])
    elif mailbox:
        lines.extend([
            "📬 Mailbox: pending / inactive",
            "It will NOT be advertised until Technocore activation succeeds.",
            "",
        ])
    else:
        lines.extend([
            "📬 Mailbox: none",
            "The profile can still publish the DID alone.",
            "",
        ])

    if remote_value is None:
        lines.extend([
            "⏳ Directory status: NOT PUBLISHED",
            "",
            "Value that will be published:",
            expected_value,
        ])
    else:
        if remote_value == expected_value:
            status = "✅ Directory status: PUBLISHED AND CURRENT"
        elif remote_value.startswith(identity["did"]):
            status = "⚠️ Directory status: PUBLISHED BUT OUTDATED"
        else:
            status = "🚨 Directory status: CONFLICT / OVERWRITTEN"

        lines.extend([
            status,
            f"Remote path: {remote_profile['path']}",
            "",
            "Remote value:",
            remote_value[:1200],
        ])

        if len(remote_value) > 1200:
            lines.append("… remote value truncated for Telegram")

    lines.extend([
        "",
        "⚠️ Trust note:",
        "DID directory notes are world-readable and world-writable. The note itself is NOT proof of ownership; signed did:key messages are the cryptographic proof.",
    ])

    return "\n".join(lines)


def generate_mailbox_name():
    return "mb-p-" + secrets.token_hex(16)


def mailbox_text(mailbox):
    if not mailbox:
        return (
            "📬 Technocore Mailbox\n\n"
            "You do not have a mailbox address yet.\n\n"
            "The bot can generate a random mb-p- address locally, but the mailbox only "
            "exists on Technocore after a signed activation write succeeds."
        )

    if not mailbox["is_active"]:
        return (
            "📬 Technocore Mailbox\n\n"
            f"Candidate address:\n{mailbox['room']}\n\n"
            "⏳ Status: NOT ACTIVE on Technocore yet.\n\n"
            "Press Activate Mailbox to create it with a signed write. If the hosted "
            "Technocore instance is at its room-capacity limit, activation will remain "
            "pending and you can retry later.\n\n"
            "⚠️ The address is not reserved by the server until activation succeeds."
        )

    return (
        "📬 Your Technocore Mailbox\n\n"
        f"Address:\n{mailbox['room']}\n\n"
        f"Created locally:\n{mailbox['created_at']}\n\n"
        "✅ Active on Technocore\n"
        "✅ Unlisted from public room discovery\n"
        "✅ Signed writes only\n"
        "⚠️ Not end-to-end encrypted: anyone who learns the mailbox name can read it."
    )


def mailbox_is_active_for_identity(mailbox, identity):
    if not mailbox or not identity:
        return False

    if mailbox["is_active"]:
        return True

    try:
        mailbox_data = get_room_messages(
            mailbox["room"],
            limit=20,
        )
    except (requests.RequestException, ValueError):
        return False

    for message in mailbox_data.get("messages", []):
        if message.get("from") == identity["did"]:
            mark_mailbox_active(identity["telegram_user_id"])
            return True

    return False


def watched_rooms_text(watches):
    if not watches:
        return (
            "🔔 Watched Rooms\n\n"
            "You are not watching any Technocore rooms yet.\n\n"
            "Open Browse Rooms, select a room and press 🔔 Watch This Room."
        )

    lines = ["🔔 Watched Rooms", ""]
    for watch in watches:
        lines.append(f"• {watch['room']}")

    lines.append("")
    lines.append(
        f"Notifications are checked about every {WATCH_POLL_INTERVAL} seconds "
        "while the bot process is running."
    )
    return "\n".join(lines)


def format_watch_notification(room, messages, missed=False):
    title = f"🔔 New Technocore activity\n\nRoom: {room}\n"
    if missed:
        title += "\n⚠️ The room moved too quickly and some messages may have been skipped.\n"

    text = title + "\n"
    shown = 0

    for message in messages:
        sender = shorten_sender(message.get("from", "unknown"))
        content = message.get("text", "")
        seq = message.get("seq", "?")

        if len(content) > 450:
            content = content[:450] + "..."

        block = f"#{seq} — {sender}\n{content}\n\n"
        if len(text) + len(block) > TELEGRAM_TEXT_LIMIT:
            break

        text += block
        shown += 1

        if shown >= 8:
            break

    omitted = max(0, len(messages) - shown)
    if omitted:
        text += f"… {omitted} more new message(s) not shown here.\n"

    return text.rstrip()


def clear_import_state(context):
    context.user_data.pop("pending_backup", None)
    context.user_data.pop("import_attempts", None)


def clear_send_state(context):
    context.user_data.pop("pending_send_text", None)
    context.user_data.pop("send_attempts", None)


def clear_mailbox_send_state(context):
    context.user_data.pop("pending_mailbox_target", None)
    context.user_data.pop("pending_mailbox_text", None)
    context.user_data.pop("mailbox_send_attempts", None)


# =========================================================
# Commands
# =========================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "⚡ Technocore Gateway\n\n"
        "Access Technocore directly from Telegram.\n\n"
        "Browse rooms, manage your DID, send signed messages, watch rooms and use a Technocore mailbox.",
        reply_markup=main_menu_keyboard(),
    )


async def rooms(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        text, keyboard = build_rooms_menu(context)
        await update.message.reply_text(text, reply_markup=keyboard)
    except (requests.RequestException, ValueError):
        await update.message.reply_text("❌ Could not connect to Technocore.")


async def read_room(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /read <room>\n\nExample:\n/read lobby")
        return

    room_name = context.args[0]
    context.user_data["current_room"] = room_name

    try:
        room_data = get_room_messages(room_name)
        text = format_messages(
            f"💬 {room_name}",
            room_data.get("messages", []),
        )
        await update.message.reply_text(text, reply_markup=room_keyboard())
    except (requests.RequestException, ValueError):
        await update.message.reply_text(f"❌ Could not read room: {room_name}")


async def watch_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: /watch <room>\n\nExample:\n/watch lobby"
        )
        return

    room = context.args[0].strip()
    user_id = update.effective_user.id

    if not ROOM_NAME_RE.fullmatch(room):
        await update.message.reply_text("❌ Invalid Technocore room name.")
        return

    if get_room_watch(user_id, room):
        await update.message.reply_text(
            f"🔔 You are already watching {room}.",
            reply_markup=watched_rooms_keyboard(get_user_watches(user_id)),
        )
        return

    if len(get_user_watches(user_id)) >= MAX_WATCHES_PER_USER:
        await update.message.reply_text(
            f"❌ You can watch up to {MAX_WATCHES_PER_USER} rooms in this MVP."
        )
        return

    try:
        room_data = get_room_messages(room, limit=1)
        last_seq = room_data.get("last_seq", 0) or 0
        save_room_watch(
            user_id,
            update.effective_chat.id,
            room,
            last_seq,
        )
        await update.message.reply_text(
            f"✅ Watching {room}. New activity will be sent here.",
            reply_markup=watched_rooms_keyboard(get_user_watches(user_id)),
        )
    except (requests.RequestException, ValueError):
        await update.message.reply_text("❌ Could not watch that room.")


async def unwatch_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: /unwatch <room>\n\nExample:\n/unwatch lobby"
        )
        return

    room = context.args[0].strip()
    if ROOM_NAME_RE.fullmatch(room):
        delete_room_watch(update.effective_user.id, room)

    await update.message.reply_text(
        f"🔕 Stopped watching {room}.",
        reply_markup=watched_rooms_keyboard(
            get_user_watches(update.effective_user.id)
        ),
    )


async def identity_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identity = get_identity(update.effective_user.id)

    if not identity:
        await update.message.reply_text(
            "🪪 You do not have a Technocore DID yet.",
            reply_markup=no_identity_keyboard(),
        )
        return

    await update.message.reply_text(
        identity_text(identity),
        reply_markup=identity_keyboard(),
    )


async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identity = get_identity(update.effective_user.id)

    if not identity:
        await update.message.reply_text(
            "🪪 You need a DID before publishing a directory profile.",
            reply_markup=no_identity_keyboard(),
        )
        return

    mailbox = get_mailbox(update.effective_user.id)

    try:
        remote_profile = get_did_directory_profile(identity["did"])
        await update.message.reply_text(
            did_profile_text(identity, mailbox, remote_profile),
            reply_markup=did_profile_keyboard(remote_profile["value"] is not None),
        )
    except requests.RequestException:
        await update.message.reply_text(
            "❌ Could not read the Technocore DID directory right now.",
            reply_markup=identity_keyboard(),
        )


# =========================================================
# DID creation conversation
# =========================================================

async def start_create_did(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    existing_identity = get_identity(update.effective_user.id)
    if existing_identity:
        await query.edit_message_text(
            "⚠️ You already have a Technocore DID.\n\n"
            f"{existing_identity['did']}",
            reply_markup=identity_keyboard(),
        )
        return ConversationHandler.END

    context.user_data.pop("pending_password_hash", None)

    await query.edit_message_text(
        "🪪 Create Technocore Identity\n\n"
        "A fresh Ed25519 keypair and did:key identity will be created.\n\n"
        "🔐 Send a NEW password now.\n"
        f"Minimum length: {MIN_PASSWORD_LENGTH} characters.\n\n"
        "IMPORTANT:\n"
        "• Use a unique password.\n"
        "• Never send a wallet seed phrase.\n"
        "• Never send another private key.\n"
        "• Telegram bot chats are not end-to-end encrypted.\n\n"
        "Use /cancel to stop."
    )
    return CREATE_PASSWORD


async def receive_did_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)

    if len(password) < MIN_PASSWORD_LENGTH:
        await update.effective_chat.send_message(
            f"❌ Password is too short. Please send at least {MIN_PASSWORD_LENGTH} characters."
        )
        return CREATE_PASSWORD

    context.user_data["pending_password_hash"] = hashlib.sha256(
        password.encode("utf-8")
    ).digest()

    await update.effective_chat.send_message(
        "🔐 Please send the same password again to confirm it."
    )
    return CONFIRM_PASSWORD


async def confirm_did_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)

    expected_hash = context.user_data.pop("pending_password_hash", None)
    if expected_hash is None:
        await update.effective_chat.send_message(
            "❌ Password session expired.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    received_hash = hashlib.sha256(password.encode("utf-8")).digest()
    if not hmac.compare_digest(expected_hash, received_hash):
        await update.effective_chat.send_message(
            "❌ Passwords did not match.\n\nSend a NEW password to start again."
        )
        return CREATE_PASSWORD

    try:
        seed, did = generate_identity()
        encrypted_seed, salt, encryption_nonce = encrypt_seed(seed, password)
        save_identity(
            update.effective_user.id,
            did,
            encrypted_seed,
            salt,
            encryption_nonce,
        )

        await update.effective_chat.send_message(
            "✅ Technocore Identity Created!\n\n"
            f"Your DID:\n{did}\n\n"
            "📦 Remember to keep an encrypted backup.",
            reply_markup=identity_keyboard(),
        )
    except sqlite3.IntegrityError:
        await update.effective_chat.send_message(
            "❌ An identity already exists.",
            reply_markup=main_menu_keyboard(),
        )

    return ConversationHandler.END


async def cancel_did_creation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("pending_password_hash", None)
    await update.message.reply_text(
        "DID creation cancelled.",
        reply_markup=main_menu_keyboard(),
    )
    return ConversationHandler.END


# =========================================================
# Backup import conversation
# =========================================================

async def start_import_backup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if get_identity(update.effective_user.id):
        await query.edit_message_text(
            "⚠️ You already have a Technocore identity.",
            reply_markup=identity_keyboard(),
        )
        return ConversationHandler.END

    clear_import_state(context)
    await query.edit_message_text(
        "♻️ Import Technocore Backup\n\n"
        "Send the encrypted JSON backup file created by this bot.\n\n"
        "Use /cancel to stop."
    )
    return IMPORT_FILE


async def receive_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    if document is None:
        return IMPORT_FILE

    if document.file_size and document.file_size > MAX_BACKUP_SIZE:
        await update.message.reply_text("❌ Backup file is too large.")
        return IMPORT_FILE

    try:
        telegram_file = await document.get_file()
        content = await telegram_file.download_as_bytearray()
        await delete_sensitive_message(update)

        if len(content) > MAX_BACKUP_SIZE:
            raise ValueError("Backup too large")

        backup = validate_backup_data(
            json.loads(bytes(content).decode("utf-8"))
        )
        context.user_data["pending_backup"] = backup
        context.user_data["import_attempts"] = 0

        await update.effective_chat.send_message(
            "✅ Backup recognized.\n\n"
            f"DID:\n{backup['did']}\n\n"
            "🔐 Send the password for this identity."
        )
        return IMPORT_PASSWORD

    except Exception:
        clear_import_state(context)
        await update.effective_chat.send_message(
            "❌ Invalid backup file.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END


async def receive_import_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)

    backup = context.user_data.get("pending_backup")
    if backup is None:
        return ConversationHandler.END

    attempts = context.user_data.get("import_attempts", 0)

    try:
        seed = decrypt_seed(
            backup["encrypted_seed"],
            backup["salt"],
            backup["encryption_nonce"],
            password,
        )
        derived_did = did_from_seed(seed)

        if not hmac.compare_digest(derived_did, backup["did"]):
            raise ValueError("DID mismatch")

        save_identity(
            update.effective_user.id,
            backup["did"],
            backup["encrypted_seed"],
            backup["salt"],
            backup["encryption_nonce"],
            backup["created_at"],
        )

        if backup.get("mailbox") and not get_mailbox(update.effective_user.id):
            save_mailbox(
                update.effective_user.id,
                backup["mailbox"],
                is_active=backup.get("mailbox_active", False),
            )

        restored_did = backup["did"]
        clear_import_state(context)
        await update.effective_chat.send_message(
            "✅ Identity Restored!\n\n"
            f"Your DID:\n{restored_did}",
            reply_markup=identity_keyboard(),
        )
        return ConversationHandler.END

    except InvalidTag:
        attempts += 1
        context.user_data["import_attempts"] = attempts

        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_import_state(context)
            await update.effective_chat.send_message(
                "❌ Import failed after 3 attempts.",
                reply_markup=no_identity_keyboard(),
            )
            return ConversationHandler.END

        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return IMPORT_PASSWORD

    except Exception:
        clear_import_state(context)
        await update.effective_chat.send_message(
            "❌ Backup verification failed.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END


async def cancel_backup_import(update: Update, context: ContextTypes.DEFAULT_TYPE):
    clear_import_state(context)
    await update.message.reply_text(
        "Backup import cancelled.",
        reply_markup=main_menu_keyboard(),
    )
    return ConversationHandler.END


# =========================================================
# Signed room message conversation
# =========================================================

async def start_signed_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    identity = get_identity(update.effective_user.id)
    if not identity:
        await query.edit_message_text(
            "🪪 You need a DID before sending signed messages.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END

    room = context.user_data.get("current_room")
    if not room:
        await query.edit_message_text(
            "❌ No room selected. Open Browse Rooms first.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    clear_send_state(context)
    await query.edit_message_text(
        "✍️ Send Signed Message\n\n"
        f"Room: {room}\n\n"
        "Send the message you want to publish.\n\n"
        "Use /cancel to stop."
    )
    return SEND_TEXT


async def receive_signed_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cleaned_text = sweep_text(update.message.text)
    except ValueError:
        await update.message.reply_text(
            "❌ Message is empty or longer than 4096 characters."
        )
        return SEND_TEXT

    context.user_data["pending_send_text"] = cleaned_text
    context.user_data["send_attempts"] = 0
    await update.message.reply_text(
        "🔐 Now send your DID password.\n\n"
        "It will only be used to decrypt your seed temporarily and sign this message."
    )
    return SEND_PASSWORD


async def receive_send_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)

    text = context.user_data.get("pending_send_text")
    room = context.user_data.get("current_room")
    identity = get_identity(update.effective_user.id)

    if not text or not room or not identity:
        clear_send_state(context)
        await update.effective_chat.send_message(
            "❌ Send session expired.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    attempts = context.user_data.get("send_attempts", 0)

    try:
        seed = decrypt_seed(
            identity["encrypted_seed"],
            identity["salt"],
            identity["encryption_nonce"],
            password,
        )
    except InvalidTag:
        attempts += 1
        context.user_data["send_attempts"] = attempts

        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_send_state(context)
            await update.effective_chat.send_message(
                "❌ Signing cancelled after 3 incorrect password attempts.",
                reply_markup=main_menu_keyboard(),
            )
            return ConversationHandler.END

        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return SEND_PASSWORD

    try:
        if not hmac.compare_digest(did_from_seed(seed), identity["did"]):
            raise ValueError("Stored identity mismatch")

        nonce = get_next_nonce(update.effective_user.id, room)
        sent_text = send_signed_message(
            room,
            text,
            identity["did"],
            seed,
            nonce,
        )
        clear_send_state(context)

        await update.effective_chat.send_message(
            "✅ Signed message sent!\n\n"
            f"Room: {room}\n\n"
            f"From:\n{identity['did']}\n\n"
            f"Message:\n{sent_text}",
            reply_markup=room_keyboard(),
        )
        return ConversationHandler.END

    except requests.HTTPError as error:
        clear_send_state(context)
        response_text = error.response.text[:500] if error.response is not None else ""
        await update.effective_chat.send_message(
            "❌ Technocore rejected the signed message.\n\n"
            f"{response_text}",
            reply_markup=room_keyboard(),
        )
        return ConversationHandler.END

    except requests.RequestException:
        clear_send_state(context)
        await update.effective_chat.send_message(
            "⚠️ Network error while sending.",
            reply_markup=room_keyboard(),
        )
        return ConversationHandler.END

    except Exception as error:
        print("Signing error:", repr(error))
        clear_send_state(context)
        await update.effective_chat.send_message(
            "❌ Could not sign the message.",
            reply_markup=room_keyboard(),
        )
        return ConversationHandler.END


async def cancel_signed_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    clear_send_state(context)
    await update.message.reply_text(
        "Signed message cancelled.",
        reply_markup=room_keyboard(),
    )
    return ConversationHandler.END


# =========================================================
# Mailbox activation conversation
# =========================================================

async def start_mailbox_activation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query
    await query.answer()

    identity = get_identity(update.effective_user.id)
    mailbox = get_mailbox(update.effective_user.id)

    if not identity:
        await query.edit_message_text(
            "🪪 You need a DID before activating a mailbox.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END

    if not mailbox:
        await query.edit_message_text(
            "📬 Generate a mailbox address first.",
            reply_markup=mailbox_keyboard(None),
        )
        return ConversationHandler.END

    if mailbox["is_active"]:
        await query.edit_message_text(
            mailbox_text(mailbox),
            reply_markup=mailbox_keyboard(mailbox),
        )
        return ConversationHandler.END

    context.user_data["mailbox_activation_attempts"] = 0

    await query.edit_message_text(
        "⚡ Activate Technocore Mailbox\n\n"
        f"Candidate address:\n{mailbox['room']}\n\n"
        "Activation sends signed initialization messages to Technocore. "
        "The mailbox is only considered created if the server accepts them.\n\n"
        "🔐 Send your DID password now.\n\n"
        "The password will not be stored. Use /cancel to stop."
    )

    return MAILBOX_ACTIVATE_PASSWORD


async def receive_mailbox_activation_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = update.message.text
    await delete_sensitive_message(update)

    identity = get_identity(update.effective_user.id)
    mailbox = get_mailbox(update.effective_user.id)

    if not identity or not mailbox:
        await update.effective_chat.send_message(
            "❌ Mailbox activation session expired.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    if mailbox["is_active"]:
        await update.effective_chat.send_message(
            mailbox_text(mailbox),
            reply_markup=mailbox_keyboard(mailbox),
        )
        return ConversationHandler.END

    attempts = context.user_data.get("mailbox_activation_attempts", 0)

    try:
        seed = decrypt_seed(
            identity["encrypted_seed"],
            identity["salt"],
            identity["encryption_nonce"],
            password,
        )
    except InvalidTag:
        attempts += 1
        context.user_data["mailbox_activation_attempts"] = attempts

        if attempts >= MAX_PASSWORD_ATTEMPTS:
            context.user_data.pop("mailbox_activation_attempts", None)
            await update.effective_chat.send_message(
                "❌ Mailbox activation cancelled after 3 incorrect password attempts.",
                reply_markup=mailbox_keyboard(mailbox),
            )
            return ConversationHandler.END

        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return MAILBOX_ACTIVATE_PASSWORD

    try:
        if not hmac.compare_digest(did_from_seed(seed), identity["did"]):
            raise ValueError("Stored identity mismatch")

        # First accepted write creates the mailbox room.
        first_nonce = get_next_nonce(
            update.effective_user.id,
            mailbox["room"],
        )
        send_signed_message(
            mailbox["room"],
            "Technocore Gateway mailbox initialized.",
            identity["did"],
            seed,
            first_nonce,
        )

        # A second write moves the room beyond the special first-message
        # retention case used by Technocore.
        second_nonce = get_next_nonce(
            update.effective_user.id,
            mailbox["room"],
        )
        send_signed_message(
            mailbox["room"],
            "Technocore Gateway mailbox ready.",
            identity["did"],
            seed,
            second_nonce,
        )

        mark_mailbox_active(update.effective_user.id)
        context.user_data.pop("mailbox_activation_attempts", None)
        mailbox = get_mailbox(update.effective_user.id)

        await update.effective_chat.send_message(
            "✅ Mailbox activated on Technocore!\n\n"
            f"Address:\n{mailbox['room']}\n\n"
            "Two signed initialization messages were accepted, so the mailbox now "
            "exists on the server.",
            reply_markup=mailbox_keyboard(mailbox),
        )
        return ConversationHandler.END

    except requests.HTTPError as error:
        context.user_data.pop("mailbox_activation_attempts", None)
        response_text = (
            error.response.text[:700]
            if error.response is not None
            else ""
        )

        if "room limit reached" in response_text.lower():
            await update.effective_chat.send_message(
                "⏳ Mailbox activation is temporarily blocked by Technocore capacity.\n\n"
                "The hosted server is refusing creation of new rooms right now. "
                "Your candidate mailbox address is still stored locally, but it does "
                "NOT exist on Technocore yet.\n\n"
                "Nothing is lost — use ⚡ Activate Mailbox later to retry.\n\n"
                f"Server response:\n{response_text}",
                reply_markup=mailbox_keyboard(mailbox),
            )
        else:
            await update.effective_chat.send_message(
                "❌ Technocore rejected mailbox activation.\n\n"
                f"{response_text}",
                reply_markup=mailbox_keyboard(mailbox),
            )

        return ConversationHandler.END

    except requests.RequestException:
        context.user_data.pop("mailbox_activation_attempts", None)
        await update.effective_chat.send_message(
            "⚠️ Network error during mailbox activation. "
            "The mailbox was not marked active; retry later.",
            reply_markup=mailbox_keyboard(mailbox),
        )
        return ConversationHandler.END

    except Exception as error:
        print("Mailbox activation error:", repr(error))
        context.user_data.pop("mailbox_activation_attempts", None)
        await update.effective_chat.send_message(
            "❌ Could not activate the mailbox.",
            reply_markup=mailbox_keyboard(mailbox),
        )
        return ConversationHandler.END


async def cancel_mailbox_activation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    context.user_data.pop("mailbox_activation_attempts", None)
    mailbox = get_mailbox(update.effective_user.id)

    await update.message.reply_text(
        "Mailbox activation cancelled.",
        reply_markup=mailbox_keyboard(mailbox),
    )
    return ConversationHandler.END


# =========================================================
# Mailbox send conversation
# =========================================================

async def start_mailbox_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    identity = get_identity(update.effective_user.id)
    if not identity:
        await query.edit_message_text(
            "🪪 You need a DID before sending mailbox messages.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END

    own_mailbox = get_mailbox(update.effective_user.id)
    clear_mailbox_send_state(context)

    own_hint = ""
    if own_mailbox and own_mailbox["is_active"]:
        own_hint = (
            "\n\nFor testing, you can send to your own mailbox:\n"
            f"{own_mailbox['room']}"
        )

    await query.edit_message_text(
        "✉️ Send to Technocore Mailbox\n\n"
        "Send the target mailbox address. It must start with mb-."
        f"{own_hint}\n\n"
        "Use /cancel to stop."
    )
    return MAILBOX_TARGET


async def receive_mailbox_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()

    if not ROOM_NAME_RE.fullmatch(target) or not target.startswith("mb-"):
        await update.message.reply_text(
            "❌ Invalid mailbox address.\n\n"
            "Example format:\nmb-p-0123456789abcdef..."
        )
        return MAILBOX_TARGET

    own_mailbox = get_mailbox(update.effective_user.id)
    if (
        own_mailbox
        and target == own_mailbox["room"]
        and not own_mailbox["is_active"]
    ):
        await update.message.reply_text(
            "⏳ Your mailbox address has not been activated on Technocore yet.\n\n"
            "Open 📬 Mailbox and use ⚡ Activate Mailbox first."
        )
        return MAILBOX_TARGET

    context.user_data["pending_mailbox_target"] = target
    await update.message.reply_text(
        "📝 Now send the message you want to deliver to this mailbox."
    )
    return MAILBOX_TEXT


async def receive_mailbox_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cleaned_text = sweep_text(update.message.text)
    except ValueError:
        await update.message.reply_text(
            "❌ Message is empty or longer than 4096 characters."
        )
        return MAILBOX_TEXT

    context.user_data["pending_mailbox_text"] = cleaned_text
    context.user_data["mailbox_send_attempts"] = 0

    await update.message.reply_text(
        "🔐 Send your DID password to sign the mailbox message.\n\n"
        "The password will not be stored."
    )
    return MAILBOX_PASSWORD


async def receive_mailbox_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)

    target = context.user_data.get("pending_mailbox_target")
    text = context.user_data.get("pending_mailbox_text")
    identity = get_identity(update.effective_user.id)

    if not target or not text or not identity:
        clear_mailbox_send_state(context)
        await update.effective_chat.send_message(
            "❌ Mailbox send session expired.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    attempts = context.user_data.get("mailbox_send_attempts", 0)

    try:
        seed = decrypt_seed(
            identity["encrypted_seed"],
            identity["salt"],
            identity["encryption_nonce"],
            password,
        )
    except InvalidTag:
        attempts += 1
        context.user_data["mailbox_send_attempts"] = attempts

        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_mailbox_send_state(context)
            await update.effective_chat.send_message(
                "❌ Mailbox send cancelled after 3 incorrect password attempts.",
                reply_markup=main_menu_keyboard(),
            )
            return ConversationHandler.END

        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return MAILBOX_PASSWORD

    try:
        if not hmac.compare_digest(did_from_seed(seed), identity["did"]):
            raise ValueError("Stored identity mismatch")

        nonce = get_next_nonce(update.effective_user.id, target)
        sent_text = send_signed_message(
            target,
            text,
            identity["did"],
            seed,
            nonce,
        )
        clear_mailbox_send_state(context)

        await update.effective_chat.send_message(
            "✅ Mailbox message sent!\n\n"
            f"To:\n{target}\n\n"
            f"From:\n{identity['did']}\n\n"
            f"Message:\n{sent_text}",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    except requests.HTTPError as error:
        clear_mailbox_send_state(context)
        response_text = error.response.text[:500] if error.response is not None else ""
        await update.effective_chat.send_message(
            "❌ Technocore rejected the mailbox message.\n\n"
            f"{response_text}",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END

    except Exception as error:
        print("Mailbox send error:", repr(error))
        clear_mailbox_send_state(context)
        await update.effective_chat.send_message(
            "❌ Could not send the mailbox message.",
            reply_markup=main_menu_keyboard(),
        )
        return ConversationHandler.END


async def cancel_mailbox_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    clear_mailbox_send_state(context)
    await update.message.reply_text(
        "Mailbox message cancelled.",
        reply_markup=main_menu_keyboard(),
    )
    return ConversationHandler.END


# =========================================================
# Room watch notifications
# =========================================================

async def watch_rooms_job(context: ContextTypes.DEFAULT_TYPE):
    watches = get_all_watches()
    if not watches:
        return

    watches_by_room = {}
    for watch in watches:
        watches_by_room.setdefault(watch["room"], []).append(watch)

    for room, room_watches in watches_by_room.items():
        since = min(watch["last_seq"] for watch in room_watches)

        try:
            room_data = await asyncio.to_thread(
                get_room_updates,
                room,
                since,
            )
        except requests.HTTPError as error:
            status = error.response.status_code if error.response is not None else None

            if status == 404:
                for watch in room_watches:
                    delete_room_watch(watch["telegram_user_id"], room)
                    try:
                        await context.bot.send_message(
                            chat_id=watch["chat_id"],
                            text=(
                                "🔕 Room watch stopped\n\n"
                                f"{room} no longer exists on Technocore."
                            ),
                            reply_markup=main_menu_keyboard(),
                        )
                    except Exception:
                        pass
            continue
        except (requests.RequestException, ValueError):
            continue

        messages = room_data.get("messages", [])
        latest_seq = room_data.get("last_seq", since) or since
        first_seq = room_data.get("first_seq")

        for watch in room_watches:
            watcher_last_seq = watch["last_seq"]
            new_messages = [
                message
                for message in messages
                if isinstance(message.get("seq"), int)
                and message["seq"] > watcher_last_seq
            ]

            missed = (
                isinstance(first_seq, int)
                and first_seq > watcher_last_seq + 1
            )

            if new_messages:
                try:
                    await context.bot.send_message(
                        chat_id=watch["chat_id"],
                        text=format_watch_notification(
                            room,
                            new_messages,
                            missed=missed,
                        ),
                        reply_markup=watch_notification_keyboard(room),
                    )
                except Exception as error:
                    print(
                        "Watch notification error:",
                        room,
                        watch["telegram_user_id"],
                        repr(error),
                    )

            if latest_seq > watcher_last_seq:
                update_room_watch_seq(
                    watch["telegram_user_id"],
                    room,
                    latest_seq,
                )


# =========================================================
# General buttons
# =========================================================

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    user_id = update.effective_user.id

    if data == "home":
        await query.edit_message_text(
            "⚡ Technocore Gateway\n\nChoose an option:",
            reply_markup=main_menu_keyboard(),
        )
        return

    if data == "about":
        await query.edit_message_text(
            "ℹ️ About Technocore Gateway\n\n"
            "Current features:\n"
            "• Browse active rooms\n"
            "• Read latest room messages\n"
            "• Create Ed25519 DID\n"
            "• Encrypted key storage\n"
            "• Export / restore backup\n"
            "• Send signed room messages\n"
            "• Generate and activate an unlisted signed-only mailbox\n"
            "• Capacity-aware mailbox activation\n"
            "• Read and send mailbox messages\n"
            "• Watch existing rooms with Telegram notifications\n"
            "• Publish the canonical sharded DID directory profile\n"
            "• Advertise an active mailbox in the DID note\n\n"
            "Next:\n"
            "• X25519 key publishing + optional E2E messaging\n"
            "• Mailbox notifications when capacity allows activation\n"
            "• README cleanup and 24/7 deployment",
            reply_markup=main_menu_keyboard(),
        )
        return

    if data == "my_identity":
        identity = get_identity(user_id)
        if identity:
            await query.edit_message_text(
                identity_text(identity),
                reply_markup=identity_keyboard(),
            )
        else:
            await query.edit_message_text(
                "🪪 No identity found.",
                reply_markup=no_identity_keyboard(),
            )
        return

    if data == "did_profile":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 You need a DID before publishing a directory profile.",
                reply_markup=no_identity_keyboard(),
            )
            return

        mailbox = get_mailbox(user_id)

        try:
            remote_profile = get_did_directory_profile(identity["did"])
            await query.edit_message_text(
                did_profile_text(identity, mailbox, remote_profile),
                reply_markup=did_profile_keyboard(remote_profile["value"] is not None),
            )
        except requests.RequestException:
            await query.edit_message_text(
                "❌ Could not read the Technocore DID directory right now.",
                reply_markup=identity_keyboard(),
            )
        return

    if data == "publish_did_profile":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 You need a DID before publishing a directory profile.",
                reply_markup=no_identity_keyboard(),
            )
            return

        mailbox = get_mailbox(user_id)

        try:
            result = publish_did_directory_profile(identity, mailbox)
            remote_profile = get_did_directory_profile(identity["did"])

            if result["status"] == "unchanged":
                prefix = "✅ Your directory profile is already current."
            elif result["status"] == "updated":
                prefix = "✅ DID directory profile updated!"
            else:
                prefix = "✅ DID directory profile published!"

            mailbox_note = ""
            if mailbox and not mailbox["is_active"]:
                mailbox_note = (
                    "\n\n⏳ Your local mailbox is still inactive, so it was intentionally "
                    "NOT advertised. Publish again after mailbox activation succeeds."
                )

            await query.edit_message_text(
                prefix
                + "\n\n"
                + did_profile_text(identity, mailbox, remote_profile)
                + mailbox_note,
                reply_markup=did_profile_keyboard(True),
            )
        except DirectoryProfileConflictError as error:
            conflicting_value = str(error)[:1200]
            await query.edit_message_text(
                "🚨 DID directory conflict detected.\n\n"
                "The sharded directory path currently contains a value that does not "
                "start with your DID. The bot refused to overwrite it automatically.\n\n"
                f"Current remote value:\n{conflicting_value}\n\n"
                "Remember: ordinary DID notes are world-writable and are not identity proof.",
                reply_markup=did_profile_keyboard(True),
            )
        except requests.HTTPError as error:
            response_text = (
                strip_budget_footer(error.response.text)[:1000]
                if error.response is not None
                else ""
            )
            await query.edit_message_text(
                "❌ Technocore rejected the DID directory update.\n\n"
                f"{response_text}",
                reply_markup=did_profile_keyboard(False),
            )
        except requests.RequestException:
            await query.edit_message_text(
                "⚠️ Network error while publishing the DID directory profile.",
                reply_markup=did_profile_keyboard(False),
            )
        except ValueError as error:
            await query.edit_message_text(
                f"❌ Could not build the DID profile: {error}",
                reply_markup=identity_keyboard(),
            )
        return

    if data == "export_backup":
        identity = get_identity(user_id)
        if not identity:
            return

        backup_file = create_backup_file(identity, get_mailbox(user_id))
        filename = f"technocore-backup-{identity['did'][-8:]}.json"
        await query.message.reply_document(
            document=backup_file,
            filename=filename,
            caption=(
                "📦 Encrypted Technocore Identity Backup\n\n"
                "Keep this file safe."
            ),
        )
        return

    if data == "watched_rooms":
        watches = get_user_watches(user_id)
        await query.edit_message_text(
            watched_rooms_text(watches),
            reply_markup=watched_rooms_keyboard(watches),
        )
        return

    if data == "watch_current_room":
        room = context.user_data.get("current_room")
        if not room:
            await query.edit_message_text(
                "❌ No room selected. Open Browse Rooms first.",
                reply_markup=main_menu_keyboard(),
            )
            return

        if get_room_watch(user_id, room):
            watches = get_user_watches(user_id)
            await query.edit_message_text(
                f"🔔 You are already watching {room}.",
                reply_markup=watched_rooms_keyboard(watches),
            )
            return

        watches = get_user_watches(user_id)
        if len(watches) >= MAX_WATCHES_PER_USER:
            await query.edit_message_text(
                f"❌ You can watch up to {MAX_WATCHES_PER_USER} rooms in this MVP.",
                reply_markup=watched_rooms_keyboard(watches),
            )
            return

        try:
            room_data = get_room_messages(room, limit=1)
            last_seq = room_data.get("last_seq", 0) or 0
            save_room_watch(
                user_id,
                query.message.chat_id,
                room,
                last_seq,
            )
            await query.edit_message_text(
                "✅ Room watch enabled!\n\n"
                f"Room: {room}\n\n"
                "You will receive Telegram notifications for new messages "
                f"about every {WATCH_POLL_INTERVAL} seconds while the bot is running.",
                reply_markup=watched_rooms_keyboard(get_user_watches(user_id)),
            )
        except (requests.RequestException, ValueError):
            await query.edit_message_text(
                "❌ Could not enable notifications for this room.",
                reply_markup=room_keyboard(),
            )
        return

    if data.startswith("stopwatch:"):
        room = data.split(":", 1)[1]
        if ROOM_NAME_RE.fullmatch(room):
            delete_room_watch(user_id, room)

        watches = get_user_watches(user_id)
        await query.edit_message_text(
            f"🔕 Stopped watching: {room}\n\n" + watched_rooms_text(watches),
            reply_markup=watched_rooms_keyboard(watches),
        )
        return

    if data.startswith("openwatch:"):
        room = data.split(":", 1)[1]
        if not ROOM_NAME_RE.fullmatch(room):
            return

        context.user_data["current_room"] = room
        try:
            room_data = get_room_messages(room)
            text = format_messages(
                f"💬 {room}",
                room_data.get("messages", []),
            )
            await query.edit_message_text(
                text,
                reply_markup=room_keyboard(),
            )
        except (requests.RequestException, ValueError):
            await query.edit_message_text(
                "❌ Could not read this room.",
                reply_markup=main_menu_keyboard(),
            )
        return

    if data == "mailbox_menu":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 Create or import a DID before creating a mailbox.",
                reply_markup=no_identity_keyboard(),
            )
            return

        mailbox = get_mailbox(user_id)

        if mailbox and not mailbox["is_active"]:
            mailbox_is_active_for_identity(
                mailbox,
                identity,
            )
            mailbox = get_mailbox(user_id)

        await query.edit_message_text(
            mailbox_text(mailbox),
            reply_markup=mailbox_keyboard(mailbox),
        )
        return

    if data == "create_mailbox":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 You need a DID first.",
                reply_markup=no_identity_keyboard(),
            )
            return

        existing = get_mailbox(user_id)
        if existing:
            await query.edit_message_text(
                mailbox_text(existing),
                reply_markup=mailbox_keyboard(existing),
            )
            return

        try:
            room = generate_mailbox_name()
            save_mailbox(
                user_id,
                room,
                is_active=False,
            )
            mailbox = get_mailbox(user_id)

            await query.edit_message_text(
                "📬 Mailbox address generated locally.\n\n"
                f"Candidate address:\n{room}\n\n"
                "This is NOT yet a real Technocore mailbox. Press ⚡ Activate Mailbox "
                "to create the room with a signed write. The bot will only mark it active "
                "after Technocore accepts the activation.",
                reply_markup=mailbox_keyboard(mailbox),
            )
        except sqlite3.IntegrityError:
            await query.edit_message_text(
                "❌ Could not generate a unique mailbox address. Please try again.",
                reply_markup=mailbox_keyboard(None),
            )
        return

    if data == "read_mailbox":
        mailbox = get_mailbox(user_id)
        if not mailbox:
            await query.edit_message_text(
                "📬 You do not have a mailbox yet.",
                reply_markup=mailbox_keyboard(None),
            )
            return

        if not mailbox["is_active"]:
            await query.edit_message_text(
                "⏳ This mailbox address has not been activated on Technocore yet.",
                reply_markup=mailbox_keyboard(mailbox),
            )
            return

        try:
            mailbox_data = get_room_messages(
                mailbox["room"],
                limit=MAILBOX_MESSAGES_LIMIT,
            )
            messages = mailbox_data.get("messages", [])
            last_seq = mailbox_data.get("last_seq", 0)

            if last_seq:
                update_mailbox_last_read(user_id, last_seq)

            text = format_messages(
                f"📥 Mailbox: {mailbox['room']}",
                messages,
            )
            await query.edit_message_text(
                text,
                reply_markup=mailbox_read_keyboard(),
            )
        except (requests.RequestException, ValueError):
            await query.edit_message_text(
                "❌ Could not read your mailbox.",
                reply_markup=mailbox_keyboard(mailbox),
            )
        return

    if data == "show_rooms":
        try:
            text, keyboard = build_rooms_menu(context)
            await query.edit_message_text(text, reply_markup=keyboard)
        except (requests.RequestException, ValueError):
            await query.edit_message_text(
                "❌ Could not connect to Technocore.",
                reply_markup=main_menu_keyboard(),
            )
        return

    if data.startswith("room:"):
        try:
            index = int(data.split(":", 1)[1])
            room_names = context.user_data.get("room_names", [])
            room_name = room_names[index]
            context.user_data["current_room"] = room_name

            room_data = get_room_messages(room_name)
            text = format_messages(
                f"💬 {room_name}",
                room_data.get("messages", []),
            )
            await query.edit_message_text(
                text,
                reply_markup=room_keyboard(),
            )
        except (requests.RequestException, ValueError, IndexError):
            await query.edit_message_text(
                "❌ Could not read room.",
                reply_markup=main_menu_keyboard(),
            )


# =========================================================
# Application
# =========================================================

def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set")

    init_database()

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    did_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(start_create_did, pattern=r"^create_did$")
        ],
        states={
            CREATE_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_did_password)
            ],
            CONFIRM_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, confirm_did_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_did_creation)],
        allow_reentry=True,
    )

    import_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(start_import_backup, pattern=r"^import_backup$")
        ],
        states={
            IMPORT_FILE: [MessageHandler(filters.Document.ALL, receive_backup_file)],
            IMPORT_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_import_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_backup_import)],
        allow_reentry=True,
    )

    signed_message_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(start_signed_message, pattern=r"^send_signed$")
        ],
        states={
            SEND_TEXT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_signed_text)
            ],
            SEND_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_send_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_signed_message)],
        allow_reentry=True,
    )

    mailbox_activation_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(
                start_mailbox_activation,
                pattern=r"^activate_mailbox$",
            )
        ],
        states={
            MAILBOX_ACTIVATE_PASSWORD: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    receive_mailbox_activation_password,
                )
            ],
        },
        fallbacks=[
            CommandHandler(
                "cancel",
                cancel_mailbox_activation,
            )
        ],
        allow_reentry=True,
    )

    mailbox_send_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(start_mailbox_send, pattern=r"^send_mailbox$")
        ],
        states={
            MAILBOX_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_mailbox_target)
            ],
            MAILBOX_TEXT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_mailbox_text)
            ],
            MAILBOX_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_mailbox_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_mailbox_send)],
        allow_reentry=True,
    )

    app.add_handler(did_conversation)
    app.add_handler(import_conversation)
    app.add_handler(signed_message_conversation)
    app.add_handler(mailbox_activation_conversation)
    app.add_handler(mailbox_send_conversation)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("rooms", rooms))
    app.add_handler(CommandHandler("read", read_room))
    app.add_handler(CommandHandler("watch", watch_command))
    app.add_handler(CommandHandler("unwatch", unwatch_command))
    app.add_handler(CommandHandler("identity", identity_command))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CallbackQueryHandler(button_handler))

    if app.job_queue is None:
        raise RuntimeError(
            'JobQueue is unavailable. Install: python-telegram-bot[job-queue]'
        )

    app.job_queue.run_repeating(
        watch_rooms_job,
        interval=WATCH_POLL_INTERVAL,
        first=5,
        name="technocore-room-watch",
    )

    print("Technocore Gateway is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
