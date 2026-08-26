import base64
import io
import json
from datetime import datetime, timezone

from config import (
    AES_NONCE_SIZE,
    BACKUP_FORMAT,
    BACKUP_VERSION,
    ROOM_NAME_RE,
    SALT_SIZE,
    SCRYPT_KEY_LENGTH,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)
from crypto_utils import b64url_decode
from database import get_e2e_chats, get_e2e_key


def encode_base64(value):
    return base64.b64encode(value).decode("ascii")


def decode_base64(value):
    if not isinstance(value, str):
        raise ValueError("Invalid base64 field")
    return base64.b64decode(value, validate=True)


def backup_encrypted_blob(row, encrypted_field):
    if row is None:
        return None
    return {
        "encrypted": encode_base64(row[encrypted_field]),
        "salt": encode_base64(row["salt"]),
        "nonce": encode_base64(row["encryption_nonce"]),
    }


def create_backup_data(identity, mailbox=None):
    user_id = identity["telegram_user_id"]
    e2e_key = get_e2e_key(user_id)
    e2e_chats = get_e2e_chats(user_id)

    e2e_data = None
    if e2e_key:
        e2e_data = {
            "public_key": e2e_key["public_key"],
            "created_at": e2e_key["created_at"],
            "private_key_encryption": backup_encrypted_blob(
                e2e_key,
                "encrypted_private_key",
            ),
        }

    chat_backups = []
    for chat in e2e_chats:
        chat_backups.append({
            "peer_did": chat["peer_did"],
            "room": chat["room"],
            "last_read_seq": int(chat["last_read_seq"]),
            "created_at": chat["created_at"],
            "room_key_encryption": backup_encrypted_blob(
                chat,
                "encrypted_room_key",
            ),
        })

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
        "e2e": e2e_data,
        "e2e_chats": chat_backups,
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


def validate_backup_encrypted_blob(data, field_name):
    if not isinstance(data, dict):
        raise ValueError(f"Invalid {field_name} encryption")
    encrypted = decode_base64(data.get("encrypted"))
    salt = decode_base64(data.get("salt"))
    nonce = decode_base64(data.get("nonce"))
    if len(encrypted) != 48 or len(salt) != SALT_SIZE or len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"Invalid {field_name} encrypted fields")
    return encrypted, salt, nonce


def validate_backup_data(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid backup")
    if data.get("format") != BACKUP_FORMAT:
        raise ValueError("Unknown backup format")

    version = data.get("version")
    if version not in (1, 2):
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

    e2e = None
    e2e_chats = []
    if version >= 2:
        raw_e2e = data.get("e2e")
        if raw_e2e is not None:
            if not isinstance(raw_e2e, dict):
                raise ValueError("Invalid E2E backup")
            public_key = raw_e2e.get("public_key")
            public_raw = b64url_decode(public_key)
            if len(public_raw) != 32:
                raise ValueError("Invalid X25519 public key in backup")
            encrypted_private, e2e_salt, e2e_nonce = validate_backup_encrypted_blob(
                raw_e2e.get("private_key_encryption"),
                "E2E private key",
            )
            e2e = {
                "public_key": public_key,
                "encrypted_private_key": encrypted_private,
                "salt": e2e_salt,
                "encryption_nonce": e2e_nonce,
                "created_at": raw_e2e.get("created_at")
                if isinstance(raw_e2e.get("created_at"), str)
                else datetime.now(timezone.utc).isoformat(),
            }

        raw_chats = data.get("e2e_chats", [])
        if not isinstance(raw_chats, list) or len(raw_chats) > 100:
            raise ValueError("Invalid E2E chats backup")
        for raw_chat in raw_chats:
            if not isinstance(raw_chat, dict):
                raise ValueError("Invalid E2E chat entry")
            peer_did = raw_chat.get("peer_did")
            room = raw_chat.get("room")
            if not isinstance(peer_did, str) or not peer_did.startswith("did:key:z6Mk"):
                raise ValueError("Invalid E2E peer DID")
            if not isinstance(room, str) or not ROOM_NAME_RE.fullmatch(room) or not room.startswith("p-"):
                raise ValueError("Invalid E2E room")
            encrypted_room_key, chat_salt, chat_nonce = validate_backup_encrypted_blob(
                raw_chat.get("room_key_encryption"),
                "E2E room key",
            )
            last_read_seq = raw_chat.get("last_read_seq", 0)
            if not isinstance(last_read_seq, int) or last_read_seq < 0:
                last_read_seq = 0
            e2e_chats.append({
                "peer_did": peer_did,
                "room": room,
                "encrypted_room_key": encrypted_room_key,
                "salt": chat_salt,
                "encryption_nonce": chat_nonce,
                "last_read_seq": last_read_seq,
                "created_at": raw_chat.get("created_at")
                if isinstance(raw_chat.get("created_at"), str)
                else datetime.now(timezone.utc).isoformat(),
            })

    return {
        "version": version,
        "did": did,
        "encrypted_seed": encrypted_seed,
        "salt": salt,
        "encryption_nonce": encryption_nonce,
        "created_at": created_at,
        "mailbox": mailbox,
        "mailbox_active": mailbox_active,
        "e2e": e2e,
        "e2e_chats": e2e_chats,
    }
