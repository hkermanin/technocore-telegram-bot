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
REQUEST_TIMEOUT = 10
TELEGRAM_TEXT_LIMIT = 3900
DATABASE_PATH = "technocore.db"

ROOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_MESSAGE_CHARS = 4096

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
) = range(9)


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
                last_read_seq INTEGER NOT NULL DEFAULT 0
            )
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
            SELECT telegram_user_id, room, created_at, last_read_seq
            FROM mailboxes
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        ).fetchone()


def save_mailbox(telegram_user_id, room):
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO mailboxes (
                telegram_user_id, room, created_at, last_read_seq
            )
            VALUES (?, ?, ?, 0)
            """,
            (telegram_user_id, room, created_at),
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

    return {
        "did": did,
        "encrypted_seed": encrypted_seed,
        "salt": salt,
        "encryption_nonce": encryption_nonce,
        "created_at": created_at,
        "mailbox": mailbox,
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


# =========================================================
# Keyboards
# =========================================================

def main_menu_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔥 Browse Rooms", callback_data="show_rooms")],
            [InlineKeyboardButton("📬 Mailbox", callback_data="mailbox_menu")],
            [
                InlineKeyboardButton("🪪 Create DID", callback_data="create_did"),
                InlineKeyboardButton("👤 My Identity", callback_data="my_identity"),
            ],
            [InlineKeyboardButton("♻️ Import Backup", callback_data="import_backup")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about")],
        ]
    )


def identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📦 Export Backup", callback_data="export_backup")],
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


def mailbox_keyboard(has_mailbox):
    if not has_mailbox:
        return InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📬 Create Mailbox", callback_data="create_mailbox")],
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
            [InlineKeyboardButton("⬅️ Back to Rooms", callback_data="show_rooms")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
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


def generate_mailbox_name():
    return "mb-p-" + secrets.token_hex(16)


def mailbox_text(mailbox):
    if not mailbox:
        return (
            "📬 Technocore Mailbox\n\n"
            "You do not have a mailbox yet.\n\n"
            "A mailbox created here will use an unlisted random mb-p- address and will "
            "accept signed writes only."
        )

    return (
        "📬 Your Technocore Mailbox\n\n"
        f"Address:\n{mailbox['room']}\n\n"
        f"Created:\n{mailbox['created_at']}\n\n"
        "✅ Unlisted from public room discovery\n"
        "✅ Signed writes only\n"
        "⚠️ Not end-to-end encrypted: anyone who learns the mailbox name can read it."
    )


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
        "Browse rooms, manage your DID, send signed messages and use a Technocore mailbox.",
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
            save_mailbox(update.effective_user.id, backup["mailbox"])

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
    if own_mailbox:
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
            "• Create an unlisted signed-only mailbox\n"
            "• Read and send mailbox messages\n\n"
            "Next:\n"
            "• Publish DID + mailbox directory note\n"
            "• Telegram mailbox notifications\n"
            "• Optional E2E encrypted messaging",
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

    if data == "mailbox_menu":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 Create or import a DID before creating a mailbox.",
                reply_markup=no_identity_keyboard(),
            )
            return

        mailbox = get_mailbox(user_id)
        await query.edit_message_text(
            mailbox_text(mailbox),
            reply_markup=mailbox_keyboard(mailbox is not None),
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
                reply_markup=mailbox_keyboard(True),
            )
            return

        try:
            room = generate_mailbox_name()
            save_mailbox(user_id, room)
            mailbox = get_mailbox(user_id)
            await query.edit_message_text(
                "✅ Mailbox created!\n\n"
                f"Address:\n{room}\n\n"
                "The address is random, unlisted and accepts signed writes only.\n\n"
                "⚠️ It is not E2E encrypted. Anyone who learns the address can read it.",
                reply_markup=mailbox_keyboard(True),
            )
        except sqlite3.IntegrityError:
            await query.edit_message_text(
                "❌ Could not create a unique mailbox. Please try again.",
                reply_markup=mailbox_keyboard(False),
            )
        return

    if data == "read_mailbox":
        mailbox = get_mailbox(user_id)
        if not mailbox:
            await query.edit_message_text(
                "📬 You do not have a mailbox yet.",
                reply_markup=mailbox_keyboard(False),
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
                reply_markup=mailbox_keyboard(True),
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
    app.add_handler(mailbox_send_conversation)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("rooms", rooms))
    app.add_handler(CommandHandler("read", read_room))
    app.add_handler(CommandHandler("identity", identity_command))
    app.add_handler(CallbackQueryHandler(button_handler))

    print("Technocore Gateway is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
