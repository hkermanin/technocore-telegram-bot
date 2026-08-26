import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
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


# =========================================================
# Configuration
# =========================================================

TECHNOCORE_API = "https://technocore.chat"

ROOMS_LIMIT = 5
MESSAGES_LIMIT = 3
REQUEST_TIMEOUT = 10

DATABASE_PATH = "technocore.db"

# Technocore did:key / Ed25519
MULTICODEC_ED25519 = b"\xed\x01"

# Same categories used by Technocore's official signer
INVISIBLE_CATEGORIES = (
    "Cc",
    "Cf",
    "Cs",
    "Co",
    "Zl",
    "Zp",
)

MAX_MESSAGE_CHARS = 4096

# Encryption
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32

SALT_SIZE = 16
AES_NONCE_SIZE = 12

MIN_PASSWORD_LENGTH = 10

# Backup
BACKUP_FORMAT = "technocore-gateway-backup"
BACKUP_VERSION = 1
MAX_BACKUP_SIZE = 50_000

MAX_PASSWORD_ATTEMPTS = 3

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


# =========================================================
# Conversation States
# =========================================================

(
    CREATE_PASSWORD,
    CONFIRM_PASSWORD,
    IMPORT_FILE,
    IMPORT_PASSWORD,
    SEND_TEXT,
    SEND_PASSWORD,
) = range(6)


# =========================================================
# Database
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )

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
                PRIMARY KEY (
                    telegram_user_id,
                    room
                )
            )
            """
        )

        connection.commit()


def get_identity(
    telegram_user_id,
):
    with get_db_connection() as connection:
        identity = connection.execute(
            """
            SELECT
                telegram_user_id,
                did,
                encrypted_seed,
                salt,
                encryption_nonce,
                created_at
            FROM identities
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        ).fetchone()

    return identity


def save_identity(
    telegram_user_id,
    did,
    encrypted_seed,
    salt,
    encryption_nonce,
    created_at=None,
):
    if created_at is None:
        created_at = datetime.now(
            timezone.utc
        ).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO identities (
                telegram_user_id,
                did,
                encrypted_seed,
                salt,
                encryption_nonce,
                created_at
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


def get_next_nonce(
    telegram_user_id,
    room,
):
    # Current nanosecond clock is 19 digits,
    # which fits Technocore's nonce rule.
    clock_nonce = time.time_ns()

    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT last_nonce
            FROM nonces
            WHERE telegram_user_id = ?
              AND room = ?
            """,
            (
                telegram_user_id,
                room,
            ),
        ).fetchone()

        if row:
            nonce = max(
                clock_nonce,
                row["last_nonce"] + 1,
            )

            connection.execute(
                """
                UPDATE nonces
                SET last_nonce = ?
                WHERE telegram_user_id = ?
                  AND room = ?
                """,
                (
                    nonce,
                    telegram_user_id,
                    room,
                ),
            )

        else:
            nonce = clock_nonce

            connection.execute(
                """
                INSERT INTO nonces (
                    telegram_user_id,
                    room,
                    last_nonce
                )
                VALUES (?, ?, ?)
                """,
                (
                    telegram_user_id,
                    room,
                    nonce,
                ),
            )

        connection.commit()

    return nonce


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

    leading_zeroes = len(raw) - len(
        raw.lstrip(b"\x00")
    )

    number = int.from_bytes(
        raw,
        "big",
    )

    encoded = ""

    while number:
        number, remainder = divmod(
            number,
            58,
        )

        encoded = (
            alphabet[remainder]
            + encoded
        )

    return (
        "1" * leading_zeroes
        + encoded
    )


def create_did_from_private_key(
    private_key,
):
    public_key = (
        private_key.public_key()
    )

    public_key_bytes = (
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    multicodec_key = (
        MULTICODEC_ED25519
        + public_key_bytes
    )

    multibase_key = (
        "z"
        + base58btc_encode(
            multicodec_key
        )
    )

    return (
        f"did:key:{multibase_key}"
    )


def generate_identity():
    seed = secrets.token_bytes(32)

    private_key = (
        Ed25519PrivateKey
        .from_private_bytes(seed)
    )

    did = create_did_from_private_key(
        private_key
    )

    return seed, did


def did_from_seed(seed):
    private_key = (
        Ed25519PrivateKey
        .from_private_bytes(seed)
    )

    return create_did_from_private_key(
        private_key
    )


def derive_encryption_key(
    password,
    salt,
):
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


def encrypt_seed(
    seed,
    password,
):
    salt = secrets.token_bytes(
        SALT_SIZE
    )

    encryption_nonce = (
        secrets.token_bytes(
            AES_NONCE_SIZE
        )
    )

    encryption_key = (
        derive_encryption_key(
            password,
            salt,
        )
    )

    aes = AESGCM(
        encryption_key
    )

    encrypted_seed = aes.encrypt(
        encryption_nonce,
        seed,
        None,
    )

    return (
        encrypted_seed,
        salt,
        encryption_nonce,
    )


def decrypt_seed(
    encrypted_seed,
    salt,
    encryption_nonce,
    password,
):
    encryption_key = (
        derive_encryption_key(
            password,
            salt,
        )
    )

    aes = AESGCM(
        encryption_key
    )

    return aes.decrypt(
        encryption_nonce,
        encrypted_seed,
        None,
    )


# =========================================================
# Technocore Signing
# =========================================================

def sweep_text(text):
    """
    Mirrors Technocore's official single-line sweep.
    """

    cleaned = "".join(
        (
            " "
            if unicodedata.category(character)
            in INVISIBLE_CATEGORIES
            else character
        )
        for character in text
    ).strip()

    if not cleaned:
        raise ValueError(
            "Message is empty after sweep"
        )

    if len(cleaned) > MAX_MESSAGE_CHARS:
        raise ValueError(
            "Message is too long"
        )

    return cleaned


def create_signature(
    seed,
    room,
    nonce,
    text,
):
    private_key = (
        Ed25519PrivateKey
        .from_private_bytes(seed)
    )

    canonical = (
        f"{room}|{nonce}|{text}"
    )

    raw_signature = private_key.sign(
        canonical.encode("utf-8")
    )

    signature = (
        base64.urlsafe_b64encode(
            raw_signature
        )
        .decode("ascii")
        .rstrip("=")
    )

    return signature


def send_signed_message(
    room,
    text,
    did,
    seed,
    nonce,
):
    cleaned_text = sweep_text(
        text
    )

    signature = create_signature(
        seed=seed,
        room=room,
        nonce=nonce,
        text=cleaned_text,
    )

    url = (
        f"{TECHNOCORE_API}/r/{room}"
    )

    payload = {
        "text": cleaned_text,
        "did": did,
        "sig": signature,
        "nonce": str(nonce),
    }

    response = requests.post(
        url,
        json=payload,
        headers={
            "Accept": "application/json",
        },
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return cleaned_text


# =========================================================
# Backup
# =========================================================

def encode_base64(value):
    return base64.b64encode(
        value
    ).decode("ascii")


def decode_base64(value):
    if not isinstance(value, str):
        raise ValueError(
            "Invalid base64 field"
        )

    return base64.b64decode(
        value,
        validate=True,
    )


def create_backup_data(identity):
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "did": identity["did"],
        "key_type": "Ed25519",
        "created_at": identity[
            "created_at"
        ],
        "exported_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "encryption": {
            "cipher": "AES-256-GCM",
            "kdf": {
                "name": "scrypt",
                "n": SCRYPT_N,
                "r": SCRYPT_R,
                "p": SCRYPT_P,
                "length": (
                    SCRYPT_KEY_LENGTH
                ),
            },
            "salt": encode_base64(
                identity["salt"]
            ),
            "nonce": encode_base64(
                identity[
                    "encryption_nonce"
                ]
            ),
            "encrypted_seed": (
                encode_base64(
                    identity[
                        "encrypted_seed"
                    ]
                )
            ),
        },
    }


def create_backup_file(identity):
    data = create_backup_data(
        identity
    )

    content = json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")

    buffer = io.BytesIO(
        content
    )

    buffer.seek(0)

    return buffer


def validate_backup_data(data):
    if not isinstance(data, dict):
        raise ValueError(
            "Invalid backup"
        )

    if (
        data.get("format")
        != BACKUP_FORMAT
    ):
        raise ValueError(
            "Unknown backup format"
        )

    if (
        data.get("version")
        != BACKUP_VERSION
    ):
        raise ValueError(
            "Unsupported backup version"
        )

    if (
        data.get("key_type")
        != "Ed25519"
    ):
        raise ValueError(
            "Unsupported key type"
        )

    did = data.get("did")

    if (
        not isinstance(did, str)
        or not did.startswith(
            "did:key:z6Mk"
        )
    ):
        raise ValueError(
            "Invalid DID"
        )

    encryption = data.get(
        "encryption"
    )

    if not isinstance(
        encryption,
        dict,
    ):
        raise ValueError(
            "Missing encryption data"
        )

    if (
        encryption.get("cipher")
        != "AES-256-GCM"
    ):
        raise ValueError(
            "Unsupported cipher"
        )

    expected_kdf = {
        "name": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "length": SCRYPT_KEY_LENGTH,
    }

    if (
        encryption.get("kdf")
        != expected_kdf
    ):
        raise ValueError(
            "Unsupported KDF settings"
        )

    salt = decode_base64(
        encryption.get("salt")
    )

    encryption_nonce = decode_base64(
        encryption.get("nonce")
    )

    encrypted_seed = decode_base64(
        encryption.get(
            "encrypted_seed"
        )
    )

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "Invalid salt"
        )

    if (
        len(encryption_nonce)
        != AES_NONCE_SIZE
    ):
        raise ValueError(
            "Invalid nonce"
        )

    if len(encrypted_seed) != 48:
        raise ValueError(
            "Invalid encrypted seed"
        )

    created_at = data.get(
        "created_at"
    )

    if not isinstance(
        created_at,
        str,
    ):
        created_at = datetime.now(
            timezone.utc
        ).isoformat()

    return {
        "did": did,
        "encrypted_seed": (
            encrypted_seed
        ),
        "salt": salt,
        "encryption_nonce": (
            encryption_nonce
        ),
        "created_at": created_at,
    }


# =========================================================
# Technocore Read API
# =========================================================

def get_rooms():
    url = (
        f"{TECHNOCORE_API}/rooms"
    )

    params = {
        "format": "json",
        "limit": ROOMS_LIMIT,
    }

    response = requests.get(
        url,
        params=params,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()


def get_room_messages(
    room_name,
):
    safe_room_name = quote(
        room_name,
        safe="",
    )

    url = (
        f"{TECHNOCORE_API}"
        f"/r/{safe_room_name}"
    )

    params = {
        "format": "json",
        "limit": MESSAGES_LIMIT,
    }

    response = requests.get(
        url,
        params=params,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()


# =========================================================
# Telegram Keyboards
# =========================================================

def main_menu_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🔥 Browse Rooms",
                    callback_data=(
                        "show_rooms"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "🪪 Create DID",
                    callback_data=(
                        "create_did"
                    ),
                ),
                InlineKeyboardButton(
                    "👤 My Identity",
                    callback_data=(
                        "my_identity"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "♻️ Import Backup",
                    callback_data=(
                        "import_backup"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "ℹ️ About",
                    callback_data="about",
                ),
            ],
        ]
    )


def identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "📦 Export Backup",
                    callback_data=(
                        "export_backup"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "🏠 Main Menu",
                    callback_data="home",
                ),
            ],
        ]
    )


def no_identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🪪 Create DID",
                    callback_data=(
                        "create_did"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "♻️ Import Backup",
                    callback_data=(
                        "import_backup"
                    ),
                ),
            ],
            [
                InlineKeyboardButton(
                    "🏠 Main Menu",
                    callback_data="home",
                ),
            ],
        ]
    )


def rooms_keyboard(room_names):
    keyboard = []

    for index, room_name in enumerate(
        room_names
    ):
        keyboard.append(
            [
                InlineKeyboardButton(
                    room_name,
                    callback_data=(
                        f"room:{index}"
                    ),
                )
            ]
        )

    keyboard.append(
        [
            InlineKeyboardButton(
                "🔄 Refresh",
                callback_data="show_rooms",
            )
        ]
    )

    keyboard.append(
        [
            InlineKeyboardButton(
                "🏠 Main Menu",
                callback_data="home",
            )
        ]
    )

    return InlineKeyboardMarkup(
        keyboard
    )


def room_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "✍️ Send Signed Message",
                    callback_data=(
                        "send_signed"
                    ),
                )
            ],
            [
                InlineKeyboardButton(
                    "⬅️ Back to Rooms",
                    callback_data=(
                        "show_rooms"
                    ),
                )
            ],
            [
                InlineKeyboardButton(
                    "🏠 Main Menu",
                    callback_data="home",
                )
            ],
        ]
    )


# =========================================================
# Helpers
# =========================================================

def shorten_sender(sender):
    if len(sender) <= 32:
        return sender

    return (
        f"{sender[:20]}"
        f"..."
        f"{sender[-8:]}"
    )


def format_room_messages(
    room_name,
    messages,
):
    if not messages:
        return (
            f"💬 {room_name}\n\n"
            "No messages found."
        )

    text = (
        f"💬 {room_name}\n\n"
    )

    for message in messages:
        seq = message.get(
            "seq",
            "?",
        )

        sender = message.get(
            "from",
            "unknown",
        )

        content = message.get(
            "text",
            "",
        )

        timestamp = message.get(
            "ts",
            "",
        )

        sender = shorten_sender(
            sender
        )

        if len(content) > 700:
            content = (
                content[:700]
                + "..."
            )

        text += f"#{seq}\n"
        text += f"👤 {sender}\n"

        if timestamp:
            text += (
                f"🕒 {timestamp}\n"
            )

        text += f"\n{content}\n"

        text += (
            "\n"
            "────────────"
            "\n\n"
        )

    return text


def build_rooms_menu(context):
    rooms_data = get_rooms()

    rooms = rooms_data.get(
        "rooms",
        [],
    )

    room_names = [
        room["room"]
        for room in rooms
        if "room" in room
    ]

    context.user_data[
        "room_names"
    ] = room_names

    total_rooms = (
        rooms_data.get(
            "total",
            "?",
        )
    )

    text = (
        "🔥 Active Technocore Rooms\n\n"
        f"Technocore currently has "
        f"{total_rooms} rooms.\n\n"
        "Choose a room to read its "
        "latest messages:"
    )

    return (
        text,
        rooms_keyboard(room_names),
    )


async def delete_sensitive_message(
    update,
):
    try:
        if update.message:
            await update.message.delete()

    except Exception:
        pass


def identity_text(identity):
    return (
        "👤 Your Technocore Identity\n\n"
        "DID:\n"
        f"{identity['did']}\n\n"
        "Created:\n"
        f"{identity['created_at']}\n\n"
        "🔐 Your private seed is stored "
        "encrypted in the bot database.\n\n"
        "Your password is NOT stored."
    )


def clear_import_state(context):
    context.user_data.pop(
        "pending_backup",
        None,
    )

    context.user_data.pop(
        "import_attempts",
        None,
    )


def clear_send_state(context):
    context.user_data.pop(
        "pending_send_text",
        None,
    )

    context.user_data.pop(
        "send_attempts",
        None,
    )


# =========================================================
# Commands
# =========================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    await update.message.reply_text(
        "⚡ Technocore Gateway\n\n"
        "Access Technocore directly "
        "from Telegram.\n\n"
        "Browse rooms, manage your DID "
        "and send cryptographically "
        "signed messages.",
        reply_markup=main_menu_keyboard(),
    )


async def rooms(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    try:
        text, keyboard = (
            build_rooms_menu(context)
        )

        await update.message.reply_text(
            text,
            reply_markup=keyboard,
        )

    except (
        requests.RequestException,
        ValueError,
    ):
        await update.message.reply_text(
            "❌ Could not connect "
            "to Technocore."
        )


async def read_room(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    if not context.args:
        await update.message.reply_text(
            "Usage: /read <room>\n\n"
            "Example:\n"
            "/read lobby"
        )

        return

    room_name = context.args[0]

    context.user_data[
        "current_room"
    ] = room_name

    try:
        room_data = (
            get_room_messages(
                room_name
            )
        )

        messages = room_data.get(
            "messages",
            [],
        )

        text = format_room_messages(
            room_name,
            messages,
        )

        await update.message.reply_text(
            text,
            reply_markup=room_keyboard(),
        )

    except (
        requests.RequestException,
        ValueError,
    ):
        await update.message.reply_text(
            f"❌ Could not read room: "
            f"{room_name}"
        )


async def identity_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    telegram_user_id = (
        update.effective_user.id
    )

    identity = get_identity(
        telegram_user_id
    )

    if not identity:
        await update.message.reply_text(
            "🪪 You do not have a "
            "Technocore DID yet.",
            reply_markup=(
                no_identity_keyboard()
            ),
        )

        return

    await update.message.reply_text(
        identity_text(identity),
        reply_markup=identity_keyboard(),
    )


# =========================================================
# DID Creation
# =========================================================

async def start_create_did(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query

    await query.answer()

    telegram_user_id = (
        update.effective_user.id
    )

    existing_identity = (
        get_identity(
            telegram_user_id
        )
    )

    if existing_identity:
        await query.edit_message_text(
            "⚠️ You already have a "
            "Technocore DID.\n\n"
            f"{existing_identity['did']}",
            reply_markup=(
                identity_keyboard()
            ),
        )

        return ConversationHandler.END

    context.user_data.pop(
        "pending_password_hash",
        None,
    )

    await query.edit_message_text(
        "🪪 Create Technocore Identity\n\n"
        "A fresh Ed25519 keypair and "
        "did:key identity will be created.\n\n"
        "🔐 Send a NEW password now.\n"
        f"Minimum length: "
        f"{MIN_PASSWORD_LENGTH} characters.\n\n"
        "IMPORTANT:\n"
        "• Use a unique password.\n"
        "• Never send a wallet seed phrase.\n"
        "• Never send another private key.\n"
        "• Telegram bot chats are not "
        "end-to-end encrypted.\n\n"
        "Use /cancel to stop."
    )

    return CREATE_PASSWORD


async def receive_did_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = (
        update.message.text
    )

    await delete_sensitive_message(
        update
    )

    if (
        len(password)
        < MIN_PASSWORD_LENGTH
    ):
        await (
            update.effective_chat
            .send_message(
                "❌ Password is too short.\n\n"
                f"Please send at least "
                f"{MIN_PASSWORD_LENGTH} "
                "characters."
            )
        )

        return CREATE_PASSWORD

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).digest()

    context.user_data[
        "pending_password_hash"
    ] = password_hash

    await (
        update.effective_chat
        .send_message(
            "🔐 Please send the same "
            "password again to confirm it."
        )
    )

    return CONFIRM_PASSWORD


async def confirm_did_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = (
        update.message.text
    )

    await delete_sensitive_message(
        update
    )

    expected_hash = (
        context.user_data.pop(
            "pending_password_hash",
            None,
        )
    )

    if expected_hash is None:
        await (
            update.effective_chat
            .send_message(
                "❌ Password session expired.",
                reply_markup=(
                    main_menu_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    received_hash = hashlib.sha256(
        password.encode("utf-8")
    ).digest()

    if not hmac.compare_digest(
        expected_hash,
        received_hash,
    ):
        await (
            update.effective_chat
            .send_message(
                "❌ Passwords did not match.\n\n"
                "Send a NEW password "
                "to start again."
            )
        )

        return CREATE_PASSWORD

    telegram_user_id = (
        update.effective_user.id
    )

    try:
        seed, did = (
            generate_identity()
        )

        (
            encrypted_seed,
            salt,
            encryption_nonce,
        ) = encrypt_seed(
            seed,
            password,
        )

        save_identity(
            telegram_user_id,
            did,
            encrypted_seed,
            salt,
            encryption_nonce,
        )

        await (
            update.effective_chat
            .send_message(
                "✅ Technocore Identity "
                "Created!\n\n"
                "Your DID:\n"
                f"{did}\n\n"
                "📦 Remember to keep an "
                "encrypted backup.",
                reply_markup=(
                    identity_keyboard()
                ),
            )
        )

    except sqlite3.IntegrityError:
        await (
            update.effective_chat
            .send_message(
                "❌ An identity already "
                "exists.",
                reply_markup=(
                    main_menu_keyboard()
                ),
            )
        )

    return ConversationHandler.END


async def cancel_did_creation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    context.user_data.pop(
        "pending_password_hash",
        None,
    )

    await update.message.reply_text(
        "DID creation cancelled.",
        reply_markup=main_menu_keyboard(),
    )

    return ConversationHandler.END


# =========================================================
# Backup Import
# =========================================================

async def start_import_backup(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query

    await query.answer()

    telegram_user_id = (
        update.effective_user.id
    )

    if get_identity(
        telegram_user_id
    ):
        await query.edit_message_text(
            "⚠️ You already have a "
            "Technocore identity.",
            reply_markup=identity_keyboard(),
        )

        return ConversationHandler.END

    clear_import_state(
        context
    )

    await query.edit_message_text(
        "♻️ Import Technocore Backup\n\n"
        "Send the encrypted JSON backup "
        "file created by this bot.\n\n"
        "Use /cancel to stop."
    )

    return IMPORT_FILE


async def receive_backup_file(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    document = (
        update.message.document
    )

    if document is None:
        return IMPORT_FILE

    if (
        document.file_size
        and document.file_size
        > MAX_BACKUP_SIZE
    ):
        await update.message.reply_text(
            "❌ Backup file is too large."
        )

        return IMPORT_FILE

    try:
        telegram_file = (
            await document.get_file()
        )

        content = (
            await telegram_file
            .download_as_bytearray()
        )

        await delete_sensitive_message(
            update
        )

        data = json.loads(
            bytes(content).decode(
                "utf-8"
            )
        )

        backup = (
            validate_backup_data(
                data
            )
        )

        context.user_data[
            "pending_backup"
        ] = backup

        context.user_data[
            "import_attempts"
        ] = 0

        await (
            update.effective_chat
            .send_message(
                "✅ Backup recognized.\n\n"
                "DID:\n"
                f"{backup['did']}\n\n"
                "🔐 Send the password "
                "for this identity."
            )
        )

        return IMPORT_PASSWORD

    except Exception:
        clear_import_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "❌ Invalid backup file.",
                reply_markup=(
                    no_identity_keyboard()
                ),
            )
        )

        return ConversationHandler.END


async def receive_import_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = (
        update.message.text
    )

    await delete_sensitive_message(
        update
    )

    backup = (
        context.user_data.get(
            "pending_backup"
        )
    )

    if backup is None:
        return ConversationHandler.END

    attempts = (
        context.user_data.get(
            "import_attempts",
            0,
        )
    )

    try:
        seed = decrypt_seed(
            backup["encrypted_seed"],
            backup["salt"],
            backup[
                "encryption_nonce"
            ],
            password,
        )

        derived_did = did_from_seed(
            seed
        )

        if not hmac.compare_digest(
            derived_did,
            backup["did"],
        ):
            raise ValueError(
                "DID mismatch"
            )

        telegram_user_id = (
            update.effective_user.id
        )

        save_identity(
            telegram_user_id,
            backup["did"],
            backup["encrypted_seed"],
            backup["salt"],
            backup[
                "encryption_nonce"
            ],
            backup["created_at"],
        )

        restored_did = (
            backup["did"]
        )

        clear_import_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "✅ Identity Restored!\n\n"
                "Your DID:\n"
                f"{restored_did}",
                reply_markup=(
                    identity_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    except InvalidTag:
        attempts += 1

        context.user_data[
            "import_attempts"
        ] = attempts

        if (
            attempts
            >= MAX_PASSWORD_ATTEMPTS
        ):
            clear_import_state(
                context
            )

            await (
                update.effective_chat
                .send_message(
                    "❌ Import failed after "
                    "3 attempts.",
                    reply_markup=(
                        no_identity_keyboard()
                    ),
                )
            )

            return ConversationHandler.END

        await (
            update.effective_chat
            .send_message(
                "❌ Incorrect password.\n\n"
                f"Attempts remaining: "
                f"{MAX_PASSWORD_ATTEMPTS - attempts}"
            )
        )

        return IMPORT_PASSWORD

    except Exception:
        clear_import_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "❌ Backup verification failed.",
                reply_markup=(
                    no_identity_keyboard()
                ),
            )
        )

        return ConversationHandler.END


async def cancel_backup_import(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    clear_import_state(
        context
    )

    await update.message.reply_text(
        "Backup import cancelled.",
        reply_markup=main_menu_keyboard(),
    )

    return ConversationHandler.END


# =========================================================
# Signed Message Conversation
# =========================================================

async def start_signed_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query

    await query.answer()

    telegram_user_id = (
        update.effective_user.id
    )

    identity = get_identity(
        telegram_user_id
    )

    if not identity:
        await query.edit_message_text(
            "🪪 You need a DID before "
            "sending signed messages.",
            reply_markup=(
                no_identity_keyboard()
            ),
        )

        return ConversationHandler.END

    room = context.user_data.get(
        "current_room"
    )

    if not room:
        await query.edit_message_text(
            "❌ No room selected.\n\n"
            "Open Browse Rooms first.",
            reply_markup=(
                main_menu_keyboard()
            ),
        )

        return ConversationHandler.END

    clear_send_state(
        context
    )

    await query.edit_message_text(
        "✍️ Send Signed Message\n\n"
        f"Room: {room}\n\n"
        "Send the message you want "
        "to publish.\n\n"
        "The message will be signed "
        "with your Technocore DID.\n\n"
        "Use /cancel to stop."
    )

    return SEND_TEXT


async def receive_signed_text(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    raw_text = (
        update.message.text
    )

    try:
        cleaned_text = (
            sweep_text(raw_text)
        )

    except ValueError:
        await update.message.reply_text(
            "❌ Message is empty or "
            "longer than 4096 characters.\n\n"
            "Please send another message."
        )

        return SEND_TEXT

    context.user_data[
        "pending_send_text"
    ] = cleaned_text

    context.user_data[
        "send_attempts"
    ] = 0

    await update.message.reply_text(
        "🔐 Now send your DID password.\n\n"
        "It will only be used to decrypt "
        "your private seed temporarily "
        "and sign this message.\n\n"
        "The password will not be stored."
    )

    return SEND_PASSWORD


async def receive_send_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = (
        update.message.text
    )

    await delete_sensitive_message(
        update
    )

    text = context.user_data.get(
        "pending_send_text"
    )

    room = context.user_data.get(
        "current_room"
    )

    if not text or not room:
        clear_send_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "❌ Send session expired.",
                reply_markup=(
                    main_menu_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    telegram_user_id = (
        update.effective_user.id
    )

    identity = get_identity(
        telegram_user_id
    )

    if not identity:
        clear_send_state(
            context
        )

        return ConversationHandler.END

    attempts = (
        context.user_data.get(
            "send_attempts",
            0,
        )
    )

    try:
        seed = decrypt_seed(
            identity[
                "encrypted_seed"
            ],
            identity["salt"],
            identity[
                "encryption_nonce"
            ],
            password,
        )

    except InvalidTag:
        attempts += 1

        context.user_data[
            "send_attempts"
        ] = attempts

        if (
            attempts
            >= MAX_PASSWORD_ATTEMPTS
        ):
            clear_send_state(
                context
            )

            await (
                update.effective_chat
                .send_message(
                    "❌ Signing cancelled "
                    "after 3 incorrect "
                    "password attempts.",
                    reply_markup=(
                        main_menu_keyboard()
                    ),
                )
            )

            return ConversationHandler.END

        await (
            update.effective_chat
            .send_message(
                "❌ Incorrect password.\n\n"
                f"Attempts remaining: "
                f"{MAX_PASSWORD_ATTEMPTS - attempts}"
            )
        )

        return SEND_PASSWORD

    try:
        derived_did = did_from_seed(
            seed
        )

        if not hmac.compare_digest(
            derived_did,
            identity["did"],
        ):
            raise ValueError(
                "Stored identity mismatch"
            )

        nonce = get_next_nonce(
            telegram_user_id,
            room,
        )

        sent_text = (
            send_signed_message(
                room=room,
                text=text,
                did=identity["did"],
                seed=seed,
                nonce=nonce,
            )
        )

        clear_send_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "✅ Signed message sent!\n\n"
                f"Room: {room}\n\n"
                f"From:\n{identity['did']}\n\n"
                f"Message:\n{sent_text}\n\n"
                f"Nonce:\n{nonce}",
                reply_markup=(
                    room_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    except requests.HTTPError as error:
        clear_send_state(
            context
        )

        response_text = ""

        if error.response is not None:
            response_text = (
                error.response.text[:500]
            )

        await (
            update.effective_chat
            .send_message(
                "❌ Technocore rejected "
                "the signed message.\n\n"
                f"{response_text}",
                reply_markup=(
                    room_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    except requests.RequestException:
        clear_send_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "⚠️ Network error while "
                "sending.\n\n"
                "Do not immediately resend "
                "the same message without "
                "checking the room first.",
                reply_markup=(
                    room_keyboard()
                ),
            )
        )

        return ConversationHandler.END

    except Exception as error:
        print(
            "Signing error:",
            repr(error),
        )

        clear_send_state(
            context
        )

        await (
            update.effective_chat
            .send_message(
                "❌ Could not sign "
                "the message.",
                reply_markup=(
                    room_keyboard()
                ),
            )
        )

        return ConversationHandler.END


async def cancel_signed_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    clear_send_state(
        context
    )

    await update.message.reply_text(
        "Signed message cancelled.",
        reply_markup=room_keyboard(),
    )

    return ConversationHandler.END


# =========================================================
# General Buttons
# =========================================================

async def button_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query

    await query.answer()

    data = query.data

    if data == "home":
        await query.edit_message_text(
            "⚡ Technocore Gateway\n\n"
            "Choose an option:",
            reply_markup=(
                main_menu_keyboard()
            ),
        )

        return

    if data == "about":
        await query.edit_message_text(
            "ℹ️ About Technocore Gateway\n\n"
            "Current features:\n"
            "• Browse active rooms\n"
            "• Read messages\n"
            "• Create Ed25519 DID\n"
            "• Encrypted key storage\n"
            "• Export / restore backup\n"
            "• Send signed messages\n\n"
            "Coming next:\n"
            "• Technocore mailbox\n"
            "• Room notifications",
            reply_markup=(
                main_menu_keyboard()
            ),
        )

        return

    if data == "my_identity":
        identity = get_identity(
            update.effective_user.id
        )

        if identity:
            await query.edit_message_text(
                identity_text(
                    identity
                ),
                reply_markup=(
                    identity_keyboard()
                ),
            )

        else:
            await query.edit_message_text(
                "🪪 No identity found.",
                reply_markup=(
                    no_identity_keyboard()
                ),
            )

        return

    if data == "export_backup":
        identity = get_identity(
            update.effective_user.id
        )

        if not identity:
            return

        backup_file = (
            create_backup_file(
                identity
            )
        )

        filename = (
            "technocore-backup-"
            f"{identity['did'][-8:]}"
            ".json"
        )

        await query.message.reply_document(
            document=backup_file,
            filename=filename,
            caption=(
                "📦 Encrypted Technocore "
                "Identity Backup\n\n"
                "Keep this file safe."
            ),
        )

        return

    if data == "show_rooms":
        try:
            text, keyboard = (
                build_rooms_menu(
                    context
                )
            )

            await query.edit_message_text(
                text,
                reply_markup=keyboard,
            )

        except requests.RequestException:
            await query.edit_message_text(
                "❌ Could not connect "
                "to Technocore.",
                reply_markup=(
                    main_menu_keyboard()
                ),
            )

        return

    if data.startswith("room:"):
        try:
            index = int(
                data.split(":")[1]
            )

            room_names = (
                context.user_data.get(
                    "room_names",
                    [],
                )
            )

            room_name = (
                room_names[index]
            )

            context.user_data[
                "current_room"
            ] = room_name

            room_data = (
                get_room_messages(
                    room_name
                )
            )

            messages = room_data.get(
                "messages",
                [],
            )

            text = (
                format_room_messages(
                    room_name,
                    messages,
                )
            )

            await query.edit_message_text(
                text,
                reply_markup=(
                    room_keyboard()
                ),
            )

        except (
            requests.RequestException,
            ValueError,
            IndexError,
        ):
            await query.edit_message_text(
                "❌ Could not read room.",
                reply_markup=(
                    main_menu_keyboard()
                ),
            )


# =========================================================
# Application
# =========================================================

def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError(
            "TELEGRAM_BOT_TOKEN is not set"
        )

    init_database()

    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .build()
    )

    did_conversation = (
        ConversationHandler(
            entry_points=[
                CallbackQueryHandler(
                    start_create_did,
                    pattern=(
                        r"^create_did$"
                    ),
                ),
            ],
            states={
                CREATE_PASSWORD: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        receive_did_password,
                    ),
                ],
                CONFIRM_PASSWORD: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        confirm_did_password,
                    ),
                ],
            },
            fallbacks=[
                CommandHandler(
                    "cancel",
                    cancel_did_creation,
                ),
            ],
            allow_reentry=True,
        )
    )

    import_conversation = (
        ConversationHandler(
            entry_points=[
                CallbackQueryHandler(
                    start_import_backup,
                    pattern=(
                        r"^import_backup$"
                    ),
                ),
            ],
            states={
                IMPORT_FILE: [
                    MessageHandler(
                        filters.Document.ALL,
                        receive_backup_file,
                    ),
                ],
                IMPORT_PASSWORD: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        receive_import_password,
                    ),
                ],
            },
            fallbacks=[
                CommandHandler(
                    "cancel",
                    cancel_backup_import,
                ),
            ],
            allow_reentry=True,
        )
    )

    signed_message_conversation = (
        ConversationHandler(
            entry_points=[
                CallbackQueryHandler(
                    start_signed_message,
                    pattern=(
                        r"^send_signed$"
                    ),
                ),
            ],
            states={
                SEND_TEXT: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        receive_signed_text,
                    ),
                ],
                SEND_PASSWORD: [
                    MessageHandler(
                        filters.TEXT
                        & ~filters.COMMAND,
                        receive_send_password,
                    ),
                ],
            },
            fallbacks=[
                CommandHandler(
                    "cancel",
                    cancel_signed_message,
                ),
            ],
            allow_reentry=True,
        )
    )

    app.add_handler(
        did_conversation
    )

    app.add_handler(
        import_conversation
    )

    app.add_handler(
        signed_message_conversation
    )

    app.add_handler(
        CommandHandler(
            "start",
            start,
        )
    )

    app.add_handler(
        CommandHandler(
            "rooms",
            rooms,
        )
    )

    app.add_handler(
        CommandHandler(
            "read",
            read_room,
        )
    )

    app.add_handler(
        CommandHandler(
            "identity",
            identity_command,
        )
    )

    app.add_handler(
        CallbackQueryHandler(
            button_handler
        )
    )

    print(
        "Technocore Gateway is running..."
    )

    app.run_polling()


if __name__ == "__main__":
    main()