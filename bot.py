import os
import secrets
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote

import requests
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

# Technocore / did:key
MULTICODEC_ED25519 = b"\xed\x01"

# Encryption
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32

SALT_SIZE = 16
AES_NONCE_SIZE = 12

MIN_PASSWORD_LENGTH = 10


load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


# =========================================================
# Conversation States
# =========================================================

CREATE_PASSWORD, CONFIRM_PASSWORD = range(2)


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

        connection.commit()


def get_identity(telegram_user_id):
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
):
    created_at = datetime.now(timezone.utc).isoformat()

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


# =========================================================
# DID / Cryptography
# =========================================================

def base58btc_encode(raw):
    alphabet = (
        "123456789"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz"
    )

    number = int.from_bytes(raw, "big")

    encoded = ""

    while number:
        number, remainder = divmod(number, 58)

        encoded = alphabet[remainder] + encoded

    return encoded


def create_did_from_private_key(private_key):
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    multicodec_key = (
        MULTICODEC_ED25519
        + public_key_bytes
    )

    multibase_key = (
        "z"
        + base58btc_encode(multicodec_key)
    )

    did = f"did:key:{multibase_key}"

    return did


def generate_identity():
    seed = secrets.token_bytes(32)

    private_key = Ed25519PrivateKey.from_private_bytes(
        seed
    )

    did = create_did_from_private_key(
        private_key
    )

    return seed, did


def derive_encryption_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    encryption_key = kdf.derive(
        password.encode("utf-8")
    )

    return encryption_key


def encrypt_seed(seed, password):
    salt = secrets.token_bytes(
        SALT_SIZE
    )

    encryption_nonce = secrets.token_bytes(
        AES_NONCE_SIZE
    )

    encryption_key = derive_encryption_key(
        password,
        salt,
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


# =========================================================
# Technocore API
# =========================================================

def get_rooms():
    url = f"{TECHNOCORE_API}/rooms"

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


def get_room_messages(room_name):
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
    keyboard = [
        [
            InlineKeyboardButton(
                "🔥 Browse Rooms",
                callback_data="show_rooms",
            ),
        ],
        [
            InlineKeyboardButton(
                "🪪 Create DID",
                callback_data="create_did",
            ),
            InlineKeyboardButton(
                "👤 My Identity",
                callback_data="my_identity",
            ),
        ],
        [
            InlineKeyboardButton(
                "ℹ️ About",
                callback_data="about",
            ),
        ],
    ]

    return InlineKeyboardMarkup(
        keyboard
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
                    callback_data=f"room:{index}",
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
    keyboard = [
        [
            InlineKeyboardButton(
                "⬅️ Back to Rooms",
                callback_data="show_rooms",
            )
        ],
        [
            InlineKeyboardButton(
                "🏠 Main Menu",
                callback_data="home",
            )
        ],
    ]

    return InlineKeyboardMarkup(
        keyboard
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

    total_rooms = rooms_data.get(
        "total",
        "?",
    )

    text = (
        "🔥 Active Technocore Rooms\n\n"
        f"Technocore currently has "
        f"{total_rooms} rooms.\n\n"
        "Choose a room to read its "
        "latest messages:"
    )

    keyboard = rooms_keyboard(
        room_names
    )

    return text, keyboard


async def delete_sensitive_message(
    update: Update,
):
    try:
        if update.message:
            await update.message.delete()

    except Exception:
        # Deletion may fail if Telegram permissions
        # or timing do not allow it.
        pass


def identity_text(identity):
    did = identity["did"]
    created_at = identity["created_at"]

    return (
        "👤 Your Technocore Identity\n\n"
        f"DID:\n{did}\n\n"
        f"Created:\n{created_at}\n\n"
        "🔐 Your private seed is stored "
        "encrypted in the bot database.\n\n"
        "Your password is NOT stored."
    )


# =========================================================
# Telegram Commands
# =========================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    text = (
        "⚡ Technocore Gateway\n\n"
        "Access Technocore directly "
        "from Telegram.\n\n"
        "Browse rooms, read messages "
        "and create your own "
        "Technocore DID identity."
    )

    await update.message.reply_text(
        text,
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

    try:
        room_data = get_room_messages(
            room_name
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
            "Technocore DID yet.\n\n"
            "Use the Create DID button "
            "from /start.",
            reply_markup=main_menu_keyboard(),
        )

        return

    await update.message.reply_text(
        identity_text(identity),
        reply_markup=main_menu_keyboard(),
    )


# =========================================================
# DID Creation Conversation
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

    existing_identity = get_identity(
        telegram_user_id
    )

    if existing_identity:
        await query.edit_message_text(
            "⚠️ You already have a "
            "Technocore DID.\n\n"
            f"{existing_identity['did']}\n\n"
            "This MVP does not allow "
            "overwriting an existing "
            "identity.",
            reply_markup=main_menu_keyboard(),
        )

        return ConversationHandler.END

    context.user_data.pop(
        "pending_did_password",
        None,
    )

    text = (
        "🪪 Create Technocore Identity\n\n"
        "The bot will generate a fresh "
        "Ed25519 keypair and a "
        "did:key identity.\n\n"
        "Your private seed will be "
        "encrypted before it is stored "
        "in SQLite.\n\n"
        "🔐 Send a NEW password now.\n"
        f"Minimum length: "
        f"{MIN_PASSWORD_LENGTH} characters.\n\n"
        "IMPORTANT:\n"
        "• Use a password you do not use "
        "anywhere else.\n"
        "• Never send a crypto wallet "
        "seed phrase here.\n"
        "• Never send another private key.\n"
        "• Telegram bot chats are not "
        "end-to-end encrypted.\n\n"
        "Use /cancel to stop."
    )

    await query.edit_message_text(
        text
    )

    return CREATE_PASSWORD


async def receive_did_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    password = update.message.text

    await delete_sensitive_message(
        update
    )

    if len(password) < MIN_PASSWORD_LENGTH:
        await update.effective_chat.send_message(
            "❌ Password is too short.\n\n"
            f"Please send at least "
            f"{MIN_PASSWORD_LENGTH} characters."
        )

        return CREATE_PASSWORD

    context.user_data[
        "pending_did_password"
    ] = password

    await update.effective_chat.send_message(
        "🔐 Please send the same "
        "password again to confirm it."
    )

    return CONFIRM_PASSWORD


async def confirm_did_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    confirmation = update.message.text

    await delete_sensitive_message(
        update
    )

    password = context.user_data.pop(
        "pending_did_password",
        None,
    )

    if password is None:
        await update.effective_chat.send_message(
            "❌ Password session expired.\n\n"
            "Please start again from /start.",
            reply_markup=main_menu_keyboard(),
        )

        return ConversationHandler.END

    if password != confirmation:
        await update.effective_chat.send_message(
            "❌ Passwords did not match.\n\n"
            "Send a NEW password to "
            "start again."
        )

        return CREATE_PASSWORD

    telegram_user_id = (
        update.effective_user.id
    )

    existing_identity = get_identity(
        telegram_user_id
    )

    if existing_identity:
        await update.effective_chat.send_message(
            "⚠️ An identity already "
            "exists for this account.",
            reply_markup=main_menu_keyboard(),
        )

        return ConversationHandler.END

    try:
        seed, did = generate_identity()

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

        del seed
        del password
        del confirmation

        text = (
            "✅ Technocore Identity Created!\n\n"
            "Your DID:\n"
            f"{did}\n\n"
            "🔐 The private seed was "
            "encrypted before being "
            "stored in SQLite.\n\n"
            "🚫 Your password was NOT "
            "stored.\n\n"
            "⚠️ Important for this MVP:\n"
            "We have not added encrypted "
            "backup export yet. If the "
            "Codespace/database is deleted, "
            "this identity cannot currently "
            "be recovered.\n\n"
            "We will add backup/export next."
        )

        await update.effective_chat.send_message(
            text,
            reply_markup=main_menu_keyboard(),
        )

    except sqlite3.IntegrityError:
        await update.effective_chat.send_message(
            "❌ Could not save this "
            "identity because an identity "
            "already exists.",
            reply_markup=main_menu_keyboard(),
        )

    except Exception as error:
        print(
            "DID creation error:",
            repr(error),
        )

        await update.effective_chat.send_message(
            "❌ Something went wrong while "
            "creating the identity.",
            reply_markup=main_menu_keyboard(),
        )

    return ConversationHandler.END


async def cancel_did_creation(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    context.user_data.pop(
        "pending_did_password",
        None,
    )

    await update.message.reply_text(
        "DID creation cancelled.",
        reply_markup=main_menu_keyboard(),
    )

    return ConversationHandler.END


# =========================================================
# General Button Handler
# =========================================================

async def button_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    query = update.callback_query

    await query.answer()

    data = query.data

    if data == "home":
        text = (
            "⚡ Technocore Gateway\n\n"
            "Access Technocore directly "
            "from Telegram.\n\n"
            "Choose an option:"
        )

        await query.edit_message_text(
            text,
            reply_markup=main_menu_keyboard(),
        )

        return

    if data == "about":
        text = (
            "ℹ️ About Technocore Gateway\n\n"
            "A Telegram interface for "
            "interacting with Technocore.\n\n"
            "Current features:\n"
            "• Browse active rooms\n"
            "• Read room messages\n"
            "• Create Ed25519 DID identity\n"
            "• Encrypted identity storage\n"
            "• View your identity\n\n"
            "Coming next:\n"
            "• Encrypted identity backup\n"
            "• Signed messaging\n"
            "• Technocore mailbox\n"
            "• Room notifications"
        )

        await query.edit_message_text(
            text,
            reply_markup=main_menu_keyboard(),
        )

        return

    if data == "my_identity":
        telegram_user_id = (
            update.effective_user.id
        )

        identity = get_identity(
            telegram_user_id
        )

        if not identity:
            text = (
                "🪪 No Technocore identity "
                "found.\n\n"
                "Use Create DID to generate "
                "your identity."
            )

        else:
            text = identity_text(
                identity
            )

        await query.edit_message_text(
            text,
            reply_markup=main_menu_keyboard(),
        )

        return

    if data == "show_rooms":
        try:
            text, keyboard = (
                build_rooms_menu(context)
            )

            await query.edit_message_text(
                text,
                reply_markup=keyboard,
            )

        except (
            requests.RequestException,
            ValueError,
        ):
            await query.edit_message_text(
                "❌ Could not connect "
                "to Technocore.",
                reply_markup=main_menu_keyboard(),
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

            if index >= len(room_names):
                await query.edit_message_text(
                    "⚠️ Room list expired. "
                    "Please refresh it.",
                    reply_markup=main_menu_keyboard(),
                )

                return

            room_name = room_names[
                index
            ]

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

            await query.edit_message_text(
                text,
                reply_markup=room_keyboard(),
            )

        except (
            requests.RequestException,
            ValueError,
            IndexError,
        ):
            await query.edit_message_text(
                "❌ Could not read "
                "this room.",
                reply_markup=main_menu_keyboard(),
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

    did_conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(
                start_create_did,
                pattern=r"^create_did$",
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

    app.add_handler(
        did_conversation
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
            button_handler,
        )
    )

    print(
        "Technocore Gateway is running..."
    )

    app.run_polling()


if __name__ == "__main__":
    main()