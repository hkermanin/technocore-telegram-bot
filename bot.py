import asyncio
import hashlib
import hmac
import json
import sqlite3

import requests
from cryptography.exceptions import InvalidTag
from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

from config import (
    E2E_INBOX_LIMIT,
    E2E_INVITE_PREFIX,
    E2E_ROOM_MESSAGES_LIMIT,
    MAILBOX_MESSAGES_LIMIT,
    MAX_BACKUP_SIZE,
    MAX_E2E_PLAINTEXT_CHARS,
    MAX_PASSWORD_ATTEMPTS,
    MAX_WATCHES_PER_USER,
    MIN_PASSWORD_LENGTH,
    ROOM_NAME_RE,
    TELEGRAM_BOT_TOKEN,
    WATCH_POLL_INTERVAL,
)
from database import (
    delete_room_watch,
    e2e_invite_processed,
    get_all_watches,
    get_e2e_chat,
    get_e2e_chats,
    get_e2e_key,
    get_identity,
    get_mailbox,
    get_next_nonce,
    get_room_watch,
    get_user_watches,
    init_database,
    mark_e2e_invite_processed,
    mark_mailbox_active,
    save_e2e_chat,
    save_e2e_key,
    save_identity,
    save_mailbox,
    save_room_watch,
    update_e2e_chat_last_read,
    update_mailbox_last_read,
    update_room_watch_seq,
)
from crypto_utils import (
    create_e2e_invite,
    decrypt_seed,
    did_from_seed,
    encrypt_e2e_room_text,
    encrypt_seed,
    generate_identity,
    generate_x25519_keypair,
    open_e2e_invite,
    sweep_text,
    x25519_public_from_private,
)
from technocore_api import (
    DirectoryProfileConflictError,
    get_did_directory_profile,
    get_room_messages,
    get_room_updates,
    parse_did_directory_value,
    publish_did_directory_profile,
    send_e2e_ciphertext,
    send_signed_message,
    strip_budget_footer,
)
from backup import (
    create_backup_file,
    validate_backup_data,
)
from ui import (
    build_rooms_menu,
    clear_e2e_state,
    clear_import_state,
    clear_mailbox_send_state,
    clear_send_state,
    delete_sensitive_message,
    did_profile_keyboard,
    did_profile_text,
    e2e_chat_keyboard,
    e2e_chat_text,
    e2e_chats_keyboard,
    e2e_chats_text,
    e2e_menu_keyboard,
    e2e_menu_text,
    format_decrypted_e2e_messages,
    format_messages,
    format_watch_notification,
    generate_mailbox_name,
    identity_keyboard,
    identity_text,
    mailbox_is_active_for_identity,
    mailbox_keyboard,
    mailbox_read_keyboard,
    mailbox_text,
    main_menu_keyboard,
    no_identity_keyboard,
    room_keyboard,
    shorten_sender,
    watch_notification_keyboard,
    watched_rooms_keyboard,
    watched_rooms_text,
)

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
    E2E_SETUP_PASSWORD,
    E2E_TARGET_DID,
    E2E_START_PASSWORD,
    E2E_ACCEPT_PASSWORD,
    E2E_SEND_TEXT,
    E2E_SEND_PASSWORD,
    E2E_READ_PASSWORD,
) = range(17)


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


async def e2e_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identity = get_identity(update.effective_user.id)
    if not identity:
        await update.message.reply_text(
            "🪪 You need a DID before using E2E messaging.",
            reply_markup=no_identity_keyboard(),
        )
        return
    e2e_key = get_e2e_key(update.effective_user.id)
    await update.message.reply_text(
        e2e_menu_text(update.effective_user.id),
        reply_markup=e2e_menu_keyboard(e2e_key is not None),
    )


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

        # Backup v2 may also contain the static X25519 key and encrypted
        # E2E room keys. Verify that they decrypt with the same password
        # before writing any of them to the local database.
        try:
            if backup.get("e2e"):
                e2e_private = decrypt_seed(
                    backup["e2e"]["encrypted_private_key"],
                    backup["e2e"]["salt"],
                    backup["e2e"]["encryption_nonce"],
                    password,
                )
                if not hmac.compare_digest(
                    x25519_public_from_private(e2e_private),
                    backup["e2e"]["public_key"],
                ):
                    raise ValueError("X25519 backup mismatch")

            for chat_backup in backup.get("e2e_chats", []):
                room_key = decrypt_seed(
                    chat_backup["encrypted_room_key"],
                    chat_backup["salt"],
                    chat_backup["encryption_nonce"],
                    password,
                )
                if len(room_key) != 32:
                    raise ValueError("Invalid E2E room key in backup")
        except InvalidTag as error:
            raise ValueError("E2E backup encryption mismatch") from error

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

        if backup.get("e2e") and not get_e2e_key(update.effective_user.id):
            e2e = backup["e2e"]
            save_e2e_key(
                update.effective_user.id,
                e2e["public_key"],
                e2e["encrypted_private_key"],
                e2e["salt"],
                e2e["encryption_nonce"],
                e2e["created_at"],
            )

        for chat in backup.get("e2e_chats", []):
            save_e2e_chat(
                update.effective_user.id,
                chat["peer_did"],
                chat["room"],
                chat["encrypted_room_key"],
                chat["salt"],
                chat["encryption_nonce"],
                last_read_seq=chat["last_read_seq"],
                created_at=chat["created_at"],
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


async def start_e2e_setup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    identity = get_identity(user_id)
    if not identity:
        await query.edit_message_text(
            "🪪 You need a DID before enabling E2E messaging.",
            reply_markup=no_identity_keyboard(),
        )
        return ConversationHandler.END
    if get_e2e_key(user_id):
        await query.edit_message_text(
            e2e_menu_text(user_id),
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END

    clear_e2e_state(context)
    context.user_data["e2e_setup_attempts"] = 0
    await query.edit_message_text(
        "🔑 Enable X25519 E2E\n\n"
        "The bot will generate a static X25519 keypair. The private key will be encrypted at rest with your existing DID password; only the public key will be published in your DID directory profile.\n\n"
        "🔐 Send your DID password now.\n\n"
        "Telegram bot chats are not E2E encrypted. Use /cancel to stop."
    )
    return E2E_SETUP_PASSWORD


async def receive_e2e_setup_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)
    user_id = update.effective_user.id
    identity = get_identity(user_id)
    if not identity:
        clear_e2e_state(context)
        return ConversationHandler.END

    attempts = context.user_data.get("e2e_setup_attempts", 0)
    try:
        seed = decrypt_seed(
            identity["encrypted_seed"],
            identity["salt"],
            identity["encryption_nonce"],
            password,
        )
        if not hmac.compare_digest(did_from_seed(seed), identity["did"]):
            raise ValueError("Stored identity mismatch")
    except InvalidTag:
        attempts += 1
        context.user_data["e2e_setup_attempts"] = attempts
        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_e2e_state(context)
            await update.effective_chat.send_message(
                "❌ E2E setup cancelled after 3 incorrect password attempts.",
                reply_markup=e2e_menu_keyboard(False),
            )
            return ConversationHandler.END
        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return E2E_SETUP_PASSWORD

    try:
        private_raw, public_b64 = generate_x25519_keypair()
        encrypted_private, salt, nonce = encrypt_seed(private_raw, password)
        save_e2e_key(user_id, public_b64, encrypted_private, salt, nonce)

        publish_note = ""
        try:
            result = publish_did_directory_profile(identity, get_mailbox(user_id))
            publish_note = f"\n\n🌐 DID directory: {result['status']}."
        except Exception as error:
            print("E2E directory publish error:", repr(error))
            publish_note = (
                "\n\n⚠️ The X25519 key was saved, but the DID directory could not be updated automatically. "
                "Open 🌐 DID Profile and publish/update it manually."
            )

        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "✅ X25519 E2E enabled!\n\n"
            f"Public key:\n{public_b64}"
            + publish_note
            + "\n\nThe private X25519 key is encrypted in SQLite; your password is not stored.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END
    except Exception as error:
        print("E2E setup error:", repr(error))
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ Could not enable E2E messaging.",
            reply_markup=e2e_menu_keyboard(False),
        )
        return ConversationHandler.END


async def start_e2e_chat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    if not get_identity(user_id) or not get_e2e_key(user_id):
        await query.edit_message_text(
            "🔑 Enable X25519 E2E first.",
            reply_markup=e2e_menu_keyboard(False),
        )
        return ConversationHandler.END

    clear_e2e_state(context)
    await query.edit_message_text(
        "➕ Start E2E Chat\n\n"
        "Send the recipient's full Ed25519 DID, for example:\n"
        "did:key:z6Mk...\n\n"
        "Their DID directory profile must advertise both x25519: and an active mailbox:.\n\n"
        "Use /cancel to stop."
    )
    return E2E_TARGET_DID


async def receive_e2e_target_did(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target_did = update.message.text.strip()
    if not target_did.startswith("did:key:z6Mk") or len(target_did) > 200:
        await update.message.reply_text("❌ Invalid Ed25519 did:key. Please send the full DID.")
        return E2E_TARGET_DID

    try:
        remote_profile = get_did_directory_profile(target_did)
        if remote_profile["value"] is None:
            await update.message.reply_text(
                "❌ No DID directory profile was found for that DID."
            )
            return E2E_TARGET_DID
        parsed = parse_did_directory_value(remote_profile["value"], target_did)
    except (requests.RequestException, ValueError) as error:
        await update.message.reply_text(f"❌ Could not use that DID profile: {error}")
        return E2E_TARGET_DID

    if not parsed.get("x25519"):
        await update.message.reply_text(
            "❌ That DID profile does not advertise an x25519: public key."
        )
        return E2E_TARGET_DID
    if not parsed.get("mailbox"):
        await update.message.reply_text(
            "❌ That DID profile does not advertise an active mailbox:."
        )
        return E2E_TARGET_DID

    context.user_data["e2e_target_did"] = target_did
    context.user_data["e2e_target_public"] = parsed["x25519"]
    context.user_data["e2e_target_mailbox"] = parsed["mailbox"]
    context.user_data["e2e_start_attempts"] = 0
    await update.message.reply_text(
        "✅ Recipient E2E profile found.\n\n"
        f"Mailbox:\n{parsed['mailbox']}\n\n"
        "⚠️ DID directory notes are world-writable. Before sending sensitive content, verify the recipient DID/profile through a trusted or previously signed channel.\n\n"
        "🔐 Send your DID password. It is needed to sign the mailbox invitation and encrypt the new room key at rest."
    )
    return E2E_START_PASSWORD


async def receive_e2e_start_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)
    user_id = update.effective_user.id
    identity = get_identity(user_id)
    target_did = context.user_data.get("e2e_target_did")
    target_public = context.user_data.get("e2e_target_public")
    target_mailbox = context.user_data.get("e2e_target_mailbox")
    if not identity or not target_did or not target_public or not target_mailbox:
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ E2E start session expired.",
            reply_markup=e2e_menu_keyboard(get_e2e_key(user_id) is not None),
        )
        return ConversationHandler.END

    attempts = context.user_data.get("e2e_start_attempts", 0)
    try:
        seed = decrypt_seed(
            identity["encrypted_seed"],
            identity["salt"],
            identity["encryption_nonce"],
            password,
        )
        if not hmac.compare_digest(did_from_seed(seed), identity["did"]):
            raise ValueError("Stored identity mismatch")
    except InvalidTag:
        attempts += 1
        context.user_data["e2e_start_attempts"] = attempts
        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_e2e_state(context)
            await update.effective_chat.send_message(
                "❌ E2E chat creation cancelled after 3 incorrect password attempts.",
                reply_markup=e2e_menu_keyboard(True),
            )
            return ConversationHandler.END
        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return E2E_START_PASSWORD

    try:
        room, room_key, invitation = create_e2e_invite(target_public)
        signed_nonce = get_next_nonce(user_id, target_mailbox)
        send_signed_message(
            target_mailbox,
            invitation,
            identity["did"],
            seed,
            signed_nonce,
        )
        encrypted_room_key, salt, nonce = encrypt_seed(room_key, password)
        chat = save_e2e_chat(
            user_id,
            target_did,
            room,
            encrypted_room_key,
            salt,
            nonce,
        )
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "✅ E2E invitation delivered!\n\n"
            f"Peer:\n{target_did}\n\n"
            f"Private room:\n{room}\n\n"
            "The recipient can now check E2E Invites and recover the same 32-byte room key. The private room itself will be created when the first encrypted message is successfully written.",
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END
    except requests.HTTPError as error:
        response_text = error.response.text[:700] if error.response is not None else ""
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ Technocore rejected the E2E invitation.\n\n" + response_text,
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END
    except Exception as error:
        print("E2E start error:", repr(error))
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ Could not create the E2E session.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END


async def start_e2e_invites(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    e2e_key = get_e2e_key(user_id)
    mailbox = get_mailbox(user_id)
    if not e2e_key:
        await query.edit_message_text(
            "🔑 Enable X25519 E2E first.",
            reply_markup=e2e_menu_keyboard(False),
        )
        return ConversationHandler.END
    if not mailbox or not mailbox["is_active"]:
        await query.edit_message_text(
            "📬 Receiving official E2E invitations requires an active mailbox advertised in your DID profile. Your mailbox is not active yet.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END

    try:
        mailbox_data = get_room_messages(mailbox["room"], limit=E2E_INBOX_LIMIT)
        pending = []
        for message in mailbox_data.get("messages", []):
            seq = message.get("seq")
            text = message.get("text", "")
            sender = message.get("from", "")
            if (
                isinstance(seq, int)
                and isinstance(text, str)
                and text.startswith(E2E_INVITE_PREFIX + " ")
                and isinstance(sender, str)
                and sender.startswith("did:key:z6Mk")
                and not e2e_invite_processed(user_id, seq)
            ):
                pending.append({"seq": seq, "text": text, "from": sender})
    except (requests.RequestException, ValueError):
        await query.edit_message_text(
            "❌ Could not read your mailbox for E2E invitations.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END

    if not pending:
        await query.edit_message_text(
            "📨 E2E Invites\n\nNo new E2E invitations were found in your mailbox.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END

    clear_e2e_state(context)
    context.user_data["e2e_pending_invites"] = pending
    context.user_data["e2e_accept_attempts"] = 0
    await query.edit_message_text(
        f"📨 E2E Invites\n\nFound {len(pending)} new signed invitation(s).\n\n"
        "🔐 Send your DID password to unlock your static X25519 private key and decrypt them."
    )
    return E2E_ACCEPT_PASSWORD


async def receive_e2e_accept_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)
    user_id = update.effective_user.id
    e2e_key = get_e2e_key(user_id)
    pending = context.user_data.get("e2e_pending_invites", [])
    if not e2e_key or not pending:
        clear_e2e_state(context)
        return ConversationHandler.END

    attempts = context.user_data.get("e2e_accept_attempts", 0)
    try:
        private_raw = decrypt_seed(
            e2e_key["encrypted_private_key"],
            e2e_key["salt"],
            e2e_key["encryption_nonce"],
            password,
        )
        if not hmac.compare_digest(
            x25519_public_from_private(private_raw),
            e2e_key["public_key"],
        ):
            raise ValueError("Stored X25519 key mismatch")
    except InvalidTag:
        attempts += 1
        context.user_data["e2e_accept_attempts"] = attempts
        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_e2e_state(context)
            await update.effective_chat.send_message(
                "❌ E2E invite processing cancelled after 3 incorrect password attempts.",
                reply_markup=e2e_menu_keyboard(True),
            )
            return ConversationHandler.END
        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return E2E_ACCEPT_PASSWORD

    accepted = 0
    rejected = 0
    for invitation in pending:
        try:
            room, room_key = open_e2e_invite(private_raw, invitation["text"])
            encrypted_room_key, salt, nonce = encrypt_seed(room_key, password)
            save_e2e_chat(
                user_id,
                invitation["from"],
                room,
                encrypted_room_key,
                salt,
                nonce,
            )
            mark_e2e_invite_processed(user_id, invitation["seq"])
            accepted += 1
        except Exception:
            mark_e2e_invite_processed(user_id, invitation["seq"])
            rejected += 1

    clear_e2e_state(context)
    chats = get_e2e_chats(user_id)
    await update.effective_chat.send_message(
        "✅ E2E invitations processed.\n\n"
        f"Accepted: {accepted}\n"
        f"Rejected/invalid: {rejected}",
        reply_markup=e2e_chats_keyboard(chats),
    )
    return ConversationHandler.END


async def start_e2e_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    try:
        chat_id = int(query.data.split(":", 1)[1])
    except (ValueError, IndexError):
        return ConversationHandler.END
    chat = get_e2e_chat(user_id, chat_id)
    if not chat:
        await query.edit_message_text(
            "❌ E2E chat not found.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END
    clear_e2e_state(context)
    context.user_data["e2e_chat_id"] = chat_id
    await query.edit_message_text(
        "✍️ Send Encrypted E2E Message\n\n"
        f"Peer: {shorten_sender(chat['peer_did'])}\n\n"
        f"Send up to {MAX_E2E_PLAINTEXT_CHARS} characters.\n\n"
        "Use /cancel to stop."
    )
    return E2E_SEND_TEXT


async def receive_e2e_send_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cleaned = sweep_text(update.message.text)
        if len(cleaned) > MAX_E2E_PLAINTEXT_CHARS:
            raise ValueError("too long")
    except ValueError:
        await update.message.reply_text(
            f"❌ E2E message must be 1–{MAX_E2E_PLAINTEXT_CHARS} characters."
        )
        return E2E_SEND_TEXT
    context.user_data["e2e_pending_text"] = cleaned
    context.user_data["e2e_send_attempts"] = 0
    await update.message.reply_text(
        "🔐 Send your DID password to unlock the encrypted room key."
    )
    return E2E_SEND_PASSWORD


async def receive_e2e_send_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)
    user_id = update.effective_user.id
    chat_id = context.user_data.get("e2e_chat_id")
    plaintext = context.user_data.get("e2e_pending_text")
    chat = get_e2e_chat(user_id, chat_id) if chat_id else None
    if not chat or not plaintext:
        clear_e2e_state(context)
        return ConversationHandler.END

    attempts = context.user_data.get("e2e_send_attempts", 0)
    try:
        room_key = decrypt_seed(
            chat["encrypted_room_key"],
            chat["salt"],
            chat["encryption_nonce"],
            password,
        )
    except InvalidTag:
        attempts += 1
        context.user_data["e2e_send_attempts"] = attempts
        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_e2e_state(context)
            await update.effective_chat.send_message(
                "❌ E2E send cancelled after 3 incorrect password attempts.",
                reply_markup=e2e_chat_keyboard(chat["id"]),
            )
            return ConversationHandler.END
        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return E2E_SEND_PASSWORD

    try:
        ciphertext = encrypt_e2e_room_text(room_key, plaintext)
        send_e2e_ciphertext(chat["room"], ciphertext)
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "✅ Encrypted message sent to Technocore.\n\n"
            "Technocore stored the AES-GCM ciphertext, not this plaintext.",
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END
    except requests.HTTPError as error:
        response_text = error.response.text[:700] if error.response is not None else ""
        clear_e2e_state(context)
        if "room limit reached" in response_text.lower():
            message = (
                "⏳ Technocore cannot create the private E2E room right now because its room-capacity limit is full.\n\n"
                "Your E2E session and room key are safely saved locally. Retry sending later.\n\n"
                f"Server response:\n{response_text}"
            )
        else:
            message = "❌ Technocore rejected the encrypted message.\n\n" + response_text
        await update.effective_chat.send_message(
            message,
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END
    except Exception as error:
        print("E2E send error:", repr(error))
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ Could not encrypt/send the E2E message.",
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END


async def start_e2e_read(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    try:
        chat_id = int(query.data.split(":", 1)[1])
    except (ValueError, IndexError):
        return ConversationHandler.END
    chat = get_e2e_chat(user_id, chat_id)
    if not chat:
        await query.edit_message_text(
            "❌ E2E chat not found.",
            reply_markup=e2e_menu_keyboard(True),
        )
        return ConversationHandler.END
    clear_e2e_state(context)
    context.user_data["e2e_chat_id"] = chat_id
    context.user_data["e2e_read_attempts"] = 0
    await query.edit_message_text(
        "📥 Read E2E Messages\n\n"
        f"Peer: {shorten_sender(chat['peer_did'])}\n\n"
        "🔐 Send your DID password to unlock the encrypted room key."
    )
    return E2E_READ_PASSWORD


async def receive_e2e_read_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    await delete_sensitive_message(update)
    user_id = update.effective_user.id
    chat_id = context.user_data.get("e2e_chat_id")
    chat = get_e2e_chat(user_id, chat_id) if chat_id else None
    if not chat:
        clear_e2e_state(context)
        return ConversationHandler.END

    attempts = context.user_data.get("e2e_read_attempts", 0)
    try:
        room_key = decrypt_seed(
            chat["encrypted_room_key"],
            chat["salt"],
            chat["encryption_nonce"],
            password,
        )
    except InvalidTag:
        attempts += 1
        context.user_data["e2e_read_attempts"] = attempts
        if attempts >= MAX_PASSWORD_ATTEMPTS:
            clear_e2e_state(context)
            await update.effective_chat.send_message(
                "❌ E2E read cancelled after 3 incorrect password attempts.",
                reply_markup=e2e_chat_keyboard(chat["id"]),
            )
            return ConversationHandler.END
        await update.effective_chat.send_message(
            "❌ Incorrect password.\n\n"
            f"Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}"
        )
        return E2E_READ_PASSWORD

    try:
        room_data = get_room_messages(chat["room"], limit=E2E_ROOM_MESSAGES_LIMIT)
        messages = room_data.get("messages", [])
        latest_seq = room_data.get("last_seq", chat["last_read_seq"]) or chat["last_read_seq"]
        if latest_seq > chat["last_read_seq"]:
            update_e2e_chat_last_read(user_id, chat["id"], latest_seq)
        text = format_decrypted_e2e_messages(chat, messages, room_key)
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            text,
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END
    except requests.HTTPError as error:
        clear_e2e_state(context)
        status = error.response.status_code if error.response is not None else None
        if status == 404:
            message = (
                "📭 This E2E room has no messages yet or has not been created on Technocore. "
                "Send the first encrypted message when room capacity allows."
            )
        else:
            message = "❌ Could not read the E2E room."
        await update.effective_chat.send_message(
            message,
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END
    except Exception as error:
        print("E2E read error:", repr(error))
        clear_e2e_state(context)
        await update.effective_chat.send_message(
            "❌ Could not decrypt the E2E room.",
            reply_markup=e2e_chat_keyboard(chat["id"]),
        )
        return ConversationHandler.END


async def cancel_e2e(update: Update, context: ContextTypes.DEFAULT_TYPE):
    clear_e2e_state(context)
    await update.message.reply_text(
        "E2E action cancelled.",
        reply_markup=e2e_menu_keyboard(get_e2e_key(update.effective_user.id) is not None),
    )
    return ConversationHandler.END


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
            "• Advertise an active mailbox in the DID note\n"
            "• X25519 + HKDF-SHA256 + AES-GCM encrypted rooms\n"
            "• Signed E2E invitations through Technocore mailboxes\n\n"
            "Next:\n"
            "• README / architecture cleanup\n"
            "• 24/7 deployment",
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

    if data == "e2e_menu":
        identity = get_identity(user_id)
        if not identity:
            await query.edit_message_text(
                "🪪 You need a DID before using E2E messaging.",
                reply_markup=no_identity_keyboard(),
            )
            return
        e2e_key = get_e2e_key(user_id)
        await query.edit_message_text(
            e2e_menu_text(user_id),
            reply_markup=e2e_menu_keyboard(e2e_key is not None),
        )
        return

    if data == "e2e_chats":
        chats = get_e2e_chats(user_id)
        await query.edit_message_text(
            e2e_chats_text(chats),
            reply_markup=e2e_chats_keyboard(chats),
        )
        return

    if data.startswith("e2echat:"):
        try:
            chat_id = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            return
        chat = get_e2e_chat(user_id, chat_id)
        if not chat:
            await query.edit_message_text(
                "❌ E2E chat not found.",
                reply_markup=e2e_menu_keyboard(get_e2e_key(user_id) is not None),
            )
            return
        await query.edit_message_text(
            e2e_chat_text(chat),
            reply_markup=e2e_chat_keyboard(chat["id"]),
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


    e2e_setup_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(start_e2e_setup, pattern=r"^e2e_setup$")],
        states={
            E2E_SETUP_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_setup_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_e2e)],
        allow_reentry=True,
    )

    e2e_start_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(start_e2e_chat, pattern=r"^e2e_start$")],
        states={
            E2E_TARGET_DID: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_target_did)
            ],
            E2E_START_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_start_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_e2e)],
        allow_reentry=True,
    )

    e2e_invites_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(start_e2e_invites, pattern=r"^e2e_invites$")],
        states={
            E2E_ACCEPT_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_accept_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_e2e)],
        allow_reentry=True,
    )

    e2e_send_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(start_e2e_send, pattern=r"^e2esend:\d+$")],
        states={
            E2E_SEND_TEXT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_send_text)
            ],
            E2E_SEND_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_send_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_e2e)],
        allow_reentry=True,
    )

    e2e_read_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(start_e2e_read, pattern=r"^e2eread:\d+$")],
        states={
            E2E_READ_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_e2e_read_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_e2e)],
        allow_reentry=True,
    )

    app.add_handler(did_conversation)
    app.add_handler(import_conversation)
    app.add_handler(signed_message_conversation)
    app.add_handler(mailbox_activation_conversation)
    app.add_handler(mailbox_send_conversation)
    app.add_handler(e2e_setup_conversation)
    app.add_handler(e2e_start_conversation)
    app.add_handler(e2e_invites_conversation)
    app.add_handler(e2e_send_conversation)
    app.add_handler(e2e_read_conversation)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("rooms", rooms))
    app.add_handler(CommandHandler("read", read_room))
    app.add_handler(CommandHandler("watch", watch_command))
    app.add_handler(CommandHandler("unwatch", unwatch_command))
    app.add_handler(CommandHandler("identity", identity_command))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CommandHandler("e2e", e2e_command))
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
