import secrets

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from config import TELEGRAM_TEXT_LIMIT, WATCH_POLL_INTERVAL
from crypto_utils import decrypt_e2e_room_text
from database import get_e2e_chats, get_e2e_key, mark_mailbox_active
PROJECT_REPO_URL = "https://github.com/hkermanin/technocore-telegram-bot"
DEVELOPER_GITHUB_URL = "https://github.com/hkermanin"
DEVELOPER_X_URL = "https://x.com/ananimatorman"
TECHNOCORE_URL = "https://technocore.chat"


from technocore_api import (
    build_did_directory_value,
    did_directory_location,
    get_room_messages,
    get_rooms,
)


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
            [InlineKeyboardButton("🔐 E2E Messaging", callback_data="e2e_menu")],
            [InlineKeyboardButton("♻️ Import Backup", callback_data="import_backup")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about")],
        ]
    )


def about_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📦 Source Code", url=PROJECT_REPO_URL),
                InlineKeyboardButton("👨‍💻 GitHub", url=DEVELOPER_GITHUB_URL),
            ],
            [
                InlineKeyboardButton("𝕏 Developer X", url=DEVELOPER_X_URL),
                InlineKeyboardButton("🌐 Technocore", url=TECHNOCORE_URL),
            ],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def identity_keyboard():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📦 Export Backup", callback_data="export_backup")],
            [InlineKeyboardButton("🌐 DID Profile", callback_data="did_profile")],
            [InlineKeyboardButton("🔐 E2E Messaging", callback_data="e2e_menu")],
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


def e2e_menu_keyboard(has_key):
    if not has_key:
        return InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("🔑 Enable X25519 E2E", callback_data="e2e_setup")],
                [InlineKeyboardButton("🌐 DID Profile", callback_data="did_profile")],
                [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
            ]
        )

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("➕ Start E2E Chat", callback_data="e2e_start")],
            [InlineKeyboardButton("📨 Check E2E Invites", callback_data="e2e_invites")],
            [InlineKeyboardButton("💬 My E2E Chats", callback_data="e2e_chats")],
            [InlineKeyboardButton("🌐 DID Profile", callback_data="did_profile")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="home")],
        ]
    )


def e2e_chats_keyboard(chats):
    keyboard = []
    for chat in chats[:20]:
        peer = shorten_sender(chat["peer_did"])
        keyboard.append(
            [InlineKeyboardButton(f"💬 {peer}", callback_data=f"e2echat:{chat['id']}")]
        )
    keyboard.append([InlineKeyboardButton("➕ Start E2E Chat", callback_data="e2e_start")])
    keyboard.append([InlineKeyboardButton("🔐 E2E Menu", callback_data="e2e_menu")])
    keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data="home")])
    return InlineKeyboardMarkup(keyboard)


def e2e_chat_keyboard(chat_id):
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📥 Read Encrypted Messages", callback_data=f"e2eread:{chat_id}")],
            [InlineKeyboardButton("✍️ Send Encrypted Message", callback_data=f"e2esend:{chat_id}")],
            [InlineKeyboardButton("💬 My E2E Chats", callback_data="e2e_chats")],
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

    e2e_key = get_e2e_key(identity["telegram_user_id"])
    if e2e_key:
        lines.extend([
            "🔐 X25519 public key advertised:",
            e2e_key["public_key"],
            "",
        ])
    else:
        lines.extend([
            "🔐 X25519: not configured",
            "Enable it from E2E Messaging to receive encrypted invitations.",
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


def clear_e2e_state(context):
    for key in (
        "e2e_setup_attempts",
        "e2e_target_did",
        "e2e_target_public",
        "e2e_target_mailbox",
        "e2e_start_attempts",
        "e2e_pending_invites",
        "e2e_accept_attempts",
        "e2e_chat_id",
        "e2e_pending_text",
        "e2e_send_attempts",
        "e2e_read_attempts",
    ):
        context.user_data.pop(key, None)


def e2e_menu_text(user_id):
    e2e_key = get_e2e_key(user_id)
    chats = get_e2e_chats(user_id)
    lines = ["🔐 Technocore E2E Messaging", ""]
    if e2e_key:
        lines.extend([
            "✅ Static X25519 key: configured",
            f"Public key:\n{e2e_key['public_key']}",
            f"💬 Saved E2E chats: {len(chats)}",
        ])
    else:
        lines.extend([
            "⏳ Static X25519 key: not configured",
            "Enable X25519 first. The public key will be added to your DID directory profile.",
        ])
    lines.extend([
        "",
        "Technocore stores only ciphertext for E2E room messages.",
        "⚠️ Telegram bot chats themselves are NOT end-to-end encrypted, so this gateway still receives your plaintext and password while processing them.",
        "Technocore can still observe metadata such as room names, message sizes and timing.",
    ])
    return "\n".join(lines)


def e2e_chats_text(chats):
    if not chats:
        return (
            "💬 My E2E Chats\n\n"
            "No E2E sessions are saved yet. Start one with a DID whose directory profile advertises both x25519: and mailbox:."
        )
    lines = ["💬 My E2E Chats", ""]
    for chat in chats[:20]:
        lines.extend([
            f"#{chat['id']} — {shorten_sender(chat['peer_did'])}",
            f"Room: {chat['room']}",
            "",
        ])
    return "\n".join(lines).rstrip()


def e2e_chat_text(chat):
    return (
        "🔐 E2E Chat\n\n"
        f"Peer DID:\n{chat['peer_did']}\n\n"
        f"Private room:\n{chat['room']}\n\n"
        "The room key is encrypted at rest. Your DID password is required to read or send plaintext."
    )


def format_decrypted_e2e_messages(chat, messages, room_key):
    lines = [
        "🔐 Decrypted E2E Messages",
        "",
        f"Peer: {shorten_sender(chat['peer_did'])}",
        f"Room: {chat['room']}",
        "",
    ]
    shown = 0
    skipped = 0
    for message in messages:
        envelope = message.get("text", "")
        try:
            plaintext = decrypt_e2e_room_text(room_key, envelope)
        except Exception:
            skipped += 1
            continue
        seq = message.get("seq", "?")
        if len(plaintext) > 700:
            plaintext = plaintext[:700] + "..."
        block = f"#{seq}\n{plaintext}\n\n────────────\n\n"
        if len("\n".join(lines)) + len(block) > TELEGRAM_TEXT_LIMIT:
            lines.append("… More decrypted messages were omitted to fit Telegram's limit.")
            break
        lines.append(block.rstrip())
        shown += 1
    if shown == 0:
        lines.append("No decryptable E2E messages found yet.")
    if skipped:
        lines.extend(["", f"⚠️ {skipped} non-decryptable/untrusted line(s) were ignored."])
    return "\n".join(lines)
