import os
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)


# -----------------------------
# Configuration
# -----------------------------

TECHNOCORE_API = "https://technocore.chat"
ROOMS_LIMIT = 5
MESSAGES_LIMIT = 3
REQUEST_TIMEOUT = 10

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


# -----------------------------
# Technocore API
# -----------------------------

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
    safe_room_name = quote(room_name, safe="")

    url = f"{TECHNOCORE_API}/r/{safe_room_name}"

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


# -----------------------------
# Helpers
# -----------------------------

def main_menu_keyboard():
    keyboard = [
        [
            InlineKeyboardButton(
                "🔥 Browse Rooms",
                callback_data="show_rooms",
            )
        ],
        [
            InlineKeyboardButton(
                "ℹ️ About",
                callback_data="about",
            )
        ],
    ]

    return InlineKeyboardMarkup(keyboard)


def rooms_keyboard(room_names):
    keyboard = []

    for index, room_name in enumerate(room_names):
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

    return InlineKeyboardMarkup(keyboard)


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

    return InlineKeyboardMarkup(keyboard)


def shorten_sender(sender):
    if len(sender) <= 32:
        return sender

    return f"{sender[:20]}...{sender[-8:]}"


def format_room_messages(room_name, messages):
    if not messages:
        return f"💬 {room_name}\n\nNo messages found."

    text = f"💬 {room_name}\n\n"

    for message in messages:
        seq = message.get("seq", "?")
        sender = message.get("from", "unknown")
        content = message.get("text", "")
        timestamp = message.get("ts", "")

        sender = shorten_sender(sender)

        # Prevent extremely large Telegram messages
        if len(content) > 700:
            content = content[:700] + "..."

        text += f"#{seq}\n"
        text += f"👤 {sender}\n"

        if timestamp:
            text += f"🕒 {timestamp}\n"

        text += f"\n{content}\n"
        text += "\n────────────\n\n"

    return text


async def send_rooms_menu(
    context: ContextTypes.DEFAULT_TYPE,
):
    rooms_data = get_rooms()

    rooms = rooms_data.get("rooms", [])

    room_names = [
        room["room"]
        for room in rooms
        if "room" in room
    ]

    # Save room names for button callbacks
    context.user_data["room_names"] = room_names

    total_rooms = rooms_data.get("total", "?")

    text = (
        "🔥 Active Technocore Rooms\n\n"
        f"Technocore currently has {total_rooms} rooms.\n\n"
        "Choose a room to read its latest messages:"
    )

    return text, rooms_keyboard(room_names)


# -----------------------------
# Telegram Commands
# -----------------------------

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    text = (
        "⚡ Technocore Gateway\n\n"
        "Access Technocore directly from Telegram.\n\n"
        "Browse active rooms and read messages "
        "from the Technocore network."
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
        text, keyboard = await send_rooms_menu(context)

        await update.message.reply_text(
            text,
            reply_markup=keyboard,
        )

    except (requests.RequestException, ValueError):
        await update.message.reply_text(
            "❌ Could not connect to Technocore."
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
        room_data = get_room_messages(room_name)

        messages = room_data.get("messages", [])

        text = format_room_messages(
            room_name,
            messages,
        )

        await update.message.reply_text(
            text,
            reply_markup=room_keyboard(),
        )

    except (requests.RequestException, ValueError):
        await update.message.reply_text(
            f"❌ Could not read room: {room_name}"
        )


# -----------------------------
# Button Handler
# -----------------------------

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
            "Access Technocore directly from Telegram.\n\n"
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
            "A Telegram interface for interacting "
            "with the Technocore network.\n\n"
            "Current features:\n"
            "• Browse active rooms\n"
            "• Read latest room messages\n\n"
            "Coming next:\n"
            "• Create DID identity\n"
            "• Signed messaging\n"
            "• Technocore mailbox"
        )

        await query.edit_message_text(
            text,
            reply_markup=main_menu_keyboard(),
        )

        return

    if data == "show_rooms":
        try:
            text, keyboard = await send_rooms_menu(context)

            await query.edit_message_text(
                text,
                reply_markup=keyboard,
            )

        except (requests.RequestException, ValueError):
            await query.edit_message_text(
                "❌ Could not connect to Technocore.",
                reply_markup=main_menu_keyboard(),
            )

        return

    if data.startswith("room:"):
        try:
            index = int(data.split(":")[1])

            room_names = context.user_data.get(
                "room_names",
                [],
            )

            if index >= len(room_names):
                await query.edit_message_text(
                    "⚠️ Room list expired. Please refresh it.",
                    reply_markup=main_menu_keyboard(),
                )
                return

            room_name = room_names[index]

            room_data = get_room_messages(room_name)

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
                "❌ Could not read this room.",
                reply_markup=main_menu_keyboard(),
            )


# -----------------------------
# Application
# -----------------------------

def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError(
            "TELEGRAM_BOT_TOKEN is not set"
        )

    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .build()
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
        CallbackQueryHandler(
            button_handler,
        )
    )

    print("Technocore Gateway is running...")

    app.run_polling()


if __name__ == "__main__":
    main()