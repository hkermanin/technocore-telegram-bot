import os

import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


TECHNOCORE_API = "https://technocore.chat"

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


def get_rooms():
    url = f"{TECHNOCORE_API}/rooms"

    params = {
        "format": "json",
        "limit": 5,
    }

    response = requests.get(url, params=params)
    response.raise_for_status()

    return response.json()


async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    await update.message.reply_text(
        "Welcome to Technocore Gateway 👋\n\n"
        "Use /rooms to see active Technocore rooms."
    )


async def rooms(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    rooms_data = get_rooms()

    message = "🔥 Active Technocore Rooms\n\n"

    for index, room in enumerate(rooms_data["rooms"], start=1):
        message += f"{index}. {room['room']}\n"

    await update.message.reply_text(message)


def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("rooms", rooms))

    print("Bot is running...")

    app.run_polling()


if __name__ == "__main__":
    main()