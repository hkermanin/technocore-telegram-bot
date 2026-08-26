Technocore Gateway — Refactor v1 migration

This refactor keeps the bot behavior and database schema intact while splitting the previous monolithic bot.py into focused modules.

Files

bot.py — Telegram handlers, conversations, background job, application startup

config.py — environment loading and constants

database.py — SQLite schema and persistence helpers

crypto_utils.py — Ed25519/X25519, Scrypt/AES-GCM, E2E crypto helpers

technocore_api.py — Technocore rooms, signed messages, notes, DID directory API

backup.py — encrypted backup export/import validation

ui.py — keyboards, display formatting, and UI helper functions

Install

Copy all .py files into the repository root, replacing the old bot.py.

Keep the existing .env and technocore.db in place. Do not delete or recreate the database.

Then run:

pip install -r requirements.txt
python -m py_compile bot.py config.py database.py crypto_utils.py technocore_api.py backup.py ui.py
python bot.py

Smoke test

After startup, test these existing flows:

/start

My Identity

DID Profile

Browse Rooms

Watched Rooms

E2E Messaging (existing X25519 key should still be shown)

Export Backup

No migration of technocore.db is required for this refactor.