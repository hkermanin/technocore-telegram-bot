import sqlite3
import time
from datetime import datetime, timezone

from config import DATABASE_PATH


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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS e2e_keys (
                telegram_user_id INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                salt BLOB NOT NULL,
                encryption_nonce BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS e2e_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_user_id INTEGER NOT NULL,
                peer_did TEXT NOT NULL,
                room TEXT NOT NULL,
                encrypted_room_key BLOB NOT NULL,
                salt BLOB NOT NULL,
                encryption_nonce BLOB NOT NULL,
                last_read_seq INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE (telegram_user_id, room)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS e2e_invites (
                telegram_user_id INTEGER NOT NULL,
                mailbox_seq INTEGER NOT NULL,
                processed_at TEXT NOT NULL,
                PRIMARY KEY (telegram_user_id, mailbox_seq)
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


def get_e2e_key(telegram_user_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT telegram_user_id, public_key, encrypted_private_key,
                   salt, encryption_nonce, created_at
            FROM e2e_keys
            WHERE telegram_user_id = ?
            """,
            (telegram_user_id,),
        ).fetchone()


def save_e2e_key(
    telegram_user_id,
    public_key,
    encrypted_private_key,
    salt,
    encryption_nonce,
    created_at=None,
):
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO e2e_keys (
                telegram_user_id, public_key, encrypted_private_key,
                salt, encryption_nonce, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(telegram_user_id) DO UPDATE SET
                public_key = excluded.public_key,
                encrypted_private_key = excluded.encrypted_private_key,
                salt = excluded.salt,
                encryption_nonce = excluded.encryption_nonce,
                created_at = excluded.created_at
            """,
            (
                telegram_user_id,
                public_key,
                encrypted_private_key,
                salt,
                encryption_nonce,
                created_at,
            ),
        )
        connection.commit()


def get_e2e_chat(telegram_user_id, chat_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT id, telegram_user_id, peer_did, room, encrypted_room_key,
                   salt, encryption_nonce, last_read_seq, created_at
            FROM e2e_chats
            WHERE telegram_user_id = ? AND id = ?
            """,
            (telegram_user_id, chat_id),
        ).fetchone()


def get_e2e_chat_by_room(telegram_user_id, room):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT id, telegram_user_id, peer_did, room, encrypted_room_key,
                   salt, encryption_nonce, last_read_seq, created_at
            FROM e2e_chats
            WHERE telegram_user_id = ? AND room = ?
            """,
            (telegram_user_id, room),
        ).fetchone()


def get_e2e_chats(telegram_user_id):
    with get_db_connection() as connection:
        return connection.execute(
            """
            SELECT id, telegram_user_id, peer_did, room, encrypted_room_key,
                   salt, encryption_nonce, last_read_seq, created_at
            FROM e2e_chats
            WHERE telegram_user_id = ?
            ORDER BY id DESC
            """,
            (telegram_user_id,),
        ).fetchall()


def save_e2e_chat(
    telegram_user_id,
    peer_did,
    room,
    encrypted_room_key,
    salt,
    encryption_nonce,
    last_read_seq=0,
    created_at=None,
):
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO e2e_chats (
                telegram_user_id, peer_did, room, encrypted_room_key,
                salt, encryption_nonce, last_read_seq, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(telegram_user_id, room) DO UPDATE SET
                peer_did = excluded.peer_did
            """,
            (
                telegram_user_id,
                peer_did,
                room,
                encrypted_room_key,
                salt,
                encryption_nonce,
                int(last_read_seq),
                created_at,
            ),
        )
        connection.commit()

    return get_e2e_chat_by_room(telegram_user_id, room)


def update_e2e_chat_last_read(telegram_user_id, chat_id, last_seq):
    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE e2e_chats
            SET last_read_seq = ?
            WHERE telegram_user_id = ? AND id = ?
            """,
            (int(last_seq), telegram_user_id, chat_id),
        )
        connection.commit()


def e2e_invite_processed(telegram_user_id, mailbox_seq):
    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM e2e_invites
            WHERE telegram_user_id = ? AND mailbox_seq = ?
            """,
            (telegram_user_id, int(mailbox_seq)),
        ).fetchone()
    return row is not None


def mark_e2e_invite_processed(telegram_user_id, mailbox_seq):
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO e2e_invites (
                telegram_user_id, mailbox_seq, processed_at
            )
            VALUES (?, ?, ?)
            """,
            (
                telegram_user_id,
                int(mailbox_seq),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
