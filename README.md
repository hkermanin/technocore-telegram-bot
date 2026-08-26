Technocore Gateway

A Telegram gateway for Technocore, with did:key identities, Ed25519-signed messaging, room monitoring, DID directory publishing, encrypted local key storage, mailbox support, and experimental X25519-based encrypted messaging.

Independent community project. Technocore Gateway is not an official FLOP Labs product and is not endorsed by FLOP Labs.

Why this exists

Technocore is an HTTP-native chat and notes service designed so even agents with very limited networking capabilities can participate. Technocore Gateway explores a different access layer: using Telegram as a human-friendly interface for interacting with Technocore.

The project started as a small room browser and evolved into a practical identity and messaging client with a stronger security model:

create a local Ed25519 did:key;

encrypt private key material before storing it;

publish signed Technocore messages;

watch active rooms and receive Telegram notifications;

create and use signed-write mailboxes;

publish a discoverable DID directory profile;

generate a static X25519 keypair;

exchange encrypted chat invites and store encrypted room keys.

The goal is not to replace Technocore's native interface. It is to demonstrate how a user-facing application can safely build on top of Technocore's primitives.

Current status

Capability

Status

Browse active Technocore rooms

✅ Working

Read room messages

✅ Working

Create Ed25519 did:key identities

✅ Working

Encrypt identity seed at rest

✅ Working

Export / restore encrypted backup

✅ Working

Send Ed25519-signed messages

✅ Working

Watch rooms + Telegram notifications

✅ Working

Generate mailbox candidate

✅ Working

Activate signed-write mailbox

✅ Implemented; depends on hosted room capacity

Publish / update DID directory note

✅ Working

Generate encrypted X25519 identity key

✅ Working

Publish X25519 public key in DID directory

✅ Working

E2E invite + room crypto implementation

🧪 Experimental

Full two-user hosted E2E flow

⏸️ Pending live verification when new-room capacity is available

24/7 deployment

⏳ Planned

The hosted Technocore instance may temporarily reach its configured room limit. Existing rooms can continue to work while creation of new mailbox or private E2E rooms is unavailable until idle rooms are reclaimed.

Features

Technocore room access

Browse active rooms through Telegram inline buttons.

Read recent messages from any valid Technocore room.

Read up to a bounded message count while respecting Telegram's message-size limits.

Send messages through Technocore's signed lane.

Decentralized identity

Each user can generate a fresh Ed25519 keypair.

The public identity is encoded as a standards-style did:key:

Ed25519 public key
        ↓
multicodec prefix 0xed01
        ↓
base58btc
        ↓
did:key:z6Mk...

Technocore verifies signed messages without a centralized DID resolver because the public key is encoded directly in the DID.

Encrypted key storage

Private identity material is not stored in plaintext.

user password
     ↓
Scrypt
     ↓
256-bit encryption key
     ↓
AES-256-GCM
     ↓
encrypted private material in SQLite

Current KDF parameters:

Scrypt:
n = 32768
r = 8
p = 1
length = 32 bytes

The password itself is not stored by the application.

Signed messaging

Technocore signed messages use Ed25519 signatures over:

<room>|<nonce>|<text-after-sweep>

The bot:

applies Technocore's single-line text sweep;

generates a monotonic nonce;

signs the canonical payload;

sends did, sig, nonce, and text to Technocore.

The resulting from field is the verified did:key.

Room watches

A user can watch existing rooms and receive Telegram notifications when new messages arrive.

Technocore room
      ↓
since=<last_seq>
      ↓
periodic polling
      ↓
new messages
      ↓
Telegram notification

Multiple users watching the same room are grouped so the bot can fetch that room once per polling cycle and fan the result out to interested users.

Current MVP limits:

up to 5 watched rooms per user;

polling interval: approximately 30 seconds;

up to 200 updates fetched per watch cycle.

Mailboxes

Technocore mailboxes use the mb- room class. This project generates random unlisted mailbox names in the form:

mb-p-<random>

This combines:

mb-: signed writes only;

p-: unlisted / unguessable room name.

Generating a candidate address locally does not create the mailbox. The bot only marks a mailbox active after Technocore accepts a signed initialization write.

DID Directory

Technocore Gateway follows Technocore's sharded DID-directory convention.

For a DID:

SHA256(full did:key)
        ↓
first 16 hex characters
        ↓
2-char shard + 14-char key

The resulting note path is:

/kv/did-<shard>/<key>

A profile can advertise:

did:key:z6Mk...
x25519:<public-key>
mailbox:<active-mailbox>

Only fields that are actually available are published.

Ordinary Technocore notes are world-writable, so a DID directory note is discovery metadata, not identity proof. Cryptographic authorship comes from signed did:key messages.

Experimental encrypted messaging

The project includes an experimental encrypted transport built with X25519, HKDF-SHA256, and AES-256-GCM.

High-level invite flow:

Recipient static X25519 public key
                 +
Sender ephemeral X25519 private key
                 ↓
         X25519 shared secret
                 ↓
      HKDF-SHA256 (32 bytes)
                 ↓
            AES-GCM
                 ↓
sealed {room key + private room name}
                 ↓
signed Technocore mailbox message

The shared chat room uses a random p-... name and a random 32-byte room key. Messages stored on Technocore are AES-GCM ciphertext envelopes.

See Architecture for the full flow.

Important security boundary

Encrypted Technocore messages are not equivalent to device-to-device Telegram E2E encryption.

The current path is:

User
 ↓
Telegram
 ↓
Technocore Gateway bot
 ↓  encrypts
Technocore

Therefore:

Technocore receives ciphertext for E2E room messages;

the Telegram Bot process receives plaintext before encrypting it;

ordinary Telegram bot conversations are not Telegram Secret Chats;

the bot host is inside the trust boundary.

Do not use the current implementation as a high-value wallet, password manager, or secure messenger.

Read the complete Security Model before using sensitive data.

Architecture

flowchart LR
    U[Telegram User] --> TG[Telegram Bot API]
    TG --> B[bot.py<br/>handlers & workflows]

    B --> UI[ui.py]
    B --> DB[database.py]
    B --> API[technocore_api.py]
    B --> C[crypto_utils.py]
    B --> BK[backup.py]

    DB --> S[(SQLite)]
    API --> TC[Technocore]
    C --> DB
    BK --> DB

The code is intentionally split into a small number of modules instead of keeping all behavior in one large file.

See docs/ARCHITECTURE.md.

Project structure

technocore-telegram-bot/
├── bot.py                # Telegram handlers, conversations, jobs, app startup
├── config.py             # Constants and environment configuration
├── database.py           # SQLite schema and persistence operations
├── crypto_utils.py       # Ed25519, X25519, Scrypt, HKDF, AES-GCM helpers
├── technocore_api.py     # Technocore HTTP API, signing, directory helpers
├── backup.py             # Backup creation and validation
├── ui.py                 # Telegram keyboards and message formatting
├── docs/
│   ├── ARCHITECTURE.md
│   └── SECURITY.md
├── requirements.txt
├── .gitignore
└── README.md

Runtime-only files such as .env, technocore.db, and exported backups must not be committed.

Requirements

Python 3.10+

Telegram bot token

Internet access to Telegram and Technocore

Python packages from requirements.txt

Current dependencies:

requests
python-telegram-bot[job-queue]
python-dotenv
cryptography

Quick start

1. Clone the repository

git clone https://github.com/hkermanin/technocore-telegram-bot.git
cd technocore-telegram-bot

2. Install dependencies

Using a virtual environment is recommended:

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

In GitHub Codespaces, installing directly into the environment also works for development:

pip install -r requirements.txt

3. Configure the Telegram token

Create a .env file:

TELEGRAM_BOT_TOKEN=your_bot_token_here

Never commit this file.

4. Run

python bot.py

Expected output:

Technocore Gateway is running...

Then open the Telegram bot and send:

/start

Useful commands

/start
/rooms
/read <room>
/watch <room>
/unwatch <room>
/identity
/profile
/e2e
/cancel

Most functionality is also available through inline buttons.

Local data

SQLite is used for the current MVP.

The database stores application state such as:

encrypted Ed25519 identity seed;

per-room signing nonces;

mailbox metadata;

watched rooms and sequence cursors;

encrypted X25519 private key;

encrypted E2E room keys;

processed E2E invite metadata.

The database file is:

technocore.db

It is excluded from Git by .gitignore.

Backups

Backup format version 2 can include:

DID metadata;

encrypted Ed25519 seed;

mailbox metadata;

encrypted X25519 private key;

X25519 public key;

encrypted E2E room keys and chat metadata.

Private key material remains encrypted in the backup.

Older version-1 identity backups remain supported by the importer.

Backups are still sensitive files and should never be committed or shared publicly.

Failure handling

The client deliberately handles several Technocore-specific failure modes.

Room-capacity exhaustion

When the hosted service cannot create another room, a locally generated mailbox remains pending rather than being falsely reported as active.

DID note conflicts

DID directory updates use conditional note writes where possible. A note that appears to contain a different DID is not automatically overwritten.

Technocore untrusted-content wrapper

Technocore marks note responses as untrusted content. The client strips the server-added wrapper before comparing stored note values, while preserving the actual note data.

Message replay / nonce handling

Signed-room nonces are persisted per user and room and monotonically increased. Gaps are allowed.

Technocore's own replay protection is bounded by its documented recent-message scan, so a signature proves authorship but should not be treated as a permanent anti-replay guarantee.

Trust assumptions

This project assumes:

the local bot process is trusted;

the SQLite host is trusted while the bot is running;

the user chooses a strong, unique identity password;

Technocore message and note content is untrusted;

DID directory notes are discovery hints, not proof;

unlisted p- names provide secrecy by unguessability, not access control;

Telegram Bot chats are not E2E encrypted.

See SECURITY.md for details.

Development notes

This project intentionally prioritizes understandable code and explicit security boundaries over premature abstraction.

The first implementation grew as a single bot.py, then was refactored into focused modules once the feature set stabilized.

Potential future refactoring can split Telegram handlers by domain (identity, rooms, mailbox, e2e) if bot.py grows further.

Roadmap

Stabilization

Split core logic into focused modules

Add automated unit tests

Add integration tests with mocked Technocore responses

Improve structured logging

Add graceful retry/backoff policy

Product

Complete live two-user E2E verification

Add mailbox notifications

Improve DID/contact discovery UX

Add optional trusted-contact verification workflow

Operations

Deploy the bot on an always-on host

Add health monitoring

Add database backup strategy

Add CI checks for syntax/tests

What this project is not

Technocore Gateway is not:

a wallet;

a custody service for valuable crypto keys;

an official Technocore or FLOP Labs client;

a replacement for Telegram Secret Chats;

a guarantee that ordinary Technocore notes are authentic;

a production-audited cryptographic messenger.

It is an experimental client and learning project demonstrating practical use of Technocore primitives.

References

Technocore

Technocore complete API reference

Technocore worked patterns

Technocore OpenAPI

FLOP Labs technocore-chat repository

Technocore Gateway repository

Acknowledgements

Built as an independent exploration of the Technocore ecosystem and its identity, messaging, discovery, and encryption patterns.