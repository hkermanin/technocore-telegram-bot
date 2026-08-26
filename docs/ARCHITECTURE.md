Architecture

This document describes the current architecture of Technocore Gateway.

The application is a Telegram-facing client for Technocore. It combines Telegram interaction, local persistence, cryptographic identity, Technocore HTTP operations, background room monitoring, and experimental encrypted messaging.

Design goals

The architecture aims to keep the project:

understandable to a developer reading it for the first time;

explicit about trust boundaries;

compatible with the existing SQLite data created by earlier versions;

small enough to run as one Python process;

modular enough that API, crypto, database, UI, and Telegram logic can evolve independently.

It is deliberately not a distributed microservice architecture.

Module map

bot.py
 ├── config.py
 ├── database.py
 ├── crypto_utils.py
 ├── technocore_api.py
 ├── backup.py
 └── ui.py

bot.py

Owns Telegram-specific orchestration:

application startup;

command handlers;

callback-query handlers;

ConversationHandler state machines;

password-entry flows;

room-watch background job;

coordination between database, crypto, and Technocore API modules.

It should contain workflows rather than low-level primitives.

config.py

Contains:

API base URL;

Telegram / Technocore limits used by the client;

room-name regular expression;

crypto parameters;

E2E envelope constants;

backup version;

environment loading.

database.py

Owns SQLite schema and persistence.

Current tables:

identities
nonces
mailboxes
room_watches
e2e_keys
e2e_chats
e2e_invites

The module performs lightweight schema migration for fields introduced after the first MVP.

crypto_utils.py

Contains cryptographic primitives and serialization helpers:

Ed25519 did:key creation;

password-based key derivation using Scrypt;

AES-GCM encryption/decryption of private material;

X25519 static key generation;

X25519 shared-secret derivation;

HKDF-SHA256;

E2E invite sealing/opening;

E2E room-message encryption/decryption;

Technocore-compatible single-line text sweep.

technocore_api.py

Contains Technocore-facing logic:

room listing;

room reading;

incremental since=<seq> reads;

signed-message submission;

note reads/writes;

DID-directory location calculation;

directory value parsing/building;

conditional directory updates;

stripping Technocore's server-added untrusted-content wrapper.

backup.py

Owns encrypted backup serialization and validation.

The module knows how to export identity-related encrypted state without exposing plaintext private keys.

ui.py

Contains Telegram presentation logic:

inline keyboards;

status text;

message formatting;

watch-notification formatting;

mailbox/profile/E2E menus.

This keeps visual changes separate from protocol code.

Runtime topology

flowchart TD
    User[Telegram user]
    Telegram[Telegram Bot API]
    Bot[Technocore Gateway process]
    DB[(SQLite)]
    Technocore[technocore.chat]

    User --> Telegram
    Telegram --> Bot
    Bot --> Telegram

    Bot <--> DB
    Bot <--> Technocore

The application currently runs as one long-lived Python process.

Startup sequence

python bot.py
    ↓
load configuration
    ↓
initialize / migrate SQLite schema
    ↓
construct Telegram Application
    ↓
register ConversationHandlers
    ↓
register command + callback handlers
    ↓
start room-watch JobQueue
    ↓
run_polling()

Identity lifecycle

Creation

sequenceDiagram
    participant U as User
    participant B as Bot
    participant C as Crypto
    participant D as SQLite

    U->>B: choose Create DID
    B->>U: request new password
    U->>B: password + confirmation
    B->>C: generate 32-byte Ed25519 seed
    C->>C: derive did:key
    B->>C: Scrypt(password, random salt)
    C->>C: AES-GCM encrypt seed
    B->>D: store encrypted seed + DID
    B->>U: return DID

The password is used transiently and is not stored.

Signing

To publish a signed Technocore message:

stored encrypted seed
        ↓
user password
        ↓
decrypt Ed25519 seed
        ↓
Technocore text sweep
        ↓
room | nonce | swept_text
        ↓
Ed25519 signature
        ↓
POST /r/<room>

The bot persists the most recent nonce per (telegram_user_id, room).

Technocore message sweep

Technocore stores a single logical line per message.

Characters in these Unicode categories are replaced with spaces before signing/storage:

Cc Cf Cs Co Zl Zp

The bot signs the swept value, not the user's raw input, because Technocore verifies the post-sweep bytes.

Room browsing

GET /rooms?format=json
        ↓
top room names
        ↓
Telegram inline keyboard
        ↓
GET /r/<room>?format=json
        ↓
formatted recent messages

Room names and content are treated as untrusted external data.

Room watches

The watch subsystem persists:

telegram_user_id
chat_id
room
last_seq

Every polling cycle:

flowchart LR
    W[All watch rows] --> G[Group by room]
    G --> R[One incremental read per room]
    R --> F[Filter messages per watcher last_seq]
    F --> N[Telegram notification]
    N --> S[Advance persisted cursor]

This avoids making one Technocore request per user when several users watch the same room.

Current interval: approximately 30 seconds.

Mailbox lifecycle

A mailbox candidate is generated locally:

mb-p-<random>

It is not considered active yet.

stateDiagram-v2
    [*] --> Candidate
    Candidate --> Active: signed initialization accepted
    Candidate --> Candidate: room-capacity / network failure
    Active --> Active: signed mailbox traffic

mb- requires signed writes. p- keeps the room out of public discovery.

The hosted Technocore deployment can temporarily refuse creation of new rooms when it reaches its configured capacity. The local state therefore distinguishes candidate from active.

DID directory

The directory location is deterministic.

fingerprint = SHA256(full DID).hexdigest()[:16]
namespace   = "did-" + fingerprint[:2]
key         = fingerprint[2:]

Example shape:

/kv/did-ab/1234567890cdef

The bot builds a value from available identity metadata.

Conceptual format:

did:key:z6Mk...
x25519:<base64url-public-key>
mailbox:mb-p-...

The exact available fields depend on user state.

Conditional update

Ordinary notes are last-write-wins. Directory updates therefore use compare-and-set semantics where possible:

read current value
        ↓
validate expected DID
        ↓
POST new value with "if": current

If the note changed concurrently, Technocore returns 409, allowing the client to re-evaluate instead of blindly overwriting.

Untrusted-content wrapper

Technocore intentionally wraps note reads with an untrusted-content warning.

The client removes only the server-generated wrapper before comparing the stored note payload. The underlying note remains untrusted application data.

X25519 identity keys

E2E messaging uses a separate static X25519 keypair. It is intentionally not the Ed25519 signing key.

X25519 private key
        ↓
Scrypt(password)
        ↓
AES-GCM
        ↓
SQLite

X25519 public key
        ↓
DID directory

Separating signing and key-agreement keys avoids mixing cryptographic purposes.

E2E invite design

The current experimental invite protocol uses:

prefix: e2e1
KDF: HKDF-SHA256
info: technocore-e2e-v1
AEAD: AES-256-GCM

Sender

sequenceDiagram
    participant S as Sender
    participant D as DID Directory
    participant M as Recipient Mailbox
    participant T as Technocore

    S->>D: read recipient DID profile
    D-->>S: X25519 public key + mailbox
    S->>S: generate ephemeral X25519 keypair
    S->>S: X25519(ephemeral private, recipient public)
    S->>S: HKDF -> shared 32-byte key
    S->>S: generate random room key + p- room
    S->>S: AES-GCM seal(room key || room)
    S->>M: signed e2e1 invite
    M->>T: stored as signed mailbox message

Envelope shape:

e2e1 <ephemeral-public> <nonce> <sealed-payload>

Recipient

mailbox invite
      ↓
recipient static X25519 private key
      +
sender ephemeral public key
      ↓
same X25519 shared secret
      ↓
same HKDF key
      ↓
AES-GCM decrypt
      ↓
room key + room name

The room key is then re-encrypted under the user's local password-derived key before being stored in SQLite.

Encrypted room messages

Each chat has a random 32-byte AES key.

For every message:

plaintext
    ↓
Technocore single-line sweep
    ↓
random 12-byte nonce
    ↓
AES-256-GCM
    ↓
<base64url nonce>.<base64url ciphertext>
    ↓
Technocore p- room

Technocore stores the ciphertext envelope.

E2E trust boundary

The term "E2E" in this project refers to encryption across the Technocore transport.

It does not mean Telegram user-device to Telegram user-device E2E.

Telegram user
     ↓ plaintext
Telegram infrastructure
     ↓ plaintext delivered to bot
Gateway process
     ↓ encryption
Technocore
     ↓ ciphertext

The bot host is therefore part of the trusted computing base.

Backup architecture

Backup format version 2 can contain encrypted copies of:

Ed25519 seed;

X25519 private key;

E2E room keys.

It can also contain non-secret metadata such as:

DID;

X25519 public key;

mailbox;

E2E peer DID / room identifiers.

The backup never intentionally exports plaintext private key material.

Failure model

Network failure

Network exceptions do not delete identity or E2E state.

Signed-message uncertainty

If a request times out after transmission, the client should not assume the server did not accept it. Nonces can safely advance because Technocore requires monotonicity, not continuity.

Room capacity

New-room creation can fail while existing rooms remain usable. Candidate mailbox and E2E state is retained for retry.

Directory conflict

The client refuses to automatically overwrite a note that resolves to another DID.

Scaling limits

The current architecture is suitable for an MVP / small community bot.

Potential scale bottlenecks:

synchronous requests calls inside application workflows;

a single SQLite database;

one-process JobQueue;

polling room watches;

password-based decryption performed in the bot process.

Possible future evolution:

requests -> async HTTP client
SQLite -> PostgreSQL
single process -> worker + scheduler
polling -> bounded long-poll strategy
bot.py -> domain-specific handler modules

These changes are intentionally deferred until real usage justifies them.

Non-goals

The current architecture does not attempt to provide:

wallet-grade key custody;

hardware-backed keys;

device-side signing;

device-to-device encrypted Telegram messaging;

verified ownership of world-writable DID directory notes;

permanent storage guarantees on Technocore.