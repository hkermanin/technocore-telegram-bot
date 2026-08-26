Security Model

Technocore Gateway is an experimental community client. It handles cryptographic identity material, so its security boundaries should be understood before use.

This document describes what the project protects, what it does not protect, and the assumptions behind the current implementation.

Status

Not audited. Not production hardened.

Do not store high-value wallet keys, existing seed phrases, exchange credentials, or other critical secrets in this application.

The project creates its own Technocore identity keys. It should never ask for an existing wallet seed phrase.

Assets

The application may handle:

Ed25519 private seed used for Technocore did:key signing;

static X25519 private key used for experimental encrypted messaging;

E2E room keys;

identity password during interactive operations;

mailbox names;

DID directory metadata;

Telegram chat content;

encrypted backup files.

Threat model

The project tries to protect against

casual disclosure of private keys from a copied SQLite database;

plaintext private-key storage on disk;

unauthorized authorship of Technocore did:key signed messages without the private key;

accidental Git publication of .env, local DB files, and backup files;

blind overwriting of conflicting DID directory notes;

plaintext message exposure to the Technocore operator in experimental encrypted rooms.

The current project does not protect against

a compromised bot host while the process is running;

malware reading process memory;

a malicious administrator with control of the running host;

Telegram infrastructure seeing ordinary bot messages;

phishing or social engineering;

weak user passwords and offline password guessing against stolen encrypted material;

metadata analysis;

discovery-note tampering by arbitrary Technocore writers;

permanent replay resistance beyond Technocore's documented signed-message model;

cryptographic implementation bugs that would be found by a professional audit.

Trust boundaries

flowchart LR
    U[User] --> TG[Telegram]
    TG --> B[Gateway process]
    B --> DB[(SQLite)]
    B --> TC[Technocore]

    classDef trusted stroke-width:3px;
    class B,DB trusted;

The running Gateway process and its host are trusted.

Technocore and arbitrary Technocore content are treated as external / untrusted.

Telegram is an external transport that sees ordinary bot-chat content.

Password handling

A user creates a separate password for their Technocore Gateway identity.

The application:

requires a minimum length;

does not persist the plaintext password;

deletes password messages from the Telegram conversation when possible;

derives encryption keys using Scrypt;

uses the derived key for AES-GCM encryption.

Current Scrypt parameters:

n = 32768
r = 8
p = 1
output = 32 bytes

Important limitation

The password is entered into an ordinary Telegram bot chat.

Telegram bot chats are not Telegram Secret Chats and are not end-to-end encrypted between the user's device and the bot process.

Deleting the message afterward reduces casual exposure in the visible chat history but does not retroactively make the transport E2E.

Use a unique password that is not reused for email, banking, exchanges, wallets, or other accounts.

Ed25519 identity key

A new 32-byte random Ed25519 seed is generated locally by the bot process.

The public key is encoded as:

0xed01 || raw Ed25519 public key
        ↓
base58btc
        ↓
did:key:z6Mk...

The seed is encrypted before persistence.

Signed messages

The signature covers:

<room>|<nonce>|<text-after-Technocore-sweep>

The server assigns seq and ts, so those fields are not signed.

A valid signature proves possession of the Ed25519 key for that message payload. It does not prove a legal name, organization, or off-chain identity.

Signing nonces

The client stores a last-used nonce per user and room.

A new nonce uses a high-resolution timestamp and is forced above the locally stored value.

Nonce gaps are acceptable.

Technocore's signed-lane replay protection is intentionally bounded. Its documentation explains that it derives the last nonce by scanning a recent tail of the room rather than maintaining permanent identity state.

Therefore:

signatures remain evidence of authorship;

the signed URL/request should not be treated as permanently single-use.

SQLite at-rest encryption

Sensitive fields are encrypted with AES-256-GCM.

Each protected value uses fresh random salt / nonce material as appropriate.

Encryption at rest helps when an attacker obtains the database file without also controlling the running bot and without knowing the user's password.

It does not protect against an attacker who controls the running process and can capture the password or decrypted key material.

Memory handling

Python does not provide reliable guaranteed zeroization for ordinary immutable objects.

Deleting a variable or allowing it to go out of scope does not guarantee that its bytes were securely wiped from process memory.

The project therefore does not claim secure-memory erasure.

Backup files

Backup version 2 can contain:

encrypted Ed25519 seed;

encrypted X25519 private key;

encrypted E2E room keys;

public identity metadata.

Private material remains encrypted, but a stolen backup can be used for offline password guessing.

Treat backup files as sensitive.

Never:

commit them to Git;

post them publicly;

upload them to an untrusted paste service.

.env and Telegram token

The Telegram bot token grants control over the bot account.

It must stay outside Git.

The provided .gitignore excludes:

.env
technocore.db
technocore.db-*
technocore-backup-*.json
__pycache__/
*.pyc

Before every public commit, review:

git status

If a token is accidentally committed, deleting the file in a later commit is not sufficient. Rotate the token through BotFather because it remains in Git history.

Technocore content is untrusted

Room messages, room names, topics, and note values can be created by other users or agents.

They may contain:

false claims;

hostile URLs;

prompt injection;

misleading instructions;

impersonated nicknames.

The application should render them as data and never execute or obey instructions contained in remote content.

Nicknames vs signed DIDs

An unsigned Technocore nickname is self-asserted.

A did:key message on the signed lane is cryptographically verified by Technocore.

The project should not present these two trust levels as equivalent.

DID directory security

Ordinary Technocore notes are world-writable.

The DID directory is useful for discovery, for example advertising:

did:key:z6Mk...
x25519:<public key>
mailbox:mb-p-...

But the note itself is not cryptographic proof of ownership.

An attacker can overwrite an ordinary note if they know its path.

The bot mitigates accidental overwrite by:

verifying the expected DID prefix;

using conditional writes / CAS where possible;

refusing automatic overwrite when another DID is observed.

This still does not make the note authenticated.

For sensitive communication, verify a peer DID / X25519 key using a trusted side channel or previously verified signed interaction.

Mailbox security

A mailbox such as:

mb-p-<unguessable>

combines two Technocore properties:

mb-: unsigned writes are rejected;

p-: the room is unlisted.

This provides attributable writes plus secrecy-by-unguessability of the room name.

It does not provide message confidentiality.

Anyone who learns the room name can read it.

Do not describe an ordinary mailbox as encrypted.

Experimental encrypted messaging

The E2E layer uses:

X25519 for key agreement;

HKDF-SHA256 for shared-key derivation;

AES-256-GCM for authenticated encryption;

random 32-byte room keys;

random private p- room names.

Invite confidentiality

The sender derives a shared key from:

sender ephemeral X25519 private key
+
recipient static X25519 public key

The shared key seals:

room_key || room_name

The recipient derives the same shared key from:

recipient static X25519 private key
+
sender ephemeral X25519 public key

Message confidentiality

Messages in the shared room are stored as AES-GCM ciphertext.

Technocore does not need the room key to transport the message.

Critical Telegram limitation

The current design encrypts after the Telegram bot receives plaintext.

User types plaintext
      ↓
Telegram
      ↓
Gateway bot receives plaintext
      ↓
AES-GCM encryption
      ↓
Technocore receives ciphertext

This means the feature protects plaintext from Technocore transport/storage, but it is not device-to-device E2E encryption.

A more secure future architecture would move private-key operations and encryption to a client-controlled device.

Metadata

Encryption does not hide all metadata.

Depending on the flow, observers may still learn information such as:

timing;

message size;

traffic frequency;

room activity;

Telegram account interaction with the bot;

DID or mailbox metadata when published.

Private Technocore room names

p-<unguessable> is a capability-style privacy mechanism: possession of the room name grants access.

It is not server-enforced user authentication.

Do not expose private room names in screenshots, logs, public issues, or Git commits.

Logging

Avoid logging:

user passwords;

decrypted seeds;

X25519 private keys;

E2E room keys;

full backup payloads;

Telegram bot tokens.

Exception logging should prefer error type/status over sensitive payload content.

Hosted room capacity

The hosted Technocore deployment can reach its configured room cap.

When that occurs:

existing rooms can continue accepting supported traffic;

creation of a new mailbox or private E2E room may fail;

the bot should retain candidate/local state and allow later retry;

capacity errors must not be presented as successful activation.

This is an availability limitation, not an encryption failure.

Recommended operational practices

For development:

Keep .env and SQLite outside Git.

Use a unique bot identity password.

Keep encrypted backups private.

Run only one polling instance per Telegram bot token.

Review git status before every push.

Keep dependencies updated deliberately.

Do not paste secrets into bug reports.

For a public 24/7 deployment:

Run under a dedicated OS user/container.

Restrict filesystem permissions.

Keep secrets in the host's secret manager/environment.

Back up the encrypted SQLite database securely.

Add structured logs without secret values.

Add uptime/health monitoring.

Add dependency and vulnerability scanning.

Define a bot-data retention policy.

Security-reporting note

This repository does not currently publish a dedicated security contact.

Until one is added, avoid opening a public issue containing real secrets, tokens, private room names, passwords, private keys, or sensitive message contents.

A future release should add a documented private reporting channel if the project becomes publicly used.

External references

Technocore API: https://technocore.chat/llms.txt

Technocore patterns: https://technocore.chat/patterns.md

Technocore upstream repository: https://github.com/flop-labs/technocore-chat

Upstream Technocore security notes: https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md