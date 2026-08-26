import base64
import secrets
import unicodedata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config import (
    AES_NONCE_SIZE,
    E2E_INFO,
    E2E_INVITE_PREFIX,
    E2E_ROOM_PREFIX,
    INVISIBLE_CATEGORIES,
    MAX_E2E_PLAINTEXT_CHARS,
    MAX_MESSAGE_CHARS,
    MULTICODEC_ED25519,
    ROOM_NAME_RE,
    SALT_SIZE,
    SCRYPT_KEY_LENGTH,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)


def base58btc_encode(raw):
    alphabet = (
        "123456789"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz"
    )

    if not raw:
        return ""

    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded

    return "1" * leading_zeroes + encoded


def create_did_from_private_key(private_key):
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    multicodec_key = MULTICODEC_ED25519 + public_key_bytes
    return f"did:key:z{base58btc_encode(multicodec_key)}"


def generate_identity():
    seed = secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return seed, create_did_from_private_key(private_key)


def did_from_seed(seed):
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return create_did_from_private_key(private_key)


def derive_encryption_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_seed(seed, password):
    salt = secrets.token_bytes(SALT_SIZE)
    encryption_nonce = secrets.token_bytes(AES_NONCE_SIZE)
    encryption_key = derive_encryption_key(password, salt)
    encrypted_seed = AESGCM(encryption_key).encrypt(
        encryption_nonce,
        seed,
        None,
    )
    return encrypted_seed, salt, encryption_nonce


def decrypt_seed(encrypted_seed, salt, encryption_nonce, password):
    encryption_key = derive_encryption_key(password, salt)
    return AESGCM(encryption_key).decrypt(
        encryption_nonce,
        encrypted_seed,
        None,
    )


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value):
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid base64url value")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except Exception as error:
        raise ValueError("Invalid base64url value") from error


def generate_x25519_keypair():
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, b64url_encode(public_bytes)


def x25519_public_from_private(private_bytes):
    private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    return b64url_encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def derive_e2e_shared(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=E2E_INFO,
    ).derive(shared_secret)


def create_e2e_invite(recipient_public_b64):
    recipient_public_raw = b64url_decode(recipient_public_b64)
    if len(recipient_public_raw) != 32:
        raise ValueError("Recipient X25519 public key must be 32 bytes")

    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_raw)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_raw = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_key = derive_e2e_shared(ephemeral_private, recipient_public)

    room_key = secrets.token_bytes(32)
    room = E2E_ROOM_PREFIX + secrets.token_hex(16)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    sealed_payload = room_key + room.encode("utf-8")
    sealed = AESGCM(shared_key).encrypt(nonce, sealed_payload, None)

    envelope = (
        f"{E2E_INVITE_PREFIX} "
        f"{b64url_encode(ephemeral_public_raw)} "
        f"{b64url_encode(nonce)} "
        f"{b64url_encode(sealed)}"
    )
    return room, room_key, envelope


def open_e2e_invite(static_private_bytes, envelope):
    parts = envelope.strip().split()
    if len(parts) != 4 or parts[0] != E2E_INVITE_PREFIX:
        raise ValueError("Invalid E2E invitation format")

    ephemeral_public_raw = b64url_decode(parts[1])
    nonce = b64url_decode(parts[2])
    sealed = b64url_decode(parts[3])

    if len(ephemeral_public_raw) != 32 or len(nonce) != AES_NONCE_SIZE:
        raise ValueError("Invalid E2E invitation fields")

    static_private = X25519PrivateKey.from_private_bytes(static_private_bytes)
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_raw)
    shared_key = derive_e2e_shared(static_private, ephemeral_public)
    payload = AESGCM(shared_key).decrypt(nonce, sealed, None)

    if len(payload) <= 32:
        raise ValueError("Invalid sealed E2E payload")

    room_key = payload[:32]
    try:
        room = payload[32:].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Invalid E2E room encoding") from error

    if not ROOM_NAME_RE.fullmatch(room) or not room.startswith(E2E_ROOM_PREFIX):
        raise ValueError("Invalid E2E room name")

    return room, room_key


def encrypt_e2e_room_text(room_key, plaintext):
    if len(room_key) != 32:
        raise ValueError("Invalid E2E room key")
    cleaned = sweep_text(plaintext)
    if len(cleaned) > MAX_E2E_PLAINTEXT_CHARS:
        raise ValueError(
            f"E2E message is too long; maximum is {MAX_E2E_PLAINTEXT_CHARS} characters"
        )
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    ciphertext = AESGCM(room_key).encrypt(nonce, cleaned.encode("utf-8"), None)
    envelope = f"{b64url_encode(nonce)}.{b64url_encode(ciphertext)}"
    if len(envelope) > MAX_MESSAGE_CHARS:
        raise ValueError("Encrypted E2E envelope exceeds Technocore message limit")
    return envelope


def decrypt_e2e_room_text(room_key, envelope):
    if len(room_key) != 32:
        raise ValueError("Invalid E2E room key")
    if not isinstance(envelope, str) or envelope.count(".") != 1:
        raise ValueError("Not an E2E ciphertext line")
    nonce_b64, ciphertext_b64 = envelope.split(".", 1)
    nonce = b64url_decode(nonce_b64)
    ciphertext = b64url_decode(ciphertext_b64)
    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError("Invalid E2E message nonce")
    plaintext = AESGCM(room_key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def sweep_text(text):
    cleaned = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()

    if not cleaned:
        raise ValueError("Message is empty after sweep")

    if len(cleaned) > MAX_MESSAGE_CHARS:
        raise ValueError("Message is too long")

    return cleaned
