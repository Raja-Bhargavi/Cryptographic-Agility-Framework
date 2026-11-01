
"""Classical cryptographic provider using X25519 and HKDF-SHA256."""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive_session_key(raw_secret):
    """Derive a 32-byte application key from an X25519 shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"crypto-agility-demo-v1",
    ).derive(raw_secret)


def _raw_public_key(public_key):
    """Serialize an X25519 public key into 32 raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def client_start():
    """Client generates an ephemeral key pair and sends its public key."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = _raw_public_key(private_key.public_key())

    return public_key, private_key


def server_respond(client_public_bytes):
    """Server receives the client's public key and derives a shared key."""
    if len(client_public_bytes) != 32:
        raise ValueError("Invalid X25519 client public key length")

    client_public_key = x25519.X25519PublicKey.from_public_bytes(
        client_public_bytes
    )

    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = _raw_public_key(server_private_key.public_key())

    raw_secret = server_private_key.exchange(client_public_key)
    server_session_key = _derive_session_key(raw_secret)

    return server_public_key, server_session_key


def client_finish(client_private_key, server_public_bytes):
    """Client receives the server's public key and derives the same key."""
    if len(server_public_bytes) != 32:
        raise ValueError("Invalid X25519 server public key length")

    server_public_key = x25519.X25519PublicKey.from_public_bytes(
        server_public_bytes
    )

    raw_secret = client_private_key.exchange(server_public_key)

    return _derive_session_key(raw_secret)


def x25519_shared_secret():
    """Backward-compatible demonstration that simulates both peers."""
    client_public, client_private = client_start()

    server_public, server_key = server_respond(client_public)

    client_key = client_finish(client_private, server_public)

    return {
        "client_key": client_key,
        "server_key": server_key,
        "match": client_key == server_key,
        "algorithm": "X25519 + HKDF-SHA256",
    }
