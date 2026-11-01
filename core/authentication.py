
"""Shared authentication utilities for the cryptographic-agility framework."""

import hashlib
import hmac
import json
import os


def canonicalize(message):
    """Convert a message into deterministic JSON bytes."""
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_auth_tag(psk, label, message):
    """Create an HMAC-SHA256 authentication tag."""

    if not isinstance(psk, bytes) or len(psk) < 32:
        raise ValueError("PSK must contain at least 32 bytes")

    if not isinstance(label, str) or not label:
        raise ValueError("Authentication label cannot be empty")

    message_bytes = canonicalize(message)

    authenticated_data = (
        b"crypto-agility-auth-v1:"
        + label.encode("utf-8")
        + b":"
        + message_bytes
    )

    return hmac.new(
        psk,
        authenticated_data,
        hashlib.sha256,
    ).digest()


def verify_auth_tag(psk, label, message, received_tag):
    """Verify an HMAC-SHA256 authentication tag."""

    expected_tag = create_auth_tag(
        psk,
        label,
        message,
    )

    return hmac.compare_digest(
        expected_tag,
        received_tag,
    )

def load_psk():
    """Load the 32-byte pre-shared key from an environment variable."""

    value = os.environ.get("CRYPTO_AGILITY_PSK")

    if not value:
        raise RuntimeError(
            "CRYPTO_AGILITY_PSK environment variable is not configured"
        )

    try:
        psk = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            "CRYPTO_AGILITY_PSK must contain hexadecimal text"
        ) from exc

    if len(psk) != 32:
        raise ValueError(
            "CRYPTO_AGILITY_PSK must represent exactly 32 bytes"
        )

    return psk
