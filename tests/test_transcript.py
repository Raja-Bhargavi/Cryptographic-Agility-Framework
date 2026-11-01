
"""Tests for cryptographic-agility transcript hashing."""

from client.client import compute_transcript_hash


def test_identical_transcripts_produce_same_hash():
    message1 = {
        "algorithm": "ML-KEM-768",
        "status": "SUCCESS",
    }

    message2 = {
        "client_capabilities": ["X25519", "ML-KEM-768"],
    }

    hash1 = compute_transcript_hash(message1, message2)
    hash2 = compute_transcript_hash(message1, message2)

    assert hash1 == hash2


def test_dictionary_order_does_not_change_hash():
    message1 = {
        "algorithm": "ML-KEM-768",
        "status": "SUCCESS",
    }

    message2 = {
        "status": "SUCCESS",
        "algorithm": "ML-KEM-768",
    }

    assert compute_transcript_hash(message1) == (
        compute_transcript_hash(message2)
    )


def test_modified_message_changes_transcript_hash():
    original = {
        "algorithm": "ML-KEM-768",
        "status": "SUCCESS",
    }

    modified = {
        "algorithm": "X25519",
        "status": "SUCCESS",
    }

    original_hash = compute_transcript_hash(original)
    modified_hash = compute_transcript_hash(modified)

    assert original_hash != modified_hash


def test_transcript_hash_is_32_bytes():
    message = {"algorithm": "X25519"}

    digest = compute_transcript_hash(message)

    assert len(digest) == 32
