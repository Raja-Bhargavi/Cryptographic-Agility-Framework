
"""Unit tests for authentication utilities."""

import pytest

from core.authentication import (
    create_auth_tag,
    verify_auth_tag,
)


TEST_PSK = b"A" * 32


def test_valid_authentication():
    message = {"client": "demo"}

    tag = create_auth_tag(
        TEST_PSK,
        "client-authentication",
        message,
    )

    assert verify_auth_tag(
        TEST_PSK,
        "client-authentication",
        message,
        tag,
    )


def test_modified_message_fails_authentication():
    original = {"client": "demo"}
    modified = {"client": "attacker"}

    tag = create_auth_tag(
        TEST_PSK,
        "client-authentication",
        original,
    )

    assert not verify_auth_tag(
        TEST_PSK,
        "client-authentication",
        modified,
        tag,
    )


def test_wrong_psk_fails_authentication():
    message = {"client": "demo"}

    tag = create_auth_tag(
        TEST_PSK,
        "client-authentication",
        message,
    )

    wrong_psk = b"B" * 32

    assert not verify_auth_tag(
        wrong_psk,
        "client-authentication",
        message,
        tag,
    )


def test_different_authentication_label_fails():
    message = {"client": "demo"}

    tag = create_auth_tag(
        TEST_PSK,
        "client-authentication",
        message,
    )

    assert not verify_auth_tag(
        TEST_PSK,
        "server-authentication",
        message,
        tag,
    )


def test_short_psk_is_rejected():
    with pytest.raises(ValueError):
        create_auth_tag(
            b"short",
            "client-authentication",
            {"client": "demo"},
        )
