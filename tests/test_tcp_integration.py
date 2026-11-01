
"""Integration tests for TCP-based cryptographic agility."""

import socket
import threading
import time

import pytest

from client.client import request_negotiation
from core.policy_engine import make_policy
from server.server import run_server_once


HOST = "127.0.0.1"


def get_free_port():
    """Find an available TCP port."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def run_tcp_case(client_caps, server_caps, policy_mode):
    """Start the server and execute one complete client exchange."""

    port = get_free_port()
    server_result = {}
    server_error = {}

    def server_task():
        try:
            server_result["result"] = run_server_once(
                HOST,
                port,
                server_caps,
            )
        except Exception as exc:
            server_error["error"] = exc

    thread = threading.Thread(target=server_task, daemon=True)
    thread.start()

    time.sleep(0.15)

    client_result = request_negotiation(
        HOST,
        port,
        client_caps,
        make_policy(policy_mode),
    )

    thread.join(timeout=5)

    assert not thread.is_alive(), "Server thread did not finish"
    assert "error" not in server_error, str(server_error.get("error"))
    assert "result" in server_result

    return client_result, server_result["result"]


ALL_CAPABILITIES = [
    "X25519",
    "ML-KEM-768",
    "HYBRID-X25519-MLKEM768",
]


def test_tcp_hybrid_execution():
    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["X25519", "HYBRID-X25519-MLKEM768"],
        "PQC_PREFERRED",
    )

    assert client["selected_algorithm"] == "HYBRID-X25519-MLKEM768"
    assert client["execution"] == "SUCCESS"
    assert client["key_confirmation"] == "SUCCESS"
    assert server["key_confirmation"] == "SUCCESS"


def test_tcp_ml_kem_execution():
    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["ML-KEM-768"],
        "PQC_PREFERRED",
    )

    assert client["selected_algorithm"] == "ML-KEM-768"
    assert client["execution"] == "SUCCESS"
    assert client["key_confirmation"] == "SUCCESS"
    assert server["key_confirmation"] == "SUCCESS"


def test_tcp_classical_fallback():
    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["X25519"],
        "PQC_PREFERRED",
    )

    assert client["selected_algorithm"] == "X25519"
    assert client["execution"] == "SUCCESS"
    assert client["key_confirmation"] == "SUCCESS"
    assert server["key_confirmation"] == "SUCCESS"


def test_tcp_hybrid_required_rejects_classical():
    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["X25519"],
        "HYBRID_REQUIRED",
    )

    assert client["status"] == "REJECTED"
    assert client["selected_algorithm"] is None
    assert server["status"] == "REJECTED"



def test_tcp_detects_modified_confirmation_nonce(monkeypatch):
    """Verify that changing a transcript message causes confirmation failure."""

    import client.client as client_module
    import base64

    original_receive_message = client_module.receive_message
    receive_count = 0

    def tampered_receive_message(file):
        nonlocal receive_count

        message = original_receive_message(file)
        receive_count += 1

        # First received message: server authentication challenge.
        # Second received message: negotiation response.
        # Third received message: server cryptographic response.
        if receive_count == 3:
            original_nonce = base64.b64decode(
                message["confirmation_nonce"]
            )

            # Change one byte while keeping the nonce valid Base64.
            modified_nonce = bytes(
                [original_nonce[0] ^ 1]
            ) + original_nonce[1:]

            message["confirmation_nonce"] = base64.b64encode(
                modified_nonce
            ).decode("ascii")

        return message

    # Replace only the client's receive function for this test.
    monkeypatch.setattr(
        client_module,
        "receive_message",
        tampered_receive_message,
    )

    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["X25519"],
        "PQC_PREFERRED",
    )

    assert client["execution"] == "SUCCESS"
    assert client["key_confirmation"] == "FAILED"
    assert client["status"] == "FAILED"

    assert server["key_confirmation"] == "FAILED"



def test_tcp_detects_modified_client_capabilities(monkeypatch):
    """Reject a modified request during server authentication."""

    import client.client as client_module

    original_send_message = client_module.send_message
    modified_request = {}

    def tampered_send_message(file, message):
        if "client_capabilities" in message:
            modified_request.update(message)

            altered_message = {
                **message,
                "client_capabilities": ["X25519"],
            }

            return original_send_message(file, altered_message)

        return original_send_message(file, message)

    monkeypatch.setattr(
        client_module,
        "send_message",
        tampered_send_message,
    )

    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ALL_CAPABILITIES,
        "PQC_PREFERRED",
    )

    # The original client request contained all capabilities.
    assert modified_request["client_capabilities"] == ALL_CAPABILITIES

    # The client rejects the server's authentication response
    # because the server authenticated the modified request.
    assert client["status"] == "FAILED"
    assert client["reason"] == "Server authentication failed."

    # The server detects that the authentication exchange
    # did not complete.
    assert server["status"] == "FAILED"
    assert server["authentication"] == "FAILED"



def test_tcp_detects_modified_server_proof(monkeypatch):
    """Verify that the client rejects a modified server HMAC proof."""

    import base64
    import client.client as client_module

    original_receive_message = client_module.receive_message
    receive_count = 0

    def tampered_receive_message(file):
        nonlocal receive_count

        message = original_receive_message(file)
        receive_count += 1

        # Messages received by the client:
        # 1. Server authentication challenge
        # 2. Negotiation response
        # 3. Server cryptographic response
        # 4. Server key-confirmation proof
        if receive_count == 4:
            original_proof = base64.b64decode(
                message["server_proof"],
                validate=True,
            )

            # Change one byte of the server's proof.
            modified_proof = (
                bytes([original_proof[0] ^ 1])
                + original_proof[1:]
            )

            message["server_proof"] = base64.b64encode(
                modified_proof
            ).decode("ascii")

        return message

    monkeypatch.setattr(
        client_module,
        "receive_message",
        tampered_receive_message,
    )

    client, server = run_tcp_case(
        ALL_CAPABILITIES,
        ["X25519"],
        "PQC_PREFERRED",
    )

    # The server successfully verified the client's proof.
    assert server["key_confirmation"] == "FAILED"

    # The client must reject the modified server proof.
    assert client["execution"] == "SUCCESS"
    assert client["key_confirmation"] == "FAILED"
    assert client["status"] == "FAILED"
