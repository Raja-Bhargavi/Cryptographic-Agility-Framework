
"""TCP client for dynamic cryptographic negotiation and execution."""

import base64
import hashlib
import hmac
import json
import socket
import secrets

from providers.classical import (
    client_start as classical_client_start,
    client_finish as classical_client_finish,
)
from providers.pqc import PQCProvider
from providers.hybrid import HybridProvider
from core.authentication import (
    load_psk,
    create_auth_tag,
    verify_auth_tag,
)


def encode_bytes(value):
    """Convert binary data into JSON-compatible Base64 text."""
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value):
    """Convert Base64 text back into binary data."""
    return base64.b64decode(value, validate=True)


def send_message(file, message):
    """Send one JSON message followed by a newline."""
    data = json.dumps(message).encode("utf-8") + b"\n"
    file.write(data)
    file.flush()


def receive_message(file):
    """Receive one newline-delimited JSON message."""
    line = file.readline()

    if not line:
        raise ConnectionError("Server disconnected unexpectedly")

    return json.loads(line.decode("utf-8"))


def compute_transcript_hash(*messages):
    """Calculate SHA-256 hash of the canonical message transcript."""

    transcript = json.dumps(
        messages,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(transcript).digest()


def prepare_client_operation(algorithm):
    """Prepare the client-side operation for the selected algorithm."""

    if algorithm == "X25519":
        public_key, private_key = classical_client_start()

        client_message = {
            "client_public_key": encode_bytes(public_key)
        }

        return client_message, private_key

    elif algorithm == "ML-KEM-768":
        provider = PQCProvider("ML-KEM-768")
        state = provider.client_start()

        client_message = {
            "client_public_key": encode_bytes(state["public_key"])
        }

        return client_message, (provider, state["key_handle"])

    elif algorithm == "HYBRID-X25519-MLKEM768":
        provider = HybridProvider()
        client_share, client_state = provider.client_start()

        client_message = {
            "mlkem_public_key": encode_bytes(
                client_share["mlkem_public_key"]
            ),
            "x25519_public_key": encode_bytes(
                client_share["x25519_public_key"]
            ),
        }

        return client_message, (provider, client_state)

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def cleanup_client_state(algorithm, client_state):
    """Release retained PQC private-key contexts when necessary."""

    if client_state is None:
        return

    if algorithm == "ML-KEM-768":
        provider, key_handle = client_state
        provider.close_keypair(key_handle)

    elif algorithm == "HYBRID-X25519-MLKEM768":
        provider, state = client_state
        provider.pqc_provider.close_keypair(state.pqc_key_handle)


def complete_client_operation(algorithm, server_response, client_state):
    """Derive the client-side session key."""

    if algorithm == "X25519":
        server_public_key = decode_bytes(
            server_response["server_public_key"]
        )

        return classical_client_finish(
            client_state,
            server_public_key,
        )

    elif algorithm == "ML-KEM-768":
        provider, key_handle = client_state

        ciphertext = decode_bytes(
            server_response["ciphertext"]
        )

        return provider.client_finish(ciphertext, key_handle)

    elif algorithm == "HYBRID-X25519-MLKEM768":
        provider, state = client_state

        response = {
            "mlkem_ciphertext": decode_bytes(
                server_response["mlkem_ciphertext"]
            ),
            "x25519_public_key": decode_bytes(
                server_response["x25519_public_key"]
            ),
        }

        return provider.client_finish(response, state)

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def request_negotiation(host, port, capabilities, policy):
    """Negotiate, execute the selected operation and confirm the key."""

    psk = load_psk()

    client_nonce = secrets.token_bytes(32)

    request = {
        "client_capabilities": capabilities,
        "policy": policy,
        "client_nonce": encode_bytes(client_nonce),
    }

    algorithm = None
    client_state = None

    try:
        with socket.create_connection(
            (host, port),
            timeout=5,
        ) as sock:

            sock.settimeout(10)

            with sock.makefile("rwb") as file:

                # 1. Send capabilities, policy and a fresh client nonce.
                send_message(file, request)

                # 2. Receive the server's authentication challenge.
                server_auth = receive_message(file)

                if server_auth["status"] != "AUTH_CHALLENGE":
                    return {
                        "status": "FAILED",
                        "reason": "Server authentication challenge was not received.",
                    }

                # 3. Build the authentication context.
                server_nonce = decode_bytes(server_auth["server_nonce"])

                if len(server_nonce) != 32:
                    return {
                        "status": "FAILED",
                        "reason": "Invalid server nonce length.",
                    }
            
                auth_context = {
                    "hello": request,
                    "server_nonce": server_auth["server_nonce"],
                }

                # 4. Verify that the server possesses the shared PSK.
                server_tag = decode_bytes(server_auth["server_auth_tag"])

                if not verify_auth_tag(
                    psk,
                    "server-authentication",
                    auth_context,
                    server_tag,
                ):
                    return {
                        "status": "FAILED",
                        "reason": "Server authentication failed.",
                    }

                # 5. Prove that the client possesses the shared PSK.
                client_tag = create_auth_tag(
                    psk,
                    "client-authentication",
                    auth_context,
                )

                send_message(
                    file,
                    {
                        "client_auth_tag": encode_bytes(client_tag),
                    },
                )

                # 6. Receive the actual negotiation decision.
                negotiation = receive_message(file)

                if negotiation["status"] != "SUCCESS":
                    return negotiation

                algorithm = negotiation["selected_algorithm"]

                # 3. Prepare the selected cryptographic operation.
                client_message, client_state = prepare_client_operation(
                    algorithm
                )

                # 4. Send client public-key material.
                send_message(file, client_message)

                # 5. Receive the server's cryptographic response.
                server_response = receive_message(file)

                if server_response["status"] != "SUCCESS":
                    return {
                        **negotiation,
                        "execution": "FAILED",
                        "status": "FAILED",
                        "reason": (
                            "Server could not complete "
                            "cryptographic operation."
                        ),
                    }

                # 6. Derive the client's session key.
                session_key = complete_client_operation(
                    algorithm,
                    server_response,
                    client_state,
                )

                # The provider's client_finish method releases its
                # retained PQC private-key context.
                client_state = None

                # 7. Calculate the complete exchange transcript hash.
                transcript_hash = compute_transcript_hash(
                    request,
                    negotiation,
                    client_message,
                    server_response,
                )

                # 8. Generate transcript-bound key confirmation.
                nonce = decode_bytes(
                    server_response["confirmation_nonce"]
                )

                proof = hmac.new(
                    session_key,
                    b"client-finished:"
                    + nonce
                    + transcript_hash,
                    hashlib.sha256,
                ).digest()

                send_message(
                    file,
                    {"proof": encode_bytes(proof)},
                )

                # 9. Receive the server's confirmation result.
                confirmation = receive_message(file)

                if confirmation.get("status") != "SUCCESS":
                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                        "status": "FAILED",
                        "reason": "Server key confirmation failed.",
                    }

                try:
                    received_server_proof = decode_bytes(
                        confirmation["server_proof"]
                    )
                except (KeyError, ValueError):
                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                        "status": "FAILED",
                        "reason": "Invalid server key confirmation proof.",
                    }

                expected_server_proof = hmac.new(
                    session_key,
                    b"server-finished:"
                    + nonce
                    + transcript_hash
                    + proof,
                    hashlib.sha256,
                ).digest()

                
                server_confirmed = hmac.compare_digest(
                    expected_server_proof,
                    received_server_proof,
                )

                if not server_confirmed:
                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                        "status": "FAILED",
                        "reason": "Server key confirmation failed.",
                    }

                # Client has verified the server's proof.
                # Now acknowledge this verification to the server.
                client_ack = hmac.new(
                    session_key,
                    b"client-ack:"
                    + nonce
                    + transcript_hash
                    + received_server_proof,
                    hashlib.sha256,
                ).digest()

                send_message(
                    file,
                    {"client_ack": encode_bytes(client_ack)},
                )

                # Wait for the server's final acknowledgement result.
                final_confirmation = receive_message(file)

                final_status = final_confirmation.get("status")

                if final_status != "SUCCESS":
                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                        "status": "FAILED",
                        "reason": "Server rejected client acknowledgement.",
                    }

                return {
                    **negotiation,
                    "execution": "SUCCESS",
                    "key_confirmation": "SUCCESS",
                    "status": "SUCCESS",
                    "key_length": len(session_key),
                    "algorithm": algorithm,
                }


    finally:
        # Clean up retained private-key state if execution did not
        # reach the provider's client_finish operation.
        cleanup_client_state(algorithm, client_state)
