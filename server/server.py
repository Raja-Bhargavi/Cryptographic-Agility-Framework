
"""TCP server for dynamic cryptographic negotiation and execution."""

import base64
import hashlib
import hmac
import json
import secrets
import socket

from core.negotiation import negotiate
from providers.classical import server_respond as classical_server_respond
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
        raise ConnectionError("Client disconnected unexpectedly")

    return json.loads(line.decode("utf-8"))

def compute_transcript_hash(*messages):
    """Create a SHA-256 hash of the canonical negotiation transcript."""

    transcript = json.dumps(
        messages,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(transcript).digest()

def handle_request(request, server_capabilities):
    """Negotiate an algorithm based on peer capabilities and policy."""
    result = negotiate(
        request["client_capabilities"],
        server_capabilities,
        request["policy"],
    )

    return {
        "server_capabilities": server_capabilities,
        **result,
    }


def execute_server_operation(algorithm, client_message):
    """Execute the server side of the selected cryptographic operation."""

    if algorithm == "X25519":
        client_public_key = decode_bytes(
            client_message["client_public_key"]
        )

        server_public_key, session_key = classical_server_respond(
            client_public_key
        )

        response = {
            "server_public_key": encode_bytes(server_public_key)
        }

    elif algorithm == "ML-KEM-768":
        provider = PQCProvider("ML-KEM-768")

        client_public_key = decode_bytes(
            client_message["client_public_key"]
        )

        result = provider.server_respond(client_public_key)

        session_key = result["shared_secret"]

        response = {
            "ciphertext": encode_bytes(result["ciphertext"])
        }

    elif algorithm == "HYBRID-X25519-MLKEM768":
        provider = HybridProvider()

        client_share = {
            "mlkem_public_key": decode_bytes(
                client_message["mlkem_public_key"]
            ),
            "x25519_public_key": decode_bytes(
                client_message["x25519_public_key"]
            ),
        }

        server_response, session_key = provider.server_respond(
            client_share
        )

        response = {
            "mlkem_ciphertext": encode_bytes(
                server_response["mlkem_ciphertext"]
            ),
            "x25519_public_key": encode_bytes(
                server_response["x25519_public_key"]
            ),
        }

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return response, session_key


def run_server_once(host, port, server_capabilities):
    """Accept one client, negotiate, execute and confirm key agreement."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(5)

        connection, _address = server.accept()

        with connection:
            connection.settimeout(5)

            # Use one binary file interface for both reading and writing.
            with connection.makefile("rwb") as file:

                # 1. Receive client capabilities and policy.
                # 1. Load the shared pre-shared key.
                psk = load_psk()

                # 2. Receive the client's authentication request.
                request = receive_message(file)

                # 3. Validate the client's nonce.
                try:
                    client_nonce = decode_bytes(request["client_nonce"])

                    if len(client_nonce) != 32:
                        raise ValueError("Invalid client nonce length")

                except (KeyError, ValueError):
                    failure = {
                        "status": "FAILED",
                        "reason": "Invalid client authentication request.",
                    }
                    send_message(file, failure)
                    return failure

                # 4. Generate a fresh server nonce.
                server_nonce = secrets.token_bytes(32)
                server_nonce_text = encode_bytes(server_nonce)

                # 5. Construct the shared authentication context.
                auth_context = {
                    "hello": request,
                    "server_nonce": server_nonce_text,
                }

                # 6. Generate the server authentication tag.
                server_tag = create_auth_tag(
                    psk,
                    "server-authentication",
                    auth_context,
                )

                # 7. Send the server's authentication challenge.
                send_message(
                    file,
                    {
                        "status": "AUTH_CHALLENGE",
                        "server_nonce": server_nonce_text,
                        "server_auth_tag": encode_bytes(server_tag),
                    },
                )

                # 8. Receive the client's proof of PSK possession.
                try:
                    client_auth = receive_message(file)

                    client_tag = decode_bytes(
                        client_auth["client_auth_tag"]
                    )

                    client_authenticated = verify_auth_tag(
                        psk,
                        "client-authentication",
                        auth_context,
                        client_tag,
                    )

                except (ConnectionError, KeyError, ValueError):
                    client_authenticated = False

                    # The client may have disconnected because it rejected
                    # the server's authentication response.
                    failure = {
                        "status": "FAILED",
                        "authentication": "FAILED",
                        "reason": "Client authentication did not complete.",
                    }

                    return failure

                # 9. Reject the connection if client authentication fails.
                if not client_authenticated:
                    failure = {
                        "status": "FAILED",
                        "reason": "Client authentication failed.",
                    }
                    send_message(file, failure)
                    return failure

                # 10. Authenticate successfully; now negotiate algorithms.
                negotiation = handle_request(
                    request,
                    server_capabilities,
                )

                send_message(file, negotiation)

                if negotiation["status"] != "SUCCESS":
                    return negotiation

                selected = negotiation["selected_algorithm"]

                # 4. Receive client public-key material.
                client_message = receive_message(file)

                # 5. Execute the selected server-side operation.
                server_response, session_key = execute_server_operation(
                    selected,
                    client_message,
                )

                # Create a fresh challenge for key confirmation.
                nonce = secrets.token_bytes(32)

                # Construct the exact response message sent to the client.
                server_response_message = {
                    "status": "SUCCESS",
                    "algorithm": selected,
                    **server_response,
                    "confirmation_nonce": encode_bytes(nonce),
                }

                # Send the cryptographic response and challenge.
                send_message(file, server_response_message)

                # 7. Calculate the same transcript hash as the client.
                transcript_hash = compute_transcript_hash(
                    request,
                    negotiation,
                    client_message,
                    server_response_message,
                )

                # 8. Receive the client's key-confirmation proof.
                finished = receive_message(file)

                expected_proof = hmac.new(
                    session_key,
                    b"client-finished:"
                    + nonce
                    + transcript_hash,
                    hashlib.sha256,
                ).digest()

                received_proof = decode_bytes(
                    finished["proof"]
                )

                
                
                confirmed = hmac.compare_digest(
                    expected_proof,
                    received_proof,
                )

                # Step 1: Reject an invalid client proof immediately.
                if not confirmed:
                    send_message(
                        file,
                        {
                            "status": "FAILED",
                            "key_confirmation": "FAILED",
                            "reason": "Client key confirmation failed.",
                        },
                    )

                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                    }

                # Step 2: Generate the server's proof only after
                # successfully verifying the client's proof.
                server_proof = hmac.new(
                    session_key,
                    b"server-finished:"
                    + nonce
                    + transcript_hash
                    + received_proof,
                    hashlib.sha256,
                ).digest()

                # Step 3: Send the server's proof to the client.
                send_message(
                    file,
                    {
                        "status": "SUCCESS",
                        "key_confirmation": "SUCCESS",
                        "server_proof": encode_bytes(server_proof),
                    },
                )

                # Step 4: Wait for the client's authenticated acknowledgement.
                try:
                    acknowledgement = receive_message(file)

                    received_ack = decode_bytes(
                        acknowledgement["client_ack"]
                    )

                except (ConnectionError, OSError, KeyError, ValueError):
                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                        "reason": "Client acknowledgement was not received or was invalid.",
                    }

                # Step 5: Independently verify the client's acknowledgement.
                expected_ack = hmac.new(
                    session_key,
                    b"client-ack:"
                    + nonce
                    + transcript_hash
                    + server_proof,
                    hashlib.sha256,
                ).digest()

                acknowledgement_verified = hmac.compare_digest(
                    expected_ack,
                    received_ack,
                )

                if not acknowledgement_verified:
                    send_message(
                        file,
                        {
                            "status": "FAILED",
                            "key_confirmation": "FAILED",
                            "reason": "Client acknowledgement verification failed.",
                        },
                    )

                    return {
                        **negotiation,
                        "execution": "SUCCESS",
                        "key_confirmation": "FAILED",
                    }

                # Step 6: Both parties have completed key confirmation.
                send_message(
                    file,
                    {
                        "status": "SUCCESS",
                        "key_confirmation": "SUCCESS",
                    },
                )

                return {
                    **negotiation,
                    "execution": "SUCCESS",
                    "key_confirmation": "SUCCESS",
                }
