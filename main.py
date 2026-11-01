
"""Run the TCP cryptographic-agility demonstration."""

import socket
import threading
import time

from client.client import request_negotiation
from core.policy_engine import make_policy
from server.server import run_server_once


HOST = "127.0.0.1"


def free_port():
    """Find an available localhost TCP port."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def run_case(title, client_caps, server_caps, policy_mode):
    """Run one client-server negotiation and cryptographic exchange."""

    port = free_port()
    result_box = {}
    error_box = {}

    def server_task():
        try:
            result_box["server"] = run_server_once(
                HOST,
                port,
                server_caps,
            )
        except Exception as exc:
            error_box["server"] = exc

    thread = threading.Thread(target=server_task, daemon=True)
    thread.start()

    # Give the server time to bind and listen.
    time.sleep(0.15)

    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)

    print("Client capabilities :", ", ".join(client_caps))
    print("Server capabilities :", ", ".join(server_caps))
    print("Security policy     :", policy_mode)

    try:
        response = request_negotiation(
            HOST,
            port,
            client_caps,
            make_policy(policy_mode),
        )
    except Exception as exc:
        print("Client error        :", exc)
        thread.join(timeout=5)
        if "server" in error_box:
            print("Server error        :", error_box["server"])
        return

    thread.join(timeout=5)

    print("Common algorithms   :",
          ", ".join(response.get("common_algorithms", [])) or "None")

    print("Selected algorithm  :",
          response.get("selected_algorithm") or "None")

    print("Negotiation status  :", response.get("status"))

    if response.get("status") == "SUCCESS":
        print("Execution status    :", response.get("execution"))
        print("Key confirmation    :", response.get("key_confirmation"))
        print("Session key length  :", response.get("key_length"), "bytes")

    print("Decision reason     :", response.get("reason", "No algorithm selected"))

    if "server" in error_box:
        print("Server error        :", error_box["server"])

    if "server" in result_box:
        print("Server result       :", result_box["server"].get("status"))
        print("Server confirmation :",
              result_box["server"].get("key_confirmation", "Not performed"))


def main():
    print("=" * 72)
    print("CRYPTOGRAPHIC AGILITY FRAMEWORK")
    print("TCP-BASED DYNAMIC NEGOTIATION AND EXECUTION PROTOTYPE")
    print("=" * 72)

    # Scenario 1: Hybrid is preferred and supported by both peers.
    run_case(
        "SCENARIO 1: HYBRID EXECUTION",
        [
            "X25519",
            "ML-KEM-768",
            "HYBRID-X25519-MLKEM768",
        ],
        [
            "X25519",
            "HYBRID-X25519-MLKEM768",
        ],
        "PQC_PREFERRED",
    )

    # Scenario 2: Both peers support ML-KEM, but not hybrid.
    run_case(
        "SCENARIO 2: POST-QUANTUM ML-KEM EXECUTION",
        [
            "X25519",
            "ML-KEM-768",
        ],
        [
            "ML-KEM-768",
        ],
        "PQC_PREFERRED",
    )

    # Scenario 3: PQC is preferred, but the server supports only X25519.
    run_case(
        "SCENARIO 3: CLASSICAL FALLBACK",
        [
            "X25519",
            "ML-KEM-768",
        ],
        [
            "X25519",
        ],
        "PQC_PREFERRED",
    )

    # Scenario 4: Hybrid is mandatory but the server does not support it.
    run_case(
        "SCENARIO 4: HYBRID REQUIRED — NEGOTIATION REJECTION",
        [
            "X25519",
            "HYBRID-X25519-MLKEM768",
        ],
        [
            "X25519",
        ],
        "HYBRID_REQUIRED",
    )

    print("\n" + "=" * 72)
    print("DEMONSTRATION COMPLETED")
    print("=" * 72)


if __name__ == "__main__":
    main()
