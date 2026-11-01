
"""Run the TCP cryptographic-agility demonstration."""

import socket
import threading
import time
from pathlib import Path

from client.client import request_negotiation
from core.policy_engine import load_policy
from server.server import run_server_once
from core.audit_logger import log_negotiation


HOST = "127.0.0.1"
CONFIG_DIR = Path(__file__).resolve().parent / "config"

POLICY_FILES = {
    "1": CONFIG_DIR / "crypto_policy.json",
    "2": CONFIG_DIR / "classical_only_policy.json",
    "3": CONFIG_DIR / "hybrid_required_policy.json",
}


def free_port():
    """Find an available localhost TCP port."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def run_case(title, client_caps, server_caps, policy):
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

    time.sleep(0.15)

    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)

    print("Client capabilities :", ", ".join(client_caps))
    print("Server capabilities :", ", ".join(server_caps))
    print("Security policy     :", policy["mode"])
    print("Allowed algorithms  :", ", ".join(policy["allowed"]))
    print("Algorithm preference:", ", ".join(policy["preference"]))

    try:
        response = request_negotiation(
            HOST,
            port,
            client_caps,
            policy,
        )
    except Exception as exc:
        print("Client error        :", exc)
        thread.join(timeout=5)

        if "server" in error_box:
            print("Server error        :", error_box["server"])

        return

    thread.join(timeout=5)

    # Save the negotiation decision and audit details.
    audit_record = {
        "scenario": title,
        "client_capabilities": client_caps,
        "server_capabilities": server_caps,
        "policy": policy,
        "negotiation_status": response.get("status"),
        "selected_algorithm": response.get("selected_algorithm"),
        "common_algorithms": response.get("common_algorithms", []),
        "eligible_algorithms": response.get("eligible_algorithms", []),
        "decision_reason": response.get("reason"),
        "audit": response.get("audit", []),
        "execution_status": response.get("execution", "NOT_EXECUTED"),
        "key_confirmation": response.get(
            "key_confirmation", "NOT_PERFORMED"
        ),
    }

    log_path = log_negotiation(audit_record)
    print("Audit saved to      :", log_path)

    print(
        "Common algorithms   :",
        ", ".join(response.get("common_algorithms", [])) or "None",
    )

    print(
        "Selected algorithm  :",
        response.get("selected_algorithm") or "None",
    )

    print("Negotiation status  :", response.get("status"))

    if response.get("status") == "SUCCESS":
        print("Execution status    :", response.get("execution"))
        print("Key confirmation    :", response.get("key_confirmation"))
        print("Session key length  :", response.get("key_length"), "bytes")

    print("Decision reason     :", response.get("reason", "No algorithm selected"))

    print("\nNEGOTIATION AUDIT")
    print("-" * 72)

    for entry in response.get("audit", []):
        print(
            f"{entry['algorithm']:<30} "
            f"{entry['decision']:<12} "
            f"{entry['reason']}"
        )

    if "server" in error_box:
        print("Server error        :", error_box["server"])

    if "server" in result_box:
        print("Server result       :", result_box["server"].get("status"))
        print(
            "Server confirmation :",
            result_box["server"].get("key_confirmation", "Not performed"),
        )


def select_runtime_policy():
    """Select and load a policy from its JSON configuration file."""

    print("\nSELECT SECURITY POLICY")
    print("-" * 72)
    print("1. PQC_PREFERRED")
    print("2. CLASSICAL_ONLY")
    print("3. HYBRID_REQUIRED")

    while True:
        choice = input("\nEnter your choice (1/2/3): ").strip()

        if choice not in POLICY_FILES:
            print("Invalid choice. Please enter 1, 2, or 3.")
            continue

        policy_path = POLICY_FILES[choice]

        try:
            policy = load_policy(policy_path)

            print("\nSelected policy:", policy["mode"])
            print("Configuration file:", policy_path.name)
            print("Policy loaded and validated successfully.")

            return policy, policy_path

        except Exception as exc:
            print("Unable to load policy:", exc)
            raise


def prepare_policy_for_next_case(current_policy, current_path):
    """
    Allow the user to keep, reload, or switch policy
    before the next TCP negotiation.
    """

    print("\n" + "-" * 72)
    print("RUNTIME POLICY CONTROL")
    print("-" * 72)
    print("Current policy:", current_policy["mode"])
    print("Current configuration:", current_path.name)
    print("\nPress Enter - Continue with current policy")
    print("R            - Reload current JSON configuration")
    print("S            - Select a different security policy")

    choice = input("\nYour choice: ").strip().upper()

    if choice == "":
        print("\nKeeping current policy:", current_policy["mode"])
        return current_policy, current_path

    if choice == "R":
        try:
            updated_policy = load_policy(current_path)

            print("\nPolicy reloaded successfully.")
            print("Active policy:", updated_policy["mode"])
            print("Updated preference:", updated_policy["preference"])

            return updated_policy, current_path

        except Exception as exc:
            print("\nPolicy reload failed:", exc)
            print("Keeping the previously loaded policy.")

            return current_policy, current_path

    if choice == "S":
        return select_runtime_policy()

    print("\nInvalid choice. Keeping the current policy.")
    return current_policy, current_path


def main():
    print("=" * 72)
    print("CRYPTOGRAPHIC AGILITY FRAMEWORK")
    print("TCP-BASED DYNAMIC NEGOTIATION AND EXECUTION PROTOTYPE")
    print("=" * 72)

    # Load the initial policy.
    runtime_policy, runtime_policy_path = select_runtime_policy()

    # Scenario 1: Both peers support hybrid.
    run_case(
        "SCENARIO 1: POLICY-DRIVEN NEGOTIATION",
        [
            "X25519",
            "ML-KEM-768",
            "HYBRID-X25519-MLKEM768",
        ],
        [
            "X25519",
            "HYBRID-X25519-MLKEM768",
        ],
        runtime_policy,
    )

    # Give the user a chance to update the policy before Scenario 2.
    runtime_policy, runtime_policy_path = prepare_policy_for_next_case(
        runtime_policy,
        runtime_policy_path,
    )

    # Scenario 2: Both peers support X25519 and ML-KEM.
    # The policy preference determines which algorithm is selected.
    run_case(
        "SCENARIO 2: DYNAMIC PREFERENCE — BEFORE RELOAD",
        [
            "X25519",
            "ML-KEM-768",
        ],
        [
            "X25519",
            "ML-KEM-768",
        ],
        runtime_policy,
    )

    # Give the user a chance to update the policy before Scenario 3.
    runtime_policy, runtime_policy_path = prepare_policy_for_next_case(
        runtime_policy,
        runtime_policy_path,
    )

    # Scenario 2: Both peers support X25519 and ML-KEM.
    # The policy preference determines which algorithm is selected.
    run_case(
        "SCENARIO 2: DYNAMIC PREFERENCE — BEFORE RELOAD",
        [
            "X25519",
            "ML-KEM-768",
        ],
        [
            "X25519",
            "ML-KEM-768",
        ],
        runtime_policy,
    )

    # Scenario 3: Server supports only classical X25519.
    run_case(
        "SCENARIO 3: CLASSICAL COMPATIBILITY TEST",
        [
            "X25519",
            "ML-KEM-768",
        ],
        [
            "X25519",
        ],
        runtime_policy,
    )

    # Scenario 4 always tests the mandatory-hybrid policy.
    hybrid_required_policy = load_policy(
        CONFIG_DIR / "hybrid_required_policy.json"
    )

    run_case(
        "SCENARIO 4: HYBRID REQUIRED — NEGOTIATION REJECTION",
        [
            "X25519",
            "HYBRID-X25519-MLKEM768",
        ],
        [
            "X25519",
        ],
        hybrid_required_policy,
    )

    print("\n" + "=" * 72)
    print("DEMONSTRATION COMPLETED")
    print("=" * 72)


if __name__ == "__main__":
    main()
