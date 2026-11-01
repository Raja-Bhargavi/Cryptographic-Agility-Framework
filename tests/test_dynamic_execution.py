
from core.crypto_api import CryptoAPI
from core.policy_engine import make_policy


CLIENT = [
    "X25519",
    "ML-KEM-768",
    "HYBRID-X25519-MLKEM768",
]

SERVER = [
    "X25519",
    "ML-KEM-768",
    "HYBRID-X25519-MLKEM768",
]


def test_dynamic_hybrid_execution():
    api = CryptoAPI()

    result = api.establish_session(
        CLIENT,
        SERVER,
        make_policy("HYBRID_REQUIRED"),
    )

    assert result["status"] == "SUCCESS"
    assert result["selected_algorithm"] == "HYBRID-X25519-MLKEM768"
    assert result["execution"] == "SUCCESS"
    assert result["keys_match"] is True
    assert result["key_length"] == 32

    print("Selected:", result["selected_algorithm"])
    print("Execution:", result["execution"])
    print("Keys match:", result["keys_match"])


def test_dynamic_classical_execution():
    api = CryptoAPI()

    result = api.establish_session(
        CLIENT,
        SERVER,
        make_policy("CLASSICAL_ONLY"),
    )

    assert result["status"] == "SUCCESS"
    assert result["selected_algorithm"] == "X25519"
    assert result["keys_match"] is True

    print("Selected:", result["selected_algorithm"])
    print("Classical execution successful!")


def test_hybrid_required_rejects_classical_only_server():
    api = CryptoAPI()

    result = api.establish_session(
        CLIENT,
        ["X25519"],
        make_policy("HYBRID_REQUIRED"),
    )

    assert result["status"] == "REJECTED"
    assert result["negotiation"]["selected_algorithm"] is None

    print("Hybrid-required policy correctly rejected the server.")
