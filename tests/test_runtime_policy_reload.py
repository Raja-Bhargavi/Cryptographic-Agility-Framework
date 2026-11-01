
import json
import pytest

from core.policy_engine import load_policy, PolicyError


def write_policy(tmp_path, policy):
    path = tmp_path / "test_policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def valid_policy():
    return {
        "mode": "PQC_PREFERRED",
        "allowed": [
            "X25519",
            "ML-KEM-768",
            "HYBRID-X25519-MLKEM768"
        ],
        "preference": [
            "HYBRID-X25519-MLKEM768",
            "ML-KEM-768",
            "X25519"
        ]
    }


def test_load_valid_policy(tmp_path):
    path = write_policy(tmp_path, valid_policy())

    policy = load_policy(path)

    assert policy["mode"] == "PQC_PREFERRED"
    assert "X25519" in policy["allowed"]


def test_reject_invalid_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_reject_unsupported_algorithm(tmp_path):
    policy = valid_policy()
    policy["allowed"].append("UNKNOWN-ALGORITHM")

    path = write_policy(tmp_path, policy)

    with pytest.raises(PolicyError):
        load_policy(path)


def test_reject_missing_policy_field(tmp_path):
    policy = valid_policy()
    del policy["preference"]

    path = write_policy(tmp_path, policy)

    with pytest.raises(PolicyError):
        load_policy(path)


def test_reject_wrong_mode_type(tmp_path):
    policy = valid_policy()
    policy["mode"] = 123

    path = write_policy(tmp_path, policy)

    with pytest.raises(PolicyError):
        load_policy(path)


def test_reject_missing_configuration_file(tmp_path):
    path = tmp_path / "does_not_exist.json"

    with pytest.raises(PolicyError):
        load_policy(path)
