
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



import main


def test_failed_runtime_reload_preserves_previous_policy(
    tmp_path, monkeypatch
):
    # Start with a valid active policy.
    previous_policy = valid_policy()
    policy_path = tmp_path / "crypto_policy.json"

    # Simulate the user pressing R.
    monkeypatch.setattr(
        "builtins.input",
        lambda _: "R"
    )

    # Simulate a failed policy reload.
    def failed_reload(path):
        raise PolicyError("Invalid policy configuration")

    monkeypatch.setattr(main, "load_policy", failed_reload)

    # Attempt to reload the policy.
    active_policy, active_path = main.prepare_policy_for_next_case(
        previous_policy,
        policy_path
    )

    # The previous policy must remain active.
    assert active_policy is previous_policy
    assert active_path == policy_path
    assert active_policy["mode"] == "PQC_PREFERRED"



def test_invalid_json_reload_preserves_previous_policy(
    tmp_path, monkeypatch
):
    import main

    # Create a valid policy that is already active.
    previous_policy = valid_policy()
    policy_path = tmp_path / "crypto_policy.json"

    # Write invalid JSON to the configuration file.
    policy_path.write_text(
        "{ invalid json",
        encoding="utf-8"
    )

    # Simulate pressing R to reload the configuration.
    monkeypatch.setattr(
        "builtins.input",
        lambda _: "R"
    )

    # Point the reload operation to the actual policy loader.
    monkeypatch.setattr(
        main,
        "load_policy",
        load_policy
    )

    active_policy, active_path = main.prepare_policy_for_next_case(
        previous_policy,
        policy_path
    )

    # Verify that the previous valid policy is preserved.
    assert active_policy is previous_policy
    assert active_path == policy_path
    assert active_policy["mode"] == "PQC_PREFERRED"
