import pytest

from core.negotiation import negotiate
from core.policy_engine import make_policy, PolicyError, validate_policy


def test_hybrid_selected_when_both_support_it():
    policy = make_policy("PQC_PREFERRED")
    result = negotiate(
        ["X25519", "ML-KEM-768", "HYBRID-X25519-MLKEM768"],
        ["X25519", "HYBRID-X25519-MLKEM768"],
        policy,
    )
    assert result["status"] == "SUCCESS"
    assert result["selected_algorithm"] == "HYBRID-X25519-MLKEM768"


def test_permitted_classical_fallback():
    policy = make_policy("PQC_PREFERRED")
    result = negotiate(
        ["X25519", "ML-KEM-768"],
        ["X25519"],
        policy,
    )
    assert result["status"] == "SUCCESS"
    assert result["selected_algorithm"] == "X25519"


def test_hybrid_required_rejects_classical_only_server():
    policy = make_policy("HYBRID_REQUIRED")
    result = negotiate(
        ["X25519", "HYBRID-X25519-MLKEM768"],
        ["X25519"],
        policy,
    )
    assert result["status"] == "REJECTED"
    assert result["selected_algorithm"] is None


def test_unknown_or_non_common_algorithm_not_selected():
    policy = make_policy("PQC_PREFERRED")
    result = negotiate(["UNKNOWN"], ["UNKNOWN"], policy)
    assert result["status"] == "REJECTED"


def test_classical_policy_rejects_pqc_allowlist():
    policy = {
        "mode": "CLASSICAL_ONLY",
        "allowed": ["X25519", "ML-KEM-768"],
        "preference": ["X25519"],
    }
    with pytest.raises(PolicyError):
        validate_policy(policy)



def test_classical_fallback_rejected_when_not_allowed():
    """Classical fallback must not happen when policy prohibits it."""

    policy = {
        "mode": "PQC_PREFERRED",
        "allowed": ["HYBRID-X25519-MLKEM768", "ML-KEM-768"],
        "preference": [
            "HYBRID-X25519-MLKEM768",
            "ML-KEM-768",
        ],
    }

    result = negotiate(
        ["X25519", "ML-KEM-768"],
        ["X25519"],
        policy,
    )

    assert result["status"] == "REJECTED"
    assert result["selected_algorithm"] is None


def test_algorithm_preference_is_respected():
    """The first eligible algorithm in policy preference must be selected."""

    policy = {
        "mode": "PQC_PREFERRED",
        "allowed": [
            "X25519",
            "ML-KEM-768",
            "HYBRID-X25519-MLKEM768",
        ],
        "preference": [
            "ML-KEM-768",
            "X25519",
            "HYBRID-X25519-MLKEM768",
        ],
    }

    result = negotiate(
        ["X25519", "ML-KEM-768", "HYBRID-X25519-MLKEM768"],
        ["X25519", "ML-KEM-768", "HYBRID-X25519-MLKEM768"],
        policy,
    )

    assert result["status"] == "SUCCESS"
    assert result["selected_algorithm"] == "ML-KEM-768"


def test_algorithm_not_in_policy_preference_is_not_selected():
    """A mutually supported algorithm must also be allowed by policy."""

    policy = {
        "mode": "PQC_PREFERRED",
        "allowed": ["ML-KEM-768"],
        "preference": ["ML-KEM-768"],
    }

    result = negotiate(
        ["X25519"],
        ["X25519"],
        policy,
    )

    assert result["status"] == "REJECTED"
    assert result["selected_algorithm"] is None


def test_negotiation_result_reports_eligible_algorithms():
    """Negotiation should expose which algorithms satisfy both capabilities and policy."""

    policy = make_policy("PQC_PREFERRED")

    result = negotiate(
        ["X25519", "ML-KEM-768", "HYBRID-X25519-MLKEM768"],
        ["X25519", "HYBRID-X25519-MLKEM768"],
        policy,
    )

    assert set(result["common_algorithms"]) == {
        "X25519",
        "HYBRID-X25519-MLKEM768",
    }

    assert set(result["eligible_algorithms"]) == {
        "X25519",
        "HYBRID-X25519-MLKEM768",
    }
