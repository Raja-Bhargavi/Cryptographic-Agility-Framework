"""Capability negotiation with explicit policy enforcement."""

from core.policy_engine import validate_policy


def negotiate(client_capabilities, server_capabilities, policy):
    """Select the first policy-preferred mechanism supported by both peers.

    This is a deterministic selection demonstration, not a secure wire protocol.
    Authentication and transcript binding are future security requirements.
    """
    validate_policy(policy)

    client = set(client_capabilities)
    server = set(server_capabilities)
    allowed = set(policy["allowed"])
    common = client & server
    eligible = common & allowed

    for algorithm in policy["preference"]:
        if algorithm in eligible:
            return {
                "status": "SUCCESS",
                "selected_algorithm": algorithm,
                "common_algorithms": sorted(common),
                "eligible_algorithms": sorted(eligible),
                "reason": "Selected highest-priority mutually supported algorithm permitted by policy.",
            }

    return {
        "status": "REJECTED",
        "selected_algorithm": None,
        "common_algorithms": sorted(common),
        "eligible_algorithms": sorted(eligible),
        "reason": "No mutually supported algorithm satisfies the active security policy.",
    }
