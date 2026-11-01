
"""Capability negotiation with explicit policy enforcement and audit details."""

from core.policy_engine import validate_policy


def negotiate(client_capabilities, server_capabilities, policy):
    """Select an algorithm and explain every policy decision."""

    validate_policy(policy)

    client = set(client_capabilities)
    server = set(server_capabilities)
    allowed = set(policy["allowed"])

    common = client & server
    eligible = common & allowed

    # Preserve policy preference order in the audit.
    # Include preferred, allowed and mutually supported algorithms.
    # This ensures that policy-forbidden common algorithms are also audited.
    candidates = list(dict.fromkeys(
        policy["preference"]
        + sorted(allowed)
        + sorted(common)
    ))
    audit = []

    for algorithm in candidates:
        if algorithm not in common:
            reason = "Not supported by both peers."
            decision = "REJECTED"

        elif algorithm not in allowed:
            reason = "Not permitted by the active security policy."
            decision = "REJECTED"

        else:
            reason = "Mutually supported and permitted by policy."
            decision = "ELIGIBLE"

        audit.append({
            "algorithm": algorithm,
            "decision": decision,
            "reason": reason,
        })

    # Select the first eligible algorithm in policy preference order.
    selected_algorithm = None

    for algorithm in policy["preference"]:
        if algorithm in eligible:
            selected_algorithm = algorithm
            break

    if selected_algorithm is not None:
        status = "SUCCESS"
        reason = (
            "Selected highest-priority mutually supported algorithm "
            "permitted by policy."
        )

        # Mark eligible but lower-priority candidates.
        for entry in audit:
            if (
                entry["decision"] == "ELIGIBLE"
                and entry["algorithm"] != selected_algorithm
            ):
                entry["decision"] = "NOT_SELECTED"
                entry["reason"] = (
                    "Eligible, but a higher-priority algorithm was selected."
                )

    else:
        status = "REJECTED"
        reason = (
            "No mutually supported algorithm satisfies the active security policy."
        )

    return {
        "status": status,
        "selected_algorithm": selected_algorithm,
        "common_algorithms": sorted(common),
        "eligible_algorithms": sorted(eligible),
        "reason": reason,
        "audit": audit,
    }
