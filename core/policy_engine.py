"""Security policy definitions and validation."""

VALID_MODES = {"CLASSICAL_ONLY", "PQC_PREFERRED", "HYBRID_REQUIRED"}


class PolicyError(ValueError):
    pass


def validate_policy(policy):
    required = {"mode", "allowed", "preference"}
    missing = required - set(policy)
    if missing:
        raise PolicyError(f"Missing policy fields: {sorted(missing)}")

    if policy["mode"] not in VALID_MODES:
        raise PolicyError(f"Unsupported policy mode: {policy['mode']}")

    if not isinstance(policy["allowed"], list) or not isinstance(policy["preference"], list):
        raise PolicyError("'allowed' and 'preference' must be lists")

    if len(policy["allowed"]) != len(set(policy["allowed"])):
        raise PolicyError("Duplicate algorithms in allowed list")

    if len(policy["preference"]) != len(set(policy["preference"])):
        raise PolicyError("Duplicate algorithms in preference list")

    if not set(policy["preference"]).issubset(set(policy["allowed"])):
        raise PolicyError("Every preferred algorithm must also be allowed")

    if policy["mode"] == "CLASSICAL_ONLY":
        if any(a.startswith("ML-KEM") or a.startswith("HYBRID") for a in policy["allowed"]):
            raise PolicyError("CLASSICAL_ONLY policy cannot allow PQC or hybrid mechanisms")

    if policy["mode"] == "HYBRID_REQUIRED":
        if not any(a.startswith("HYBRID") for a in policy["allowed"]):
            raise PolicyError("HYBRID_REQUIRED policy must allow a hybrid mechanism")

    return True


def make_policy(mode="PQC_PREFERRED"):
    """Return a fresh policy dictionary for the requested demonstration mode."""
    if mode == "CLASSICAL_ONLY":
        return {
            "mode": mode,
            "allowed": ["X25519"],
            "preference": ["X25519"],
        }
    if mode == "PQC_PREFERRED":
        return {
            "mode": mode,
            "allowed": ["X25519", "ML-KEM-768", "HYBRID-X25519-MLKEM768"],
            "preference": [
                "HYBRID-X25519-MLKEM768",
                "ML-KEM-768",
                "X25519",
            ],
        }
    if mode == "HYBRID_REQUIRED":
        return {
            "mode": mode,
            "allowed": ["HYBRID-X25519-MLKEM768"],
            "preference": ["HYBRID-X25519-MLKEM768"],
        }
    raise PolicyError(f"Unknown mode: {mode}")
