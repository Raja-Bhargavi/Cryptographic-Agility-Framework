
"""Security policy definitions, validation and configuration loading."""

import json
from pathlib import Path


VALID_MODES = {
    "CLASSICAL_ONLY",
    "PQC_PREFERRED",
    "HYBRID_REQUIRED",
}

SUPPORTED_ALGORITHMS = {
    "X25519",
    "ML-KEM-768",
    "HYBRID-X25519-MLKEM768",
}


class PolicyError(ValueError):
    """Raised when a cryptographic policy is invalid."""


def validate_policy(policy):
    """Validate the structure and security rules of a policy."""

    if not isinstance(policy, dict):
        raise PolicyError("Policy must be a dictionary")

    required = {"mode", "allowed", "preference"}
    missing = required - set(policy)

    if missing:
        raise PolicyError(
            f"Missing policy fields: {sorted(missing)}"
        )

    # Validate the mode's type before checking its value.
    if not isinstance(policy["mode"], str):
        raise PolicyError("'mode' must be a string")

    if policy["mode"] not in VALID_MODES:
        raise PolicyError(
            f"Unsupported policy mode: {policy['mode']}"
        )

    if not isinstance(policy["allowed"], list):
        raise PolicyError("'allowed' must be a list")

    if not isinstance(policy["preference"], list):
        raise PolicyError("'preference' must be a list")

    algorithms = policy["allowed"] + policy["preference"]

    if not all(isinstance(a, str) for a in algorithms):
        raise PolicyError("Algorithm names must be strings")

    if len(policy["allowed"]) != len(set(policy["allowed"])):
        raise PolicyError("Duplicate algorithms in allowed list")

    if len(policy["preference"]) != len(set(policy["preference"])):
        raise PolicyError("Duplicate algorithms in preference list")

    unknown = set(policy["allowed"]) - SUPPORTED_ALGORITHMS

    if unknown:
        raise PolicyError(
            f"Unsupported algorithms in allowed list: {sorted(unknown)}"
        )

    if not set(policy["preference"]).issubset(
        set(policy["allowed"])
    ):
        raise PolicyError(
            "Every preferred algorithm must also be allowed"
        )

    if not policy["allowed"]:
        raise PolicyError("'allowed' cannot be empty")

    if not policy["preference"]:
        raise PolicyError("'preference' cannot be empty")

    # CLASSICAL_ONLY must not permit PQC or hybrid algorithms.
    if policy["mode"] == "CLASSICAL_ONLY":
        if any(
            a.startswith("ML-KEM") or a.startswith("HYBRID")
            for a in policy["allowed"]
        ):
            raise PolicyError(
                "CLASSICAL_ONLY policy cannot allow PQC or hybrid mechanisms"
            )

    # HYBRID_REQUIRED must not permit classical or standalone PQC fallback.
    if policy["mode"] == "HYBRID_REQUIRED":
        if not any(
            a.startswith("HYBRID")
            for a in policy["allowed"]
        ):
            raise PolicyError(
                "HYBRID_REQUIRED policy must allow a hybrid mechanism"
            )

        if any(
            not a.startswith("HYBRID")
            for a in policy["allowed"]
        ):
            raise PolicyError(
                "HYBRID_REQUIRED policy cannot allow classical or standalone PQC fallback"
            )

    return True


def make_policy(mode="PQC_PREFERRED"):
    """Return a fresh policy dictionary for a demonstration mode."""

    if mode == "CLASSICAL_ONLY":
        policy = {
            "mode": mode,
            "allowed": ["X25519"],
            "preference": ["X25519"],
        }

    elif mode == "PQC_PREFERRED":
        policy = {
            "mode": mode,
            "allowed": [
                "X25519",
                "ML-KEM-768",
                "HYBRID-X25519-MLKEM768",
            ],
            "preference": [
                "HYBRID-X25519-MLKEM768",
                "ML-KEM-768",
                "X25519",
            ],
        }

    elif mode == "HYBRID_REQUIRED":
        policy = {
            "mode": mode,
            "allowed": ["HYBRID-X25519-MLKEM768"],
            "preference": ["HYBRID-X25519-MLKEM768"],
        }

    else:
        raise PolicyError(f"Unknown mode: {mode}")

    validate_policy(policy)
    return policy


def load_policy(config_path):
    """Load and validate a policy from a JSON configuration file."""

    path = Path(config_path)

    try:
        with path.open("r", encoding="utf-8") as file:
            policy = json.load(file)

    except FileNotFoundError as exc:
        raise PolicyError(
            f"Policy configuration not found: {path}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"Invalid JSON policy configuration: {exc}"
        ) from exc

    except OSError as exc:
        raise PolicyError(
            f"Unable to read policy configuration: {exc}"
        ) from exc

    # Also verifies that the JSON root is a valid policy dictionary.
    validate_policy(policy)

    return policy
