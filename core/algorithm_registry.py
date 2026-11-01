
"""Central catalogue of mechanisms known to the prototype.

The registry distinguishes key establishment, key encapsulation,
signatures and symmetric encryption.

Implementation status reflects the current prototype, not
production security certification.
"""

ALGORITHM_REGISTRY = {
    "X25519": {
        "family": "classical",
        "purpose": "key_establishment",
        "provider": "cryptography",
        "implementation": "implemented",
        "status": "working_prototype",
    },
    "ML-KEM-768": {
        "family": "pqc",
        "purpose": "key_encapsulation",
        "provider": "liboqs",
        "implementation": "implemented",
        "status": "working_prototype",
    },
    "HYBRID-X25519-MLKEM768": {
        "family": "hybrid",
        "purpose": "hybrid_key_establishment",
        "provider": "cryptography + liboqs",
        "implementation": "implemented",
        "status": "working_prototype",
    },
    "AES-256-GCM": {
        "family": "classical_symmetric",
        "purpose": "authenticated_encryption",
        "provider": "cryptography",
        "implementation": "not_implemented",
        "status": "catalogued",
    },
    "ECDSA-P256": {
        "family": "classical",
        "purpose": "digital_signature",
        "provider": "cryptography",
        "implementation": "not_implemented",
        "status": "catalogued",
    },
    "ML-DSA-65": {
        "family": "pqc",
        "purpose": "digital_signature",
        "provider": "liboqs",
        "implementation": "not_implemented",
        "status": "catalogued",
    },
}


def get_algorithm(name):
    """Return a copy of metadata, or None for an unknown identifier."""
    item = ALGORITHM_REGISTRY.get(name)
    return dict(item) if item else None


def list_algorithms():
    """Return all registered identifiers."""
    return sorted(ALGORITHM_REGISTRY.keys())
