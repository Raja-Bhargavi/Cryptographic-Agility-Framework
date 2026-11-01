
"""Post-Quantum Cryptography provider using liboqs.

Implements ML-KEM-768 key generation, encapsulation and decapsulation.
"""

import secrets
import oqs


class PQCProvider:
    name = "liboqs PQC Provider"

    def __init__(self, algorithm="ML-KEM-768"):
        self.algorithm = algorithm

        if algorithm not in oqs.get_enabled_kem_mechanisms():
            raise ValueError(
                f"{algorithm} is not available in the installed liboqs build"
            )

        # Private-key contexts remain local to the client.
        self._key_contexts = {}

    def supported_algorithms(self):
        return ["ML-KEM-768"]

    def is_implemented(self, algorithm):
        return (
            algorithm == "ML-KEM-768"
            and algorithm in oqs.get_enabled_kem_mechanisms()
        )

    def generate_keypair(self):
        """Generate a key pair and retain its private-key context."""

        kem = oqs.KeyEncapsulation(self.algorithm)

        try:
            public_key = kem.generate_keypair()
        except Exception:
            kem.__exit__(None, None, None)
            raise

        key_handle = secrets.token_urlsafe(24)
        self._key_contexts[key_handle] = kem

        return public_key, key_handle

    def encapsulate(self, public_key):
        """Generate a ciphertext and shared secret using a public key."""

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, key_handle):
        """Recover the shared secret using the recipient's private key."""

        if key_handle not in self._key_contexts:
            raise ValueError("Invalid or expired private-key handle")

        kem = self._key_contexts[key_handle]
        return kem.decap_secret(ciphertext)

    def close_keypair(self, key_handle):
        """Release a private-key context when it is no longer needed."""

        kem = self._key_contexts.pop(key_handle, None)

        if kem is not None:
            kem.__exit__(None, None, None)

    # ---------------------------------------------------------
    # Peer-facing operations for client-server communication
    # ---------------------------------------------------------

    def client_start(self):
        """Client generates a key pair and returns its public key."""
        public_key, key_handle = self.generate_keypair()

        return {
            "public_key": public_key,
            "key_handle": key_handle,
        }

    def server_respond(self, client_public_key):
        """Server encapsulates a secret using the client's public key."""
        ciphertext, shared_secret = self.encapsulate(client_public_key)

        return {
            "ciphertext": ciphertext,
            "shared_secret": shared_secret,
        }

    def client_finish(self, ciphertext, key_handle):
        """Client decapsulates and releases its private-key context."""
        try:
            return self.decapsulate(ciphertext, key_handle)
        finally:
            self.close_keypair(key_handle)
