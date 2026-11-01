
"""Application-facing facade for the crypto-agility framework."""

from core.algorithm_registry import get_algorithm
from core.negotiation import negotiate

from providers.classical import x25519_shared_secret
from providers.pqc import PQCProvider
from providers.hybrid import HybridProvider


class CryptoAPI:
    """Stable interface between applications and crypto providers."""

    def __init__(self):
        # Providers are initialized only when required.
        self._pqc_providers = {}
        self._hybrid_provider = HybridProvider()

    # -------------------------------------------------
    # 1. Algorithm negotiation
    # -------------------------------------------------

    def negotiate(self, client_capabilities, server_capabilities, policy):
        """Select an algorithm according to capabilities and policy."""
        return negotiate(
            client_capabilities,
            server_capabilities,
            policy
        )

    # -------------------------------------------------
    # 2. Algorithm information
    # -------------------------------------------------

    def algorithm_info(self, algorithm):
        """Retrieve algorithm metadata from the registry."""

        info = get_algorithm(algorithm)

        if info is None:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        return info

    # -------------------------------------------------
    # 3. Classical cryptography
    # -------------------------------------------------

    def establish_classical_secret(self):
        """Perform a local X25519 key-agreement self-test."""

        return x25519_shared_secret()

    # -------------------------------------------------
    # 4. PQC provider management
    # -------------------------------------------------

    def _get_pqc_provider(self, algorithm="ML-KEM-768"):
        """Get or initialize the requested PQC provider."""

        if algorithm not in self._pqc_providers:

            provider = PQCProvider(algorithm)

            if not provider.is_implemented(algorithm):
                raise ValueError(
                    f"PQC algorithm not implemented: {algorithm}"
                )

            self._pqc_providers[algorithm] = provider

        return self._pqc_providers[algorithm]

    # -------------------------------------------------
    # 5. PQC key generation
    # -------------------------------------------------

    def generate_pqc_keypair(self, algorithm="ML-KEM-768"):
        """Generate a PQC public key and local private-key handle."""

        provider = self._get_pqc_provider(algorithm)

        return provider.generate_keypair()

    # -------------------------------------------------
    # 6. PQC encapsulation
    # -------------------------------------------------

    def encapsulate_pqc_secret(
        self,
        public_key,
        algorithm="ML-KEM-768"
    ):
        """Generate a ciphertext and shared secret."""

        provider = self._get_pqc_provider(algorithm)

        return provider.encapsulate(public_key)

    # -------------------------------------------------
    # 7. PQC decapsulation
    # -------------------------------------------------

    def decapsulate_pqc_secret(
        self,
        ciphertext,
        key_handle,
        algorithm="ML-KEM-768"
    ):
        """Recover the shared secret using the private-key handle."""

        provider = self._get_pqc_provider(algorithm)

        return provider.decapsulate(ciphertext, key_handle)

    # -------------------------------------------------
    # 8. Release private-key context
    # -------------------------------------------------

    def close_pqc_keypair(self, key_handle, algorithm="ML-KEM-768"):
        """Release the locally stored private-key context."""

        provider = self._get_pqc_provider(algorithm)

        provider.close_keypair(key_handle)

    
    def is_hybrid_supported(self):
        return self._hybrid_provider.is_implemented(
        "HYBRID-X25519-MLKEM768"
    )

    def start_hybrid_exchange(self):
        return self._hybrid_provider.client_start()

    def respond_to_hybrid_exchange(self, client_share):
        return self._hybrid_provider.server_respond(client_share)

    def finish_hybrid_exchange(self, server_response, client_state):
        return self._hybrid_provider.client_finish(
            server_response,
            client_state,
        )

    
    def establish_session(
        self,
        client_capabilities,
        server_capabilities,
        policy,
    ):
        """Negotiate an algorithm and execute the selected key establishment."""

        # 1. Negotiate the algorithm.
        negotiation_result = self.negotiate(
            client_capabilities,
            server_capabilities,
            policy,
        )

        # 2. Stop if negotiation is rejected.
        if negotiation_result["status"] != "SUCCESS":
            return {
                "status": "REJECTED",
                "negotiation": negotiation_result,
                "reason": "No cryptographic operation was executed.",
            }

        selected = negotiation_result["selected_algorithm"]

        # 3. Verify that the selected algorithm is implemented.
        algorithm_info = self.algorithm_info(selected)

        if algorithm_info["implementation"] != "implemented":
            return {
                "status": "EXECUTION_REJECTED",
                "negotiation": negotiation_result,
                "reason": f"{selected} is not implemented.",
            }

        # 4. Execute the selected cryptographic mechanism.
        if selected == "X25519":
            result = self.establish_classical_secret()

            client_key = result["client_key"]
            server_key = result["server_key"]

        elif selected == "ML-KEM-768":
            public_key, key_handle = self.generate_pqc_keypair()

            try:
                ciphertext, server_key = (
                    self.encapsulate_pqc_secret(public_key)
                )

                client_key = self.decapsulate_pqc_secret(
                    ciphertext,
                    key_handle,
                )
            finally:
                self.close_pqc_keypair(key_handle)

        elif selected == "HYBRID-X25519-MLKEM768":
            client_share, client_state = self.start_hybrid_exchange()

            server_response, server_key = (
                self.respond_to_hybrid_exchange(client_share)
            )

            client_key = self.finish_hybrid_exchange(
                server_response,
                client_state,
            )

        else:
            return {
                "status": "EXECUTION_REJECTED",
                "negotiation": negotiation_result,
                "reason": f"No execution handler exists for {selected}.",
            }

        # 5. Verify that both parties derived the same key.
        if client_key != server_key:
            return {
                "status": "EXECUTION_FAILED",
                "negotiation": negotiation_result,
                "reason": "Client and server derived different keys.",
            }

        # 6. Return the session establishment result.
        return {
            "status": "SUCCESS",
            "selected_algorithm": selected,
            "negotiation": negotiation_result,
            "execution": "SUCCESS",
            "key_length": len(client_key),
            "keys_match": True,
            "session_key": client_key,
        }
