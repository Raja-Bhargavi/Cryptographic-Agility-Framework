
"""Hybrid key establishment using X25519 and ML-KEM-768.

This is an educational application-level prototype.
It is not a TLS 1.3 implementation.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from providers.pqc import PQCProvider


@dataclass
class HybridClientState:
    """Temporary client-side private state for one exchange."""
    x25519_private_key: object
    pqc_key_handle: str


class HybridProvider:
    name = "X25519 + ML-KEM-768 Hybrid Provider"

    def __init__(self):
        self.pqc = PQCProvider("ML-KEM-768")

    def supported_algorithms(self):
        return ["HYBRID-X25519-MLKEM768"]

    def is_implemented(self, algorithm):
        return (
            algorithm == "HYBRID-X25519-MLKEM768"
            and self.pqc.is_implemented("ML-KEM-768")
        )

    @staticmethod
    def _raw_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _derive_application_key(mlkem_secret, x25519_secret):
        """Derive application key material from both component secrets."""
        combined_secret = mlkem_secret + x25519_secret

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"crypto-agility-hybrid-x25519-mlkem768-v1",
        ).derive(combined_secret)

    def client_start(self):
        """Generate client public shares and retain private state."""

        # Generate the ML-KEM key pair.
        mlkem_public, key_handle = self.pqc.generate_keypair()

        # Generate the ephemeral X25519 key pair.
        x_private = x25519.X25519PrivateKey.generate()
        x_public = self._raw_public_key(x_private.public_key())

        client_state = HybridClientState(
            x25519_private_key=x_private,
            pqc_key_handle=key_handle,
        )

        # These public values are sent to the server.
        client_share = {
            "mlkem_public_key": mlkem_public,
            "x25519_public_key": x_public,
        }

        return client_share, client_state

    def server_respond(self, client_share):
        """Process client shares and produce the server response."""

        # Validate the public key lengths for this prototype.
        if len(client_share["mlkem_public_key"]) != 1184:
            raise ValueError("Invalid ML-KEM-768 public key length")

        if len(client_share["x25519_public_key"]) != 32:
            raise ValueError("Invalid X25519 public key length")

        # ML-KEM: encapsulate to the client's public key.
        ciphertext, mlkem_secret = self.pqc.encapsulate(
            client_share["mlkem_public_key"]
        )

        # X25519: generate server ephemeral key and exchange.
        server_private = x25519.X25519PrivateKey.generate()

        client_x_public = x25519.X25519PublicKey.from_public_bytes(
            client_share["x25519_public_key"]
        )

        x25519_secret = server_private.exchange(client_x_public)

        server_x_public = self._raw_public_key(
            server_private.public_key()
        )

        # Both component secrets are combined in the specified order.
        application_key = self._derive_application_key(
            mlkem_secret,
            x25519_secret,
        )

        server_response = {
            "mlkem_ciphertext": ciphertext,
            "x25519_public_key": server_x_public,
        }

        return server_response, application_key

    def client_finish(self, server_response, client_state):
        """Complete the exchange and derive the client's application key."""

        try:
            # Recover the ML-KEM shared secret.
            mlkem_secret = self.pqc.decapsulate(
                server_response["mlkem_ciphertext"],
                client_state.pqc_key_handle,
            )

            # Recover the X25519 shared secret.
            server_x_public = x25519.X25519PublicKey.from_public_bytes(
                server_response["x25519_public_key"]
            )

            x25519_secret = client_state.x25519_private_key.exchange(
                server_x_public
            )

            # Derive the same application key as the server.
            return self._derive_application_key(
                mlkem_secret,
                x25519_secret,
            )

        finally:
            # This private-key handle must not be reused.
            self.pqc.close_keypair(client_state.pqc_key_handle)
