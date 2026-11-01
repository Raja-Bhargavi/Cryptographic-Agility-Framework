
from core.crypto_api import CryptoAPI


def test_crypto_api_pqc_operations():

    api = CryptoAPI()

    # Alice generates a key pair.
    public_key, key_handle = api.generate_pqc_keypair()

    assert len(public_key) == 1184

    # Bob encapsulates using Alice's public key.
    ciphertext, bob_secret = api.encapsulate_pqc_secret(
        public_key
    )

    assert len(ciphertext) == 1088

    # Alice decapsulates.
    alice_secret = api.decapsulate_pqc_secret(
        ciphertext,
        key_handle
    )

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32

    api.close_pqc_keypair(key_handle)

    print("CryptoAPI ML-KEM-768 integration successful!")



def test_crypto_api_classical_operation():

    api = CryptoAPI()

    result = api.establish_classical_secret()

    # The classical provider returns a dictionary.
    assert isinstance(result, dict)

    # Verify that both parties generated the same secret.
    assert result["match"] is True

    assert isinstance(result["client_key"], bytes)
    assert isinstance(result["server_key"], bytes)

    assert result["client_key"] == result["server_key"]

    assert len(result["client_key"]) == 32

    assert result["algorithm"] == "X25519 + HKDF-SHA256"

    print("CryptoAPI X25519 integration successful!")

