
from providers.pqc import PQCProvider


def test_ml_kem_768_provider():

    provider = PQCProvider()

    print("\nProvider:", provider.name)
    print("Supported algorithms:", provider.supported_algorithms())

    # Alice generates her key pair.
    public_key, key_handle = provider.generate_keypair()

    print("\n1. Alice generated her key pair.")
    print("Public key size:", len(public_key))

    # Bob encapsulates using Alice's public key.
    ciphertext, bob_secret = provider.encapsulate(public_key)

    print("\n2. Bob performed encapsulation.")
    print("Ciphertext size:", len(ciphertext))

    # Alice decapsulates using her private-key context.
    alice_secret = provider.decapsulate(ciphertext, key_handle)

    print("\n3. Alice performed decapsulation.")

    print("\nShared secrets match:", alice_secret == bob_secret)
    print("Shared secret size:", len(alice_secret))

    assert alice_secret == bob_secret

    provider.close_keypair(key_handle)

    print("\nSUCCESS: PQC provider is working!")


if __name__ == "__main__":
    test_ml_kem_768_provider()
