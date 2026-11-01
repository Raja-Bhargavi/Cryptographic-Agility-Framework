import oqs

algorithm = "ML-KEM-768"

print("Testing:", algorithm)

# Alice generates a public-private key pair
with oqs.KeyEncapsulation(algorithm) as alice:
    public_key = alice.generate_keypair()

    print("1. Alice generated her key pair")
    print("   Public key size:", len(public_key), "bytes")

    # Bob uses Alice's public key to generate a shared secret
    with oqs.KeyEncapsulation(algorithm) as bob:
        ciphertext, bob_secret = bob.encap_secret(public_key)

        print("2. Bob generated the ciphertext")
        print("   Ciphertext size:", len(ciphertext), "bytes")

    # Alice uses her private key to recover the shared secret
    alice_secret = alice.decap_secret(ciphertext)

    print("3. Alice decapsulated the ciphertext")

    # Compare both shared secrets
    print("\nShared secret verification:",
          alice_secret == bob_secret)

    print("Shared secret size:", len(alice_secret), "bytes")

    if alice_secret == bob_secret:
        print("\nSUCCESS: ML-KEM-768 key exchange completed!")
    else:
        print("\nFAILURE: Shared secrets do not match!")
        