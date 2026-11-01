
from providers.hybrid import HybridProvider


def test_hybrid_key_establishment():
    # Simulate two independent parties.
    client = HybridProvider()
    server = HybridProvider()

    # Step 1: Client generates its public shares.
    client_share, client_state = client.client_start()

    assert len(client_share["mlkem_public_key"]) == 1184
    assert len(client_share["x25519_public_key"]) == 32

    # Step 2: Server processes the shares and responds.
    server_response, server_key = server.server_respond(client_share)

    assert len(server_response["mlkem_ciphertext"]) == 1088
    assert len(server_response["x25519_public_key"]) == 32

    # Step 3: Client completes the exchange.
    client_key = client.client_finish(
        server_response,
        client_state,
    )

    # Step 4: Verify both parties derived the same key.
    assert isinstance(client_key, bytes)
    assert isinstance(server_key, bytes)
    assert len(client_key) == 32
    assert len(server_key) == 32
    assert client_key == server_key

    print("Hybrid X25519 + ML-KEM-768 exchange successful!")
    print("Client key length:", len(client_key))
    print("Server key length:", len(server_key))
    print("Shared keys match:", client_key == server_key)
