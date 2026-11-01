
from core.crypto_api import CryptoAPI


def test_hybrid_exchange_through_crypto_api():
    client_api = CryptoAPI()
    server_api = CryptoAPI()

    assert client_api.is_hybrid_supported()

    # Client starts the exchange.
    client_share, client_state = (
        client_api.start_hybrid_exchange()
    )

    # Server processes the client's public information.
    server_response, server_key = (
        server_api.respond_to_hybrid_exchange(client_share)
    )

    # Client completes the exchange.
    client_key = client_api.finish_hybrid_exchange(
        server_response,
        client_state,
    )

    assert client_key == server_key
    assert len(client_key) == 32

    print("Hybrid exchange through CryptoAPI successful!")
    print("Shared keys match:", client_key == server_key)
