from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Client side
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Server side
server_private_key_ecdh = ec.generate_private_key(ec.SECP256R1())
server_public_key_ecdh = server_private_key_ecdh.public_key()

# Client computes shared secret
client_shared_secret = client_private_key.exchange(
    ec.ECDH(),
    server_public_key_ecdh
)

# Server computes shared secret
server_shared_secret = server_private_key_ecdh.exchange(
    ec.ECDH(),
    client_public_key
)

assert client_shared_secret == server_shared_secret
print("Shared secret established.")
