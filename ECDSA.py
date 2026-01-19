from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Bank server ECDSA key pair
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()


message = b"Welcome to Secure Bank"

signature = server_private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

false_signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

fake = server_private_key.verify(false_signature, message, ec.ECDSA(hashes.SHA256()))
real = server_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
if real != fake:
    print("Signature verified successfully.")
else:
    print("Signature verification failed.")