# Session Key establishment using ECDSA (Elliptic Curve Digital Signature Algorithm)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign(private_key, message: bytes):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify(public_key, message: bytes, signature: bytes):
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    return True


