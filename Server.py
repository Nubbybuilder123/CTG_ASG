# server.py
from ECDH import generate_keypair as ecdh_keys, derive_shared_secret, derive_aes_key
from ECDSA import generate_keypair as ecdsa_keys, sign, verify
import time

class BankServer:
    def __init__(self):
        # Long-term identity key (like certificate key)
        self.ecdsa_private, self.ecdsa_public = ecdsa_keys()

        # Ephemeral session keys
        self.ecdh_private, self.ecdh_public = ecdh_keys()

    def authenticate_to_client(self):
        message = b"Bank Server Authentication"
        signature = sign(self.ecdsa_private, message)
        return message, signature, self.ecdsa_public

    def establish_session(self, client_ecdh_public):
        shared_secret = derive_shared_secret(
            self.ecdh_private, client_ecdh_public
        )
        self.session_key = derive_aes_key(shared_secret)
        time.sleep(2)
        print("[Server] Secure session key established.")


    def verify_transaction(self, client_public_key, transaction, signature):
        verify(client_public_key, transaction, signature)
        time.sleep(2)
        print("[Server] Transaction verified and accepted.")
