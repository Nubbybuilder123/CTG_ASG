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
        print(f"Generating Shared Secret(Server).....")
        shared_secret = derive_shared_secret(
            self.ecdh_private, client_ecdh_public
        )
        time.sleep(2)
        print(f"Server Shared Secret: {shared_secret}\n")

        print(f"Generating Server Session Key.....")
        self.session_key = derive_aes_key(shared_secret)
        print(f"Server Session Key: {self.session_key}\n")
        time.sleep(2)
        print("[Server] Secure session key established.")


    def verify_transaction(self, client_public_key, transaction, signature):
        try:
            verify(client_public_key, transaction, signature)
            print("[Server] Transaction verified and accepted.")
            return True
        except Exception:
            print("[Server] Invalid signature! Transaction rejected.")
            return False
        
