# client.py
from ECDH import generate_keypair as ecdh_keys, derive_shared_secret, derive_aes_key
from ECDSA import generate_keypair as ecdsa_keys, sign, verify
from Server import BankServer

# --- Setup ---
server = BankServer()

# Client identity (for signing transactions)
client_ecdsa_private, client_ecdsa_public = ecdsa_keys()

# Client ECDH keys
client_ecdh_private, client_ecdh_public = ecdh_keys()

# --- Phase 1: Authenticate Server ---
message, signature, server_public_key = server.authenticate_to_client()
verify(server_public_key, message, signature)
print("[Client] Server authenticated successfully.")

# --- Phase 2: Establish Secure Session (ECDH) ---
client_shared_secret = derive_shared_secret(
    client_ecdh_private, server.ecdh_public
)
client_session_key = derive_aes_key(client_shared_secret)
server.establish_session(client_ecdh_public)

print("[Client] Secure session key established.")

# --- Phase 3: Secure Transaction ---
transaction = b"Transfer $1000 to Account 888888"
transaction_signature = sign(client_ecdsa_private, transaction)

server.verify_transaction(
    client_ecdsa_public,
    transaction,
    transaction_signature
)
