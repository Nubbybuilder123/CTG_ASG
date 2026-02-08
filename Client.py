# client.py
from ECDH import generate_keypair as ecdh_keys, derive_shared_secret, derive_aes_key
from ECDSA import generate_keypair as ecdsa_keys, sign, verify
from Server import BankServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time



def encrypt_payload(aes_key, message, signature):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    payload = message + b"||" + signature
    ciphertext = aesgcm.encrypt(nonce, payload, None)

    return nonce, ciphertext

def decrypt_payload(aes_key, nonce, ciphertext):
    aesgcm = AESGCM(aes_key)
    payload = aesgcm.decrypt(nonce, ciphertext, None)

    message, signature = payload.split(b"||")
    return message, signature


# setup
server = BankServer()
ACCOUNT_FILE = "CTG_ASG/account.txt"

def load_account():
    with open(ACCOUNT_FILE, "r") as f:
        lines = f.readlines()

    account = {}
    for line in lines:
        key, value = line.strip().split("=")
        if key =="BALANCE":
            account[key] = int(value)
        else:
            account[key] = value

    return account

def save_account(account):
    with open(ACCOUNT_FILE, "w") as f:
        f.write(f"ACCOUNT_ID={account['ACCOUNT_ID']}\n")
        f.write(f"BALANCE={account['BALANCE']}\n")


# Client identity keys (ECDSA)
client_ecdsa_private, client_ecdsa_public = ecdsa_keys()

# Client ECDH keys
client_ecdh_private, client_ecdh_public = ecdh_keys()

# Phase 1: Authenticate Server
message, signature, server_public_key = server.authenticate_to_client()
print(f"Authenticating Server to Client.....")
print(f"Server Public Key: {server_public_key}")
print(f"Message: {message}")
print(f"Signature: {signature}")
verify(server_public_key, message, signature)
time.sleep(2)
print("[Client] Bank server authenticated.\n")



# Phase 2: Secure Session
print(f"Generating Shared Secret(Client).....")
time.sleep(2)
client_shared_secret = derive_shared_secret(
    client_ecdh_private, server.ecdh_public
)
print(f"Client Shared Secret: {client_shared_secret}\n")
print(f"Generating Client Session Key....")
time.sleep(2)
client_session_key = derive_aes_key(client_shared_secret)
print(f"Client Session Key: {client_session_key}\n")
server.establish_session(client_ecdh_public)




# CLI Banking Menu
account = load_account()

while True:
    print("---- Internet Banking CLI ----")
    print("1. View Account Balance")
    print("2. Deposit Money")
    print("3. Withdraw Money")
    print("4. Exit")

    choice = input("Choose an option: ")

    if choice == "1":
        print(f"\nAccount ID: {account['ACCOUNT_ID']}")
        print(f"Balance: ${account['BALANCE']}\n")

    elif choice == "2":
        amount = int(input("Enter amount to deposit($): "))
        transaction = f"DEPOSIT:{amount}".encode()

        signature = sign(client_ecdsa_private, transaction)
        print(f"\nClient transaction text after encode: {transaction}") 
        print(f"Client signature after sign: {signature}\n")
        print("Encrypting Signature and Transaction.....\n")
        time.sleep(2)
        nonce , aesEncryptedPayload = encrypt_payload(client_session_key, transaction, signature)
        print(f"Client AES encrypted payload: {aesEncryptedPayload}\n")

        print(f"Sending encrypted payload to server for verification...\n")

        print(f"----------------------------------------------------")
        print(f"                  SERVER SIDE ")
        print(f"----------------------------------------------------\n")
        print(f"Payload Received: {aesEncryptedPayload}")
        print(f"Decrypting encrypted payload at server side using session key.....\n")
        time.sleep(2)
        
        transaction_receive, signature_receive = decrypt_payload(server.session_key, nonce, aesEncryptedPayload)

        print(f"Server side decrypted transaction: {transaction_receive}")
        print(f"Server side decrypted signature: {signature_receive}")

        print(f"Verifying transaction at server side with client ECDSA public key.....") 
        print(f"Client ECDSA Public Key: {client_ecdsa_public}\n")
        status = server.verify_transaction(client_ecdsa_public, transaction_receive, signature_receive)
        time.sleep(2)
        if (status):
            account["BALANCE"] += amount
            save_account(account)
            print("Deposit successful.\n")

    elif choice == "3":
        amount = int(input("Enter amount to withdraw($): "))

        if amount > account["BALANCE"]:
            print("Insufficient funds.\n")
            continue

        transaction = f"WITHDRAW:{amount}".encode()
        print(f"\nClient transaction text after encode: {transaction}")
        signature = sign(client_ecdsa_private, transaction)
        print(f"Client signature after sign: {signature}\n")
        print("Encrypting Signature and Transaction.....\n")
        time.sleep(2)
        nonce , aesEncryptedPayload = encrypt_payload(client_session_key, transaction, signature)
        print(f"Client AES encrypted payload: {aesEncryptedPayload}\n")
        print(f"Sending encrypted payload to server for verification...\n")
        print(f"----------------------------------------------------")
        print(f"                  SERVER SIDE ")
        print(f"----------------------------------------------------\n")
        print(f"Payload Received: {aesEncryptedPayload}")
        print(f"Decrypting encrypted payload at server side using session key.....\n")
        time.sleep(2)
        transaction_receive, signature_receive = decrypt_payload(server.session_key, nonce, aesEncryptedPayload)
        print(f"Server side decrypted transaction: {transaction_receive}")
        print(f"Server side decrypted signature: {signature_receive}\n")
        print(f"Verifying transaction at server side with client ECDSA public key.....")
        print(f"Client ECDSA Public Key: {client_ecdsa_public}\n")
        time.sleep(2)
        status = server.verify_transaction(client_ecdsa_public, transaction_receive, signature_receive)

        if (status):
            account["BALANCE"] -= amount
            save_account(account)
            print("Withdrawal successful.\n")

    elif choice == "4":
        print("Logging out...")
        break

    else:
        print("Invalid option.\n")
