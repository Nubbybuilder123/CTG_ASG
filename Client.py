# client.py
from ECDH import generate_keypair as ecdh_keys, derive_shared_secret, derive_aes_key
from ECDSA import generate_keypair as ecdsa_keys, sign, verify
from Server import BankServer
import time

# setup
server = BankServer()
ACCOUNT_FILE = "account.txt"

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
verify(server_public_key, message, signature)
time.sleep(2)
print("[Client] Bank server authenticated.")



# Phase 2: Secure Session
client_shared_secret = derive_shared_secret(
    client_ecdh_private, server.ecdh_public
)
client_session_key = derive_aes_key(client_shared_secret)
server.establish_session(client_ecdh_public)
time.sleep(2)
print("[Client] Secure session established.\n")


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
        server.verify_transaction(client_ecdsa_public, transaction, signature)

        account["BALANCE"] += amount
        save_account(account)
        print("Deposit successful.\n")

    elif choice == "3":
        amount = int(input("Enter amount to withdraw($): "))

        if amount > account["BALANCE"]:
            print("Insufficient funds.\n")
            continue

        transaction = f"WITHDRAW:{amount}".encode()
        signature = sign(client_ecdsa_private, transaction)
        server.verify_transaction(client_ecdsa_public, transaction, signature)

        account["BALANCE"] -= amount
        save_account(account)
        print("Withdrawal successful.\n")

    elif choice == "4":
        print("Logging out...")
        break

    else:
        print("Invalid option.\n")
