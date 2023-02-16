from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
import json
import requests
import random

app = Flask(__name__)

# A dictionary to store user balances
balances = {"Alice": 100, "Bob": 50, "Charlie": 200}

# Generate a new RSA key pair for the wallet
wallet_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


@app.route("/balance/<username>", methods=["GET"])
def get_balance(username):
    """Endpoint to retrieve the balance of a user"""
    return str(balances.get(username, 0))


@app.route("/transfer", methods=["POST"])
def transfer():
    """Endpoint to transfer funds from one user to another"""
    data = request.get_data()
    data_dict = json.loads(data)
    sender = data_dict.get("sender")
    recipient = data_dict.get("recipient")
    amount = data_dict.get("amount")
    signature = data_dict.get("signature")

    # Verify the signature of the transfer request
    sender_public_key = serialization.load_pem_public_key(sender.encode())
    verifier = sender_public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(data.encode())
    try:
        verifier.verify()
    except:
        return "Invalid signature", 400

    # Check if the sender has enough balance
    if balances.get(sender, 0) < amount:
        return "Insufficient balance", 400

    # Transfer funds from sender to recipient
    balances[sender] -= amount
    balances[recipient] = balances.get(recipient, 0) + amount
    return "Transfer successful"


@app.route("/simulate", methods=["POST"])
def simulate():
    """Endpoint to simulate interactions between users"""
    data = request.get_data()
    data_dict = json.loads(data)
    num_transfers = data_dict.get("num_transfers", 10)
    for i in range(num_transfers):
        sender, recipient = select_users()
        amount = select_amount(sender)
        signature = sign_transfer(sender, recipient, amount)
        transfer_funds(sender, recipient, amount, signature)
    return "Simulation successful"


def select_users():
    """Selects two random users"""
    users = list(balances.keys())
    sender = recipient = None
    while sender == recipient:
        sender = random.choice(users)
        recipient = random.choice(users)
    return sender, recipient


def select_amount(sender):
    """Selects a random amount to transfer from the sender"s balance"""
    balance = balances.get(sender, 0)
    return random.randint(1, balance)


def sign_transfer(sender, recipient, amount):
    """Signs a transfer request using the sender"s private key"""
    data = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount
    }
    message = json.dumps(data)
    signature = wallet_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def transfer_funds(sender, recipient, amount, signature):
    """Sends a transfer request to the recipient"""
    data = {
        "sender": wallet_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode(),
    "recipient": recipient,
    "amount": amount,
    "signature": signature
    }
    headers = {"Content-type": "application/json"}
    requests.post("http://localhost:5000/transfer", data=json.dumps(data), headers=headers)


if __name__ == "__main__":
    app.run()

    # Load the private key for Bob"s wallet
    with open("bob_private_key.pem", "rb") as f:
        bob_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Sign the transfer request
    data = {
        "sender": "Bob",
        "recipient": "Alice",
        "amount": 3
    }
    message = json.dumps(data)
    signature = bob_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_hex = signature.hex()

# Send the transfer request to the server
    data["signature"] = signature_hex
    headers = {"Content-type": "application/json"}
    response = requests.post("http://localhost:5000/transfer", data=json.dumps(data), headers=headers)
    print(response.text)
