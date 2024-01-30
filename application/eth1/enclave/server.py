#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import os
import socket
import subprocess

import web3
from web3.auto import w3

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# =============== Common Utility =================

# Encrypt using data key from KMS, from within the enclave
def kms_encrypt_call(credential, plaintext):
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    # Generate a data key
    generate_key_args = [
        "/app/kmstool_enclave_cli",
        "generate-data-key",
        "--region", os.getenv("REGION"),
        "--proxy-port", "8000",
        "--aws-access-key-id", aws_access_key_id,
        "--aws-secret-access-key", aws_secret_access_key,
        "--aws-session-token", aws_session_token,
        "--output", "json"
    ]

    proc_generate = subprocess.Popen(generate_key_args, stdout=subprocess.PIPE)
    result_generate = proc_generate.communicate()[0].decode()

    data_key = json.loads(result_generate)
    plaintext_key = base64.b64decode(data_key["Plaintext"])
    ciphertext_key = base64.b64encode(data_key["CiphertextBlob"]).decode()

    # Encrypt your data using the plaintext key
    encrypted_data = encrypt_data_with_key(plaintext, plaintext_key)
    
    # Delete plain text key from memory
    securely_delete_key(plaintext_key)

    return ciphertext_key, encrypted_data

# Utility code to encrypt data with raw data key
def encrypt_data_with_key(data, key):
    # Ensure the data is padded to meet the block size requirements of the encryption algorithm
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create an AES cipher object with the key and use CBC mode for encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes([0] * 16)), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

# Utility code to decrypt data with raw data key
def decrypt_data_with_key(ciphertext, key):
    # Create an AES cipher object with the key and use CBC mode for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes([0] * 16)), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

# Securely delete memory
def securely_delete_key(key):
    # Overwrite the key with zeros
    key_len = len(key)
    zeroed_key = b'\x00' * key_len
    key[:key_len] = zeroed_key

# Decrypt the encrypted data key using KMS, here cypher text is the encrypted data key
def kms_decrypt_call(credential, ciphertext):
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "decrypt",
        "--region",
        os.getenv("REGION"),
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]

    print("subprocess args: {}".format(subprocess_args))

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)

    # returns b64 encoded plaintext
    result_b64 = proc.communicate()[0].decode()
    plaintext_b64 = result_b64.split(":")[1].strip()

    return plaintext_b64

# =============== End of Common Utility =================

# =============== Wallet Generation =================
# Generate wallets for incoming user metadata list 
def generate_wallets(user_data_list):
    wallets = []

    for user_data in user_data_list:
        user_id = user_data["user_id"]
        email = user_data["email"]

        # Generate a new wallet address and encrypted private key
        wallet_address, encrypted_private_key = generate_wallet_for_user(user_data)

        wallet_info = {
            "user_id": user_id,
            "email": email,
            "wallet_address": wallet_address,
            "encrypted_private_key": encrypted_private_key,
        }

        wallets.append(wallet_info)

    return wallets

# Utility function to generate wallet for a user, and return the encrypted wallet & encrypted data key
def generate_wallet_for_user(user_data):
    wallet_address, private_key = generate_wallet()
    encrypted_private_key = encrypt_data_with_key(private_key, user_data["encryption_key"])
    return wallet_address, encrypted_private_key

# Utility function to create an individual wallet using web3.py 
def generate_wallet():
    account = w3.eth.account.create()
    return account.address, account.privateKey.hex()

# =============== End of Wallet Generation =================

# =============== EVM Transaction Signing =================

def sign_transaction(credential, transaction_dict, key_input):
    try:
        key_b64 = kms_decrypt_call(credential, key_input)
    except Exception as e:
        msg = "exception happened calling kms binary: {}".format(e)
        print(msg)
        response_plaintext = msg

    else:
        key_plaintext = base64.standard_b64decode(key_b64).decode()

        try:
            transaction_dict["value"] = web3.Web3.toWei(
                    transaction_dict["value"], "ether"
                )
            transaction_signed = w3.eth.account.sign_transaction(
                    transaction_dict, key_plaintext
                )
            response_plaintext = {
                    "transaction_signed": transaction_signed.rawTransaction.hex(),
                    "transaction_hash": transaction_signed.hash.hex(),
                }

        except Exception as e:
            msg = "exception happened signing the transaction: {}".format(e)
            print(msg)
            response_plaintext = msg

            # delete internal reference to plain text password
        del key_plaintext

    print("response_plaintext: {}".format(response_plaintext))
    return response_plaintext

# =============== End of Transaction Signing =================

def main():
    print("Starting server...")

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in the parent EC2 instance
    port = 5000

    # Bind the socket to CID and port
    s.bind((cid, port))

    # Listen for connection from the client
    s.listen()

    while True:
        c, addr = s.accept()

        # Get AWS credential sent from the parent instance
        payload = c.recv(4096)
        payload_json = json.loads(payload.decode())
        print("payload json: {}".format(payload_json))

        credential = payload_json["credential"]
        transaction_dict = payload_json["transaction_payload"]

        # Extract the method type from the payload
        method_type = payload_json["method_type"]
        print("method_type: {}".format(method_type))

        # Check the method type and invoke the appropriate function
        if method_type == "encrypt":
            key_input = payload_json["plaintext_data"]
            response_plaintext = kms_encrypt_call(credential, key_input)
        elif method_type == "decrypt":
            key_input = payload_json["encrypted_key"]
            response_plaintext = sign_transaction(credential, transaction_dict, key_input)
        else:
            response_plaintext = {"error": "Invalid method_type"}

        c.send(str.encode(json.dumps(response_plaintext)))
        c.close()

if __name__ == "__main__":
    main()
