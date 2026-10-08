import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)

    with open(input_file, "rb") as file:
        data = file.read()

    nonce = os.urandom(12)

    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    with open(output_file, "wb") as file:
        file.write(nonce)
        file.write(encrypted_data)


def decrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    decrypted_data = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(decrypted_data)