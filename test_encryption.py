from encryption import generate_key, encrypt_file, decrypt_file
import os

# Generate a 256-bit AES key
key = generate_key()

print("AES-256 key generated successfully.")

# Files used for testing
original_file = "uploads/test.txt.txt"
encrypted_file = "uploads/test_encrypted.bin"
decrypted_file = "uploads/test_decrypted.txt"

# Encrypt
encrypt_file(original_file, encrypted_file, key)

print("File encrypted successfully.")

# Decrypt
decrypt_file(encrypted_file, decrypted_file, key)

print("File decrypted successfully.")

# Compare original and decrypted files
with open(original_file, "rb") as original:
    original_data = original.read()

with open(decrypted_file, "rb") as decrypted:
    decrypted_data = decrypted.read()

if original_data == decrypted_data:
    print("SUCCESS: Original and decrypted files are identical.")
else:
    print("ERROR: Files are different.")