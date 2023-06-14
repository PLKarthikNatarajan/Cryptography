from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def cbc_mac(key, message):
    iv = os.urandom(16)  # Generate a random initialization vector (IV)

    # Create a Cipher object using AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the message using PKCS7 padding scheme
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()

    # Encrypt the padded message using CBC mode
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return ciphertext


# Generate a random key
key = os.urandom(32)

# Define the message
message = b"Hello, CBC-MAC!"

# Calculate the CBC MAC for the one-block message
mac = cbc_mac(key, message)
print("MAC for one-block message:", mac.hex())

# Construct the two-block message X || (X ⊕ T)
two_block_message = message + bytes(x ^ y for x, y in zip(message, mac))

# Show that the adversary knows the CBC MAC for the two-block message
print("CBC MAC for two-block message:", cbc_mac(key, two_block_message).hex())
