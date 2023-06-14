from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def encrypt_ecb(plaintext, key):
    # Create a cipher object with AES algorithm and ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    encryptor = cipher.encryptor()

    # Create a padder with the block size of the cipher
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Pad the plaintext
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the ciphertext
    return ciphertext


def encrypt_cbc(plaintext, key, iv):
    # Create a cipher object with AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    encryptor = cipher.encryptor()

    # Create a padder with the block size of the cipher
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Pad the plaintext
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the ciphertext
    return ciphertext


def encrypt_cfb(plaintext, key, iv):
    # Create a cipher object with AES algorithm and CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Return the ciphertext
    return ciphertext


# Example usage
key = os.urandom(16)  # Generate a random 16-byte AES key
iv = os.urandom(algorithms.AES.block_size // 8)  # Generate a random IV with the block size of AES
plaintext = b'This is a test message'

# Encryption in ECB mode
ciphertext_ecb = encrypt_ecb(plaintext, key)
print("ECB Ciphertext:", ciphertext_ecb)

# Encryption in CBC mode
ciphertext_cbc = encrypt_cbc(plaintext, key, iv)
print("CBC Ciphertext:", ciphertext_cbc)

# Encryption in CFB mode
ciphertext_cfb = encrypt_cfb(plaintext, key, iv)
print("CFB Ciphertext:", ciphertext_cfb)
