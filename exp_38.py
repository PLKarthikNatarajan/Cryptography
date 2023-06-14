import numpy as np


def encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key_size = int(np.sqrt(len(key)))
    plaintext_size = int(np.ceil(len(plaintext) / key_size))

    padded_plaintext = plaintext.ljust(plaintext_size * key_size, 'X')
    ciphertext = ""

    for i in range(0, len(padded_plaintext), key_size):
        block = padded_plaintext[i:i + key_size]
        block_indices = [ord(ch) - ord('A') for ch in block]
        block_matrix = np.array(block_indices).reshape(key_size, 1)

        encrypted_block_matrix = np.dot(key, block_matrix) % 26
        encrypted_block = "".join(chr(index + ord('A')) for index in encrypted_block_matrix.flatten())
        ciphertext += encrypted_block

    return ciphertext


def known_plaintext_attack(plaintexts, ciphertexts):
    plaintext_matrix = np.array([list(map(lambda x: ord(x) - ord('A'), plaintext)) for plaintext in plaintexts])
    ciphertext_matrix = np.array([list(map(lambda x: ord(x) - ord('A'), ciphertext)) for ciphertext in ciphertexts])

    key = np.dot(np.linalg.pinv(plaintext_matrix), ciphertext_matrix) % 26

    return key


def decrypt(ciphertext, key):
    ciphertext_matrix = np.array(list(map(lambda x: ord(x) - ord('A'), ciphertext)))
    decrypted_matrix = np.dot(ciphertext_matrix, key) % 26
    decrypted_text = ''.join(chr(int(val) + ord('A')) for val in decrypted_matrix)
    return decrypted_text


# Example usage
plaintexts = ["HELLO", "WORLD"]
ciphertexts = ["AXNNE", "ZCVDN"]
key = known_plaintext_attack(plaintexts, ciphertexts)

print("Recovered Key:")
print(key)

# Test the decryption with the recovered key
recovered_plaintext = decrypt(ciphertexts[0], key)
print("Decrypted Plaintext:")
print(recovered_plaintext)
