from exp_22 import generate_round_keys, encrypt_block


def ctr_encrypt(plaintext, key, counter):
    ciphertext = []
    round_keys = generate_round_keys(key)
    for block in plaintext:
        encrypted_counter = encrypt_block(counter, round_keys)
        encrypted_block = bin(int(block, 2) ^ int(encrypted_counter, 2))[2:].zfill(8)
        ciphertext.append(encrypted_block)
        counter = bin(int(counter, 2) + 1)[2:].zfill(8)
    return ciphertext


# Counter mode decryption
def ctr_decrypt(ciphertext, key, counter):
    plaintext = []
    round_keys = generate_round_keys(key)
    for block in ciphertext:
        decrypted_counter = encrypt_block(counter, round_keys)
        decrypted_block = bin(int(block, 2) ^ int(decrypted_counter, 2))[2:].zfill(8)
        plaintext.append(decrypted_block)
        counter = bin(int(counter, 2) + 1)[2:].zfill(8)
    return plaintext


# Test data
plaintext = ['00000001', '00001000', '00010000']
key = '0111111101'
counter = '00000000'

# Encrypt using S-DES in counter mode
ciphertext = ctr_encrypt(plaintext, key, counter)
print("Ciphertext:", ciphertext)

# Decrypt using S-DES in counter mode
decrypted_plaintext = ctr_decrypt(ciphertext, key, counter)
print("Decrypted plaintext:", decrypted_plaintext)
