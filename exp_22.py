# def apply_permutation(bits, permutation):
#     return ''.join(bits[i - 1] for i in permutation)
#
#
# def initial_permutation(block):
#     ip = [2, 6, 3, 1, 4, 8, 5, 7]
#     return apply_permutation(block, ip)
#
#
# def expansion(block):
#     e = [4, 1, 2, 3, 2, 3, 4, 1]
#     return apply_permutation(block, e)
#
#
# def xor_strings(str1, str2):
#     return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2))
#
#
# def substitute(sbox, bits):
#     row = int(bits[0] + bits[3], 2)
#     col = int(bits[1] + bits[2], 2)
#     return '{0:02b}'.format(sbox[row][col])
#
#
# def substitution(block):
#     sbox1 = [
#         [1, 0, 3, 2],
#         [3, 2, 1, 0],
#         [0, 2, 1, 3],
#         [3, 1, 3, 2]
#     ]
#     sbox2 = [
#         [0, 1, 2, 3],
#         [2, 0, 1, 3],
#         [3, 0, 1, 0],
#         [2, 1, 0, 3]
#     ]
#     left = block[:4]
#     right = block[4:]
#     left_substituted = substitute(sbox1, left)
#     right_substituted = substitute(sbox2, right)
#     return left_substituted + right_substituted
#
#
# def p4(block):
#     p = [2, 4, 3, 1]
#     return apply_permutation(block, p)
#
#
# def fk(block, subkey):
#     expanded = expansion(block)
#     xored = xor_strings(expanded, subkey)
#     substituted = substitution(xored)
#     p4ed = p4(substituted)
#     return p4ed
#
#
# def generate_subkeys(key):
#     p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
#     p8 = [6, 3, 7, 4, 8, 5, 10, 9]
#     permuted_key = apply_permutation(key, p10)
#     left = permuted_key[:5]
#     right = permuted_key[5:]
#     left_shifted = left[1:] + left[:1]
#     right_shifted = right[1:] + right[:1]
#     shifted_key = left_shifted + right_shifted
#     subkey1 = apply_permutation(shifted_key, p8)
#     left_shifted = left_shifted[2:] + left_shifted[:2]
#     right_shifted = right_shifted[2:] + right_shifted[:2]
#     shifted_key = left_shifted + right_shifted
#     subkey2 = apply_permutation(shifted_key, p8)
#     return subkey1, subkey2
#
#
# def sdes_encrypt(plaintext, key, iv):
#     subkey1, subkey2 = generate_subkeys(key)
#     iv = bytearray(iv)


# S-DES functions

# S-DES permutation constants
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def apply_permutation(bits, permutation):
    return ''.join(bits[i - 1] for i in permutation)


def generate_round_keys(key):
    round_keys = []
    key = apply_permutation(key, P10)
    left, right = key[:5], key[5:]
    for i in range(2):
        left = left[1:] + left[0]
        right = right[1:] + right[0]
        round_key = apply_permutation(left + right, P8)
        round_keys.append(round_key)
    return round_keys


def f_function(bits, round_key):
    expanded = apply_permutation(bits, EP)
    xored = bin(int(expanded, 2) ^ int(round_key, 2))[2:].zfill(8)
    left, right = xored[:4], xored[4:]
    sbox_output = apply_sbox(left, S0) + apply_sbox(right, S1)
    return apply_permutation(sbox_output, P4)


def apply_sbox(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1:3], 2)
    return format(sbox[row][col], '02b')


def encrypt_block(block, round_keys):
    block = apply_permutation(block, IP)
    left, right = block[:4], block[4:]
    for i in range(2):
        f_result = f_function(right, round_keys[i])
        new_right = bin(int(left, 2) ^ int(f_result, 2))[2:].zfill(4)
        left = right
        right = new_right
    cipher_text = apply_permutation(right + left, IP_INV)
    return cipher_text


def decrypt_block(block, round_keys):
    block = apply_permutation(block, IP)
    left, right = block[:4], block[4:]
    for i in range(2):
        f_result = f_function(right, round_keys[1 - i])
        new_right = bin(int(left, 2) ^ int(f_result, 2))[2:].zfill(4)
        left = right
        right = new_right
    plain_text = apply_permutation(right + left, IP_INV)
    return plain_text


# CBC encryption
def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    round_keys = generate_round_keys(key)
    previous_cipher_block = iv
    for block in plaintext:
        block = bin(int(block, 2) ^ int(previous_cipher_block, 2))[2:].zfill(8)
        encrypted_block = encrypt_block(block, round_keys)
        ciphertext.append(encrypted_block)
        previous_cipher_block = encrypted_block
    return ciphertext


# CBC decryption
def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    round_keys = generate_round_keys(key)
    previous_cipher_block = iv
    for block in ciphertext:
        decrypted_block = decrypt_block(block, round_keys)
        decrypted_block = bin(int(decrypted_block, 2) ^ int(previous_cipher_block, 2))[2:].zfill(8)
        plaintext.append(decrypted_block)
        previous_cipher_block = block
    return plaintext


# Test data
plaintext = ['00000001', '00100011']
key = '0111111101'
iv = '10101010'

# Encrypt using S-DES in CBC mode
ciphertext = cbc_encrypt(plaintext, key, iv)
print("Ciphertext:", ciphertext)
