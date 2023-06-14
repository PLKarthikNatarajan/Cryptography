def generate_subkeys(block_size):
    if block_size == 64:
        constant = 0x1B
    elif block_size == 128:
        constant = 0x87
    else:
        raise ValueError("Invalid block size")

    zero_block = bytes([0] * (block_size // 8))

    # Apply the block cipher to the zero block
    ciphertext = block_cipher(zero_block)

    # Left shift the ciphertext by one bit
    left_shifted = left_shift(ciphertext, block_size)

    # XOR the left shifted ciphertext with the constant
    subkey1 = xor(left_shifted, constant)

    # Left shift the first subkey by one bit
    subkey2 = left_shift(subkey1, block_size)

    return subkey1, subkey2


def block_cipher(block):
    # Block cipher implementation
    # Replace this with your actual block cipher function
    # For demonstration purposes, we'll just return the block as is
    return block


def left_shift(data, block_size):
    # Left shift implementation
    # Shifts the bits of the data by one position to the left
    # For demonstration purposes, we'll just shift the bytes as is
    shifted = bytearray(data)
    shift_amount = 1
    while shift_amount < block_size:
        carry = 0
        for i in range(len(shifted) - 1, -1, -1):
            temp = shifted[i] & 0x80
            shifted[i] = ((shifted[i] << 1) & 0xFF) | carry
            carry = temp >> 7
        shift_amount += 1
    return bytes(shifted)


def xor(data, constant):
    # XOR implementation
    # Performs bitwise XOR operation between the data and constant
    # For demonstration purposes, we'll just XOR the bytes as is
    xored = bytearray(data)
    for i in range(len(xored)):
        xored[i] ^= constant
    return bytes(xored)


# Test the subkey generation for block size 64 bits
subkey1, subkey2 = generate_subkeys(64)
print("Subkey 1 (64-bit):", subkey1.hex())
print("Subkey 2 (64-bit):", subkey2.hex())

# Test the subkey generation for block size 128 bits
subkey1, subkey2 = generate_subkeys(128)
print("Subkey 1 (128-bit):", subkey1.hex())
print("Subkey 2 (128-bit):", subkey2.hex())
