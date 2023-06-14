import string
import collections


def calculate_frequency(text):
    # Count the frequency of each letter in the text
    frequency = collections.Counter(text)

    # Calculate the relative frequency of each letter
    total = sum(frequency.values())
    relative_frequency = {letter: count / total for letter, count in frequency.items()}

    return relative_frequency


def decrypt(ciphertext, key):
    # Create a decryption key using the given substitution key
    decryption_key = str.maketrans(key, string.ascii_uppercase)

    # Decrypt the ciphertext using the decryption key
    plaintext = ciphertext.translate(decryption_key)

    return plaintext


def perform_frequency_attack(ciphertext, num_solutions=10):
    # Calculate the letter frequency of the ciphertext
    ciphertext_frequency = calculate_frequency(ciphertext)

    # Sort the letter frequencies in descending order
    sorted_frequency = sorted(ciphertext_frequency.items(), key=lambda x: x[1], reverse=True)

    # Generate a list of potential plaintexts with different substitution keys
    potential_plaintexts = []

    for i in range(num_solutions):
        # Extract the most likely ciphertext letter
        ciphertext_letter = sorted_frequency[i][0]

        # Create a substitution key based on the ciphertext letter
        key = ciphertext_letter * len(string.ascii_uppercase)

        # Decrypt the ciphertext using the substitution key
        plaintext = decrypt(ciphertext, key)

        # Add the potential plaintext to the list
        potential_plaintexts.append(plaintext)

    return potential_plaintexts


# Example usage
ciphertext = "WKH HDVLHVW PHWKRG RI HQFLSKHULQJ D WHAW PHVVDJH LV WR UHSODFH HDFK FKDUDFWHU EB DQRWKHU XVLQJ D ILAHG UXOH, VR IRU HADPSOH HYHUB OHWWHU D PDB EH UHSODFHG EB WKH OHWWHU DQG HYHUB OHWWHU E EB WKH PDB."

potential_plaintexts = perform_frequency_attack(ciphertext, num_solutions=10)

print("Top 10 possible plaintexts:")
for i, plaintext in enumerate(potential_plaintexts):
    print(f"{i + 1}. {plaintext}")
