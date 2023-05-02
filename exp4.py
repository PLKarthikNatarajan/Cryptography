def encrypt(plaintext, k):
    if len(k) <= 1:
        print("keyword should be at least 2 characters long")
        return
    ciphertext = ""
    for i in range(len(plaintext)):
        ciphertext += chr((((ord(plaintext[i])-97) + (ord(k[i%len(k)] )-97)+26)%26)+97)
    return ciphertext

def decrypt(ciphertext, k):
    if len(k) <= 1:
        print("keyword should be at least 2 characters long")
        return
    plaintext = ""
    for i in range(len(ciphertext)):
        plaintext += chr((((ord(ciphertext[i])-97) - (ord(k[i%len(k)])-97)+26)%26)+97)
    return plaintext

def vigenerecipherButtonFunction():
    enteredKey = input('Enter key: ').lower().replace('[^a-z]', '')
    message = input('Enter message: ').lower().replace('[^a-z]', '')
    if enteredKey == "" or message == "":
      print("Please enter key and message to be ciphered/deciphered!")
      return
    result = encrypt(message, enteredKey)
    print(result)

def vigeneredecipherButtonFunction():
    enteredKey = input('Enter key: ')
    message = input('Enter message: ')
    if enteredKey == "" or message == "":
      print("Please enter key and message to be ciphered/deciphered!")
      return
    result = decrypt(message, enteredKey)
    print(result)

plaintext=input("enter plaintext:")
k=input("enter key:")
print(encrypt(plaintext,k))
ciphertext=encrypt(plaintext,k)
print(decrypt(ciphertext,k))