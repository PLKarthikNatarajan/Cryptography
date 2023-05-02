l1 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
      'X', 'Y', 'Z']
ind = []

ch = int(input("Enter the process: \n1)Encryption \n2)Decryption\t:"))

if ch == 1:
    pt = input("Enter the plain text: ")
    k = int(input("Enter the k value: "))
    for i in pt:
        if i in l1:
            x = l1.index(i)
            cip = (x + k) % 26
            ind.append(l1[cip])

    for i in ind:
        print(i, end="")
if ch == 2:
    pt = input("Enter the cipher text: ")
    k = int(input("Enter the k value: "))
    for i in pt:
        if i in l1:
            x = l1.index(i)
            cip = (x - k) % 26
            ind.append(l1[cip])

    for i in ind:
        print(i, end="")