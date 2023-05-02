l1 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
      'X', 'Y', 'Z']

a = int(input("Enter the a value: "))
b = int(input("Enter the b value: "))
ch = int(input("Enter the choice:\n1)Encrypt\n2)Decrypt\t:"))
if ch == 1:
    pt = input("Enter the plain text: ")
    alphabet = ""
    for i in pt:
        if i != " ":
            if i in l1:
                x = l1.index(i)
                print(x, end=",")
                new_index = int(((a * x) + b) % 26)
                print(new_index, end=",")
                alphabet = alphabet + l1[new_index]
                print(l1[new_index])

    print(alphabet)

if ch == 2:
    ct = input("Enter the cipher text: ")
    alphabet = ""
    for i in ct:
        if i != " ":
            if i in l1:
                x = l1.index(i)
                print(x, end=",")
                new_index = int(((x - b) / a) % 26)
                print(new_index, end=",")
                alphabet = alphabet + l1[new_index]
                print(l1[new_index])

    print(alphabet)