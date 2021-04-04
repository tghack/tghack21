from secret import flag

enc = []
for i in flag:
    enc.append(hex(ord(i)+1))

for e in enc:
    print(e)
