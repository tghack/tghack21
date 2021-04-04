from secret import flag

enc = []
for i in flag:
    enc.append(hex(ord(i)%1000+0x00))

for e in enc:
    print(e)