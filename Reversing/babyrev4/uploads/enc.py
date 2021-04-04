from secret import *

enc = []
for i in flag:
    enc.append(hex(ord(i)+secret_number))

for e in enc:
    print(e)