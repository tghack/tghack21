from secret import *

enc = []
for i in flag:
    enc.append(hex(ord(i)+secret_number))
    secret_number += 1

for e in enc:
    print(e)