from secret import *

enc = []
for i in flag:
    enc.append((ord(i)+secret_number_1))

cne = enc[::-1]

cne2 = []
for e in range (0,len(cne),2):
    cne2.append(cne[e])

for e in range (1,len(cne),2):
    cne2.append(cne[e])

for r in cne2:
    print(r-secret_number_2)