## Writeup

Modulus does nothing in this challenge
```pyhton
lines = []

with open('enc.txt') as res:
    for line in res.readlines():
        lines.append(line.strip())

flag = []

for org_letter in lines:
    flag.append(chr(int(org_letter,16)))

print(''.join(flag))
```