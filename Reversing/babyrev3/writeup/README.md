## Writeup

Simple solve script, change the values that does not make sense to numbers and you got the flag.
```python
lines = []

with open('enc.txt') as res:
    for line in res.readlines():
        lines.append(line.strip())


flag = []
print((ord('3')%65))
for org_letter in lines:
    if int(org_letter,16) < 65:
        flag.append(chr(int(org_letter,16)+65))
    else:
        flag.append(chr(int(org_letter,16)))
        

print(''.join(flag))
```
