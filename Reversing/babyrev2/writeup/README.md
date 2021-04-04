## Writeup


```python
lines = []

with open('enc.txt') as res:
    for line in res.readlines():
        lines.append(line.strip())

flag = []

for org_letter in lines:
    flag.append(chr(int(org_letter,16)-1))

print(''.join(flag))
```