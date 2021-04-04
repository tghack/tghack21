## Writeup


```python
lines = []

with open('enc.txt') as res:
    for line in res.readlines():
        lines.append(line.strip())

diff = 0
known_letter_value = ord("T")
first_output_value = int(lines[0],16)
diff = first_output_value-known_letter_value

print(diff)
flag = []

print(lines)
for org_letter in lines:
    flag.append(chr(int(org_letter,16)-diff))

print(''.join(flag))

```