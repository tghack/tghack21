## Writeup

Solve script

```python
f = open("./enc.txt")
lines = f.readlines()
ln = len(lines)
first = lines[:ln//2+1]
last = lines[ln//2+1:]

enc = []
for x in range(17):
    enc.append(first[x])
    enc.append(last[x])

print("T" + "".join([chr(int(x)+9) for x in enc[::-1]]))
```