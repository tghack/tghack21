In this challenge we need to solve 7 levels of 50 crypto/encoding challenges with a strict time limit, we only have two seconds for each challenge to respond.

Through trial and error we can use known plaintext attacks to figure out what each level is. We use `hello` as known plaintext in the writeup, but while solving doing longer single character inputs etc. will help solve each level easier.

## Level 1: base64
```
hello becomes aGVsbG8=
```
Looks like base64, we use [cyberchef](https://gchq.github.io/CyberChef/) base64 decode and see `aGVsbG8=` decodes to `hello`.

## Level 2: rot13
```
hello becomes uryyb
```
Output looks like a substitution cipher, try ROT13 and it decrypts correctly to `hello`.

## Level 3: rot13 -> base64 -> rot13
```
hello becomes qKW5rJV=
```
Decoding base64 gives broken output, since we just got introduced to rot13, lets try `rot13->base64`, this gives us output we recognize from previous level, thus `rot13->base64->rot13`

## Level 4: XOR with key 0x2A -> base64
```
hello becomes Qk9GRkU=
```
Decoding base64 we get `BOFFE`, leveraging Cyberchef magic operator, we can see XOR with key 0x2A gives `hello`.

## Level 5: Vigenere with key tghack
```
hello becomes akslq
```
Looks like another substitution cipher, using Vigenere decode on Cyberchef with input `akslq` and key `hello`, we get the output `tghac`. Sending longer input will reveal the key `tghack`.

## Level 6: rot13 -> vigenere with key tghack
```
hello becomes nxfyd
```
If we input `nxfyd` into the previous Cyberchef session we get similar output as from Level 2, so `rot13->Vigenere`

## Level 7: vigenere with key tghack -> XOR with key 0x2a -> base64
```
hello becomes S0FZRls=
```
Base64 decode we get `KAYF[`, guessing another reuse we try XOR with known key 0x2A. Which results in output similar to Level 5 `akslq`.

Complete solver script:
```python
#!/usr/bin/env python3
from pwn import *
from string import ascii_lowercase, ascii_uppercase
from base64 import b64decode
import codecs
HOST, PORT = 'are-ye-pirate.tghack.no', 1337
io = connect(HOST, PORT)
def vigenere(s, key="tghack"):
    f = 0
    x = ''
    for i,c in enumerate(s):
        if c.lower() not in ascii_lowercase:
            f += 1
            x += c
        elif c in ascii_lowercase:
            kidx = ascii_lowercase.index(key[(i-f)%len(key)])
            midx = ascii_lowercase.index(c)
            x += ascii_lowercase[(midx-kidx+26)%26]
        elif c in ascii_uppercase:
            kidx = ascii_uppercase.index(key[(i-f)%len(key)])
            midx = ascii_uppercase.index(c)
            x += ascii_uppercase[(midx-kidx+26)%26]
    return x
def level1(s):
    return b64decode(s).decode()
def level2(s):
    return codecs.encode(s, 'rot_13')
def level3(s):
    resp = codecs.encode(s, 'rot_13')
    resp = b64decode(resp).decode()
    resp = codecs.encode(resp, 'rot_13')
    return resp
def level4(s):
    resp = b64decode(s).decode()
    return ''.join(chr(ord(c)^0x2A) for c in resp)
def level5(s):
    return vigenere(s)
def level6(s):
    resp = vigenere(s)
    return codecs.encode(resp, 'rot_13')
def level7(s):
    resp = b64decode(s).decode()
    resp = ''.join(chr(ord(c)^0x2A) for c in resp)
    return vigenere(resp)
def solve(level):
    io.sendlineafter('some input> ', 'hello')
    for _ in range(50):
        io.recvuntil("Now decode ")
        c = io.recvline().strip().decode()
        print(f"Challenge: {c}")
        a = level(c)
        print(f"Answer: {a}")
        io.sendlineafter('> ', a)
solve(level1)
solve(level2)
solve(level3)
solve(level4)
solve(level5)
solve(level6)
solve(level7)
print(io.recvall(timeout=2).decode())
```