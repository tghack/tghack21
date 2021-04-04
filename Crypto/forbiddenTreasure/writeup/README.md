# forbidden Treasure

So here is the first idea I had which first led me to creating the precursor for this task, hiddenTreasure. This task however doesn't have a simple logic bug and you can't provide plaintext to get a plaintext/ciphertext pair to easily find the keystream. Here you're just provided with the text that's normally sent as public information. Just with the underlying bug of nonce reuse.

Nonce reuse you say? Yeah! Here we have to abuse something called the forbidden attack. Which is based on the fact that if you reuse the nonce in aes gcm and have two ciphertext/tag pairs with this problem you can use that to forge authentication tags. Or in this case just prove that you can forge them by calculating the the authentication tag would have been for a message.


In this task you weren't provided with the source-code but it's fairly similar to hiddenTreasure with some code to generate random sequences to encrypt as well as of course reusing the nonce.

```go
package main

import (
        "bufio"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "encoding/hex"
        "fmt"
        "io/ioutil"
        "log"
        mrand "math/rand"
        "os"
)

var printable = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\\'()*+,-./:;<=>?@[]^_`{|}~ ")

func randSeq(n int) []byte {
        b := make([]byte, n)
        for i := range b {
                b[i] = printable[mrand.Intn(len(printable))]
        }
        return b
}

func main() {
        key := make([]byte, 32)
        rand.Read(key)
        nonce := make([]byte, 12)
        rand.Read(nonce)
        fmt.Println("Here have two encrypted messages and show me you know the authentication tag of the third:")
        fmt.Println(encrypt(key, nonce, randSeq(16)))
        fmt.Println(encrypt(key, nonce, randSeq(16)))
        ct, verifyTag := encrypt(key, nonce, randSeq(16))
        fmt.Println("If you can create the authentication tag for this ct you get the treasure:")
        fmt.Println(ct)

        scanner := bufio.NewScanner(os.Stdin)
        if !scanner.Scan() {
                log.Printf("Failed to read: %v", scanner.Err())
                return
        }
        hexTag := scanner.Text()

        if verifyTag != hexTag {
                log.Println("oops! wrong!")
                return
        }

        flag, err := ioutil.ReadFile("flag")
        if err != nil {
                log.Println(err.Error())
                return
        }

        fmt.Println("Here you go, good work!")
        fmt.Println(string(flag))

}

func encrypt(key, nonce, plaintext []byte) (ciphertext, tag string) {
        block, err := aes.NewCipher(key)
        if err != nil {
                log.Fatal(err.Error())
        }

        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                log.Fatal(err.Error())
        }

        ciphertextAndTag := aesgcm.Seal(nil, nonce, plaintext, nil)

        return hex.EncodeToString(ciphertextAndTag[:16]), hex.EncodeToString(ciphertextAndTag[len(ciphertextAndTag)-16:])
}
```

So this attack is fairly complicated and I don't think I could explain in better than some of the writeups I've linked at the bottom of the writeup. This attack has lot's of PoCs and tools like nonce-disrespect so there's lots of ways to solve it I used a modified version of the script from RedRocket to solve it:

```py
import pwnlib
from sage.all import *
from pwn import xor

r = pwnlib.tubes.remote.remote("127.0.0.1", 1337)
print(r.recvuntil("== proof-of-work: "))

r.recvline()

ct1, tg1 = r.recvline().decode().strip().split()
ct2, tg2 = r.recvline().decode().strip().split()
r.recvline()
ct3 = r.recvline().decode().strip()


# Sage magic inspiration from http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/
from binascii import unhexlify, hexlify


def slice_and_pad(b_str, bsize=16):
    b_str += b"\x00" * (len(b_str) % bsize)
    return [bytearray(b_str[k : k + bsize]) for k in range(0, len(b_str), bsize)]

def unhex_blocks(h_str, bsize=16):
    h_str = unhexlify(h_str)
    return slice_and_pad(h_str, bsize)

def xor(a, b):
    assert len(a) == len(b)
    return bytearray([a[i] ^ b[i] for i in range((len(a)))])

def byte_to_bin(byte):
    b = bin(byte)[2:]
    return "0" * (8 - len(b)) + b

def block_to_bin(block):
    assert len(block) == 16
    b = ""
    for byte in block:
        b += byte_to_bin(byte)
    return b

def bytes_to_poly(block, a):
    f = 0
    for e, bit in enumerate(block_to_bin(block)):
        f += int(bit) * a ** e
    return f

def poly_to_int(poly):
    a = 0
    for i, bit in enumerate(poly._vector_()):
        a |= int(bit) << (127 - i)
    return a

def poly_to_hex(poly):
    return hex(poly_to_int(poly))[2:]

C1 = unhex_blocks(ct2)
T1 = unhex_blocks(tg2)

C2 = unhex_blocks(ct1)
T2 = unhex_blocks(tg1)

C3 = unhex_blocks(ct3)

# Same length for all messages
bit_len_plain = len(C1[0]) // 2 * 8
bit_len_auth = 0
L = unhex_blocks(hex((bit_len_auth << 64) | bit_len_plain)[2:].rjust(32, "0"))

T = xor(T1[0], T2[0])
C = [xor(C1[0], C2[0])]

# Sage magic

F, a = GF(2 ** 128, name="a").objgen()
R, X = PolynomialRing(F, name="X").objgen()

C1_p = [bytes_to_poly(C1[0], a)]
T1_p = bytes_to_poly(T1[0], a)

C3_p = [bytes_to_poly(C3[0], a)]

C_p = [bytes_to_poly(C[0], a)]
T_p = bytes_to_poly(T, a)

L_p = bytes_to_poly(L[0], a)


f1 = C1_p[0] * X ** 2 + L_p * X + T1_p
f3 = C3_p[0] * X ** 2 + L_p * X
p = C_p[0] * X ** 2 + T_p

s = ""

for root, _ in p.roots():
    EJ = f1(root)
    flag = f3(root) + EJ
    s = str(poly_to_hex(flag))

print(s)
r.sendline(s)
r.recvline()
print(r.revline().decode())
```



# Further reading
![Redrocket VolgaCTF 2018 writeup](http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/)
![rctcwyvrn UTCTF 2020 writeup](https://rctcwyvrn.github.io/posts/2020-03-12-galois_writeup.html)

