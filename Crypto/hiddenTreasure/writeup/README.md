# hiddenTreasure

This task was made as a precursor to my next task forbidden treasure. Below you can see the source code that was provided to the participants along with the service.
```go
package main

import (
        "bufio"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "fmt"
        "io/ioutil"
        "log"
        "os"
)

var (
        cnt uint8
)

func main() {
        key := make([]byte, 32)
        rand.Read(key)
        nonce := make([]byte, 11)
        rand.Read(nonce)
        flag, err := ioutil.ReadFile("flag")
        if err != nil {
                log.Fatal(err.Error())
        }
        encrypt(key, nonce, flag)
        for {
                scanner := bufio.NewScanner(os.Stdin)
                if !scanner.Scan() {
                        log.Fatalf("Failed to read: %v", scanner.Err())
                        return
                }
                plaintext := scanner.Bytes()

                encrypt(key, nonce, plaintext)
        }
}

func encrypt(key, nonce, plaintext []byte) {
        nonce = append(nonce, cnt) // Keep the IV unique
        block, err := aes.NewCipher(key)
        if err != nil {
                log.Fatal(err.Error())
        }

        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                log.Fatal(err.Error())
        }

        ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

        fmt.Printf("%x\n", ciphertext)
        cnt++
}
```

So this code just reads in some random bytes, from a secure source, so no vulnerabilities there. Then it encrypts the flag and outputs the ciphertext, afterwards there's a while loop letting you encrypt know plaintexts and get the output.

Seems fine, let's have closer look at the encrypt function so at the first line we see that the nonce, which *has to be unique* is kept unique by taking 11 random bytes and then appending a counter. 

Then it goes on to encrypt the plaintext and lastly increasing the counter.

OK so if the nonce is unique and we don't know the key. There's no vulnerabilities, right? Wrong. At the top of the code where the cnt variable is declared it's set as a uint8, maybe this is just to make byte conversion easy. However it has a side effect. since it's a uint8 when it has the value 255 adding 1 brings the cnt back to zero! That means after being sent the encrypted flag we can encrypt 255 messages and have the counter wrap around. Then send a message where we know the plaintext and will get back known ciphertext.

From there we know have a know plaintext /ciphertext pair with the same keystream, since the nonce was the same, now we can just use some simple xor operations XORing the flag with the already XORed ciphertext and plaintext pair.

Essentially just:

```
KS = ct ^ pt
flag = encrypted_flag^KS
```

And without further ado here's my solve script.

```py
import pwnlib
from pwn import *

r = pwnlib.tubes.remote.remote("127.0.0.1", 1337)
print(r.recvuntil("== proof-of-work: "))

flag = unhex(r.recvline().strip()[:-32])  # strip newline and tag and unhex

payload = "a" * len(flag)

for i in range(255):  # send the same payload until counter wraps around
    r.sendline(payload)
    r.recvline()

r.sendline(payload)  # same nonce as when flag was encrypted
print(xor(flag, unhex(r.recvline().strip()[:-32]), payload))
```

