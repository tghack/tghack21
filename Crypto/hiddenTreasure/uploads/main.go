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
