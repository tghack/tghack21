# Crooked Race

This was a really fun task for me. I love typeracer, and used to go on that site all the time trying to better my typing speed for no actual reason. As I seldom knew what words to type as fast as I could write them in real life, but I digress. 

I just wanted to crate a challenge where you have to cheat in typeracer and not get detected. You didn't get the source code for this challenge at the bottom of the writeup if you want to have a look.

So essentially I implemented wpm checks where you had to type over 120 wpm, but not over 300, convincing the script that a human was typing. I also checked that you didn't type long words in the same time as really short words.

These challenges above are basically requiring that you use a script to "cheat" however in the last part of the script I generate some words and output them as ASCII art, and you only have two seconds to submit them, this is similar to typeracer.com 's captcha check, where you first have to type text, which is easy. Then get an image captcha which you have to type just as fast. I was essentially trying to mimic that.

So, for typeracer.com you would have to bring out OCR tools and try to parse and submit the text. And one could try to go the OCR route for this challenge as well, however that might become tedious. So what I did was that I found a really recognizable ASCII art font, called "basic", then I just parsed out the letters from the ASCII-art letters that were output. I actually had a hint ready because I didn't think people would find the font, however I didn't have to use the hint because people recognized it straight away for the most part.

NOTE: my solution for different speeds for different length words is over-complicated and could just be solved by sleeping after sending each char and you'll get the difference naturally.

Anyways this was just a fun challenge for me to make, I actually made it during the CTF just in time for the last batch of challenges to go out and I'm quite happy with how it turned out.

# Solve script:
```py
import pwnlib
import string
from pyfiglet import Figlet
import time

r = pwnlib.tubes.remote.remote('crookedrace.tghack.no', 1337)

intro = r.recvline()
words = [r.recvline()[:-1] for i in range(50)]
charlen = sum([len(w) for w in words])
base_sleep = (((charlen/5)/400)*60)/50
for word in words:
    time.sleep(base_sleep+(0.05*len(word)))
    r.sendline(word)
last_challenge = r.recvline()
ascii_text = r.recvuntil("===").decode()[:-4]

uniq = list(set(ascii_text))
uniq.remove(" ")
uniq.remove("\n")

# multiline string to 2d array
def tD_a(s):
    arr = []
    for l in s.split("\n"):
        l = [c for c in l]
        arr.append(l)
    return arr

# print 2D array as multiline string
def p_tD_a(arr):
    s = ""
    for l in arr:
        s += "".join(l) + "\n"
    return s


charset = string.ascii_uppercase + " '.?,-!"

f = Figlet(font='basic')
d = {}
for l in charset:
    d[l] = f.renderText(l)

ascii_arr = tD_a(ascii_text)[:-2]

mn = min([len(l) for l in ascii_arr])
mx = min([len(l) for l in ascii_arr])


height = len(ascii_arr)
ixs = [0] + [x for x in range(mn) if all([ascii_arr[y][x] == ' ' for y in range(height)])] + [mx]
captcha = ""
i = 1
while i < len(ixs):
    s = ""
    for y in range(height):
        frm = ixs[i-1]
        m1 = ixs[i]
        m2 = len(ascii_arr[y])
        to  = min(m1, m2)
        if i == len(ixs)-1:
            to = max(m1,m2)
        s += "".join(ascii_arr[y][frm: to ]) + "\n"

    for al in charset:
        l = d[al]
        stripped_s = s.replace(" ","")
        stripped_l = l.replace(" ","")[:-2]
        if stripped_l == stripped_s:
            captcha += al
    i += 1

expected = r.recvline()
captcha = captcha.replace("  "," ")
r.sendline(captcha)
flag = r.recvlineS().strip()
print(flag)
```

# Source code:

```go
package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/common-nighthawk/go-figure"
)

type stat struct {
	Length    int
	ElapsedMS int
}

var (
	wordChn = make(chan string, 0)
	
	phraseTxt string

	words []string

	requiredWords int  = 50
	
	finalWordCnt int = 3

	charsTyped int
	
	stats map[int]stat = make(map[int]stat)
	
	marginMS int = 20

	marginLength int = 4
	
	wpmLimit float64 = 120.0

	wpmMax float64 = 300.0
)

func init(){
	rand.Seed(time.Now().Unix())
	log.SetOutput(os.Stdout)

	b, err := os.ReadFile("phrases.txt")
	if err != nil {
		log.Fatal(err)
	}
	phraseTxt = string(b)
}


func read() {
	
	r := bufio.NewReader(os.Stdin)
	for {
		word, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			os.Exit(10)
		}
		wordChn <- strings.TrimSpace( word)
	}
}

func main() {
	phrases := strings.Split(phraseTxt,"\n")
	for i := 0; i < requiredWords; i++ {
		words  = append(words, phrases[rand.Intn(len(phrases))])
	}
	fmt. Println("Yarr write these words faster than me and I'll give ya your reward, time has started, GO!")
	fmt.Println(strings.Join(words,"\n"))
	started := time.Now()
	go read()
	for currWord := 0; currWord < len(words); currWord++{
		wordTime := time.Now()
		word := <-wordChn
		if  word == words[currWord] {
			charsTyped += len(word)
			stats[currWord] = stat{
				Length:    len(word),
				ElapsedMS: int(time.Since(wordTime).Milliseconds()),
			}
			continue
		}else{
			log.Printf("Sorry, '%s' does not match '%s'", word, words[currWord])
			os.Exit(11)
		}
	}
	
	elapsed := float64(time.Since(started).Milliseconds())

	wpm := (float64(charsTyped)/5)/(elapsed/60000)
	if wpm < wpmLimit {
		log.Printf("Sorry, wpm less than %d\n" ,int(wpmLimit))
		os.Exit(12)
	}
	if wpm > wpmMax {
		log.Printf("Aaarg, %d that be too fast of typing, no landlubber can type above %d, yar be robot!\n", int(wpm), int(wpmMax))
		os.Exit(13)
	}

	for word, stat := range stats {
		for word1, stat1 := range stats {
			if stat.Length > (stat1.Length + marginLength) && (stat.ElapsedMS < stat1.ElapsedMS - marginMS) {
					log.Printf("Damn, you managed to type '%s' in %dms and '%s' in %dms, the phrases are different in length but you used about the same time, what gives cheater?", words[word],stat.ElapsedMS,words[word1],stat1.ElapsedMS)
					os.Exit(14)
			}
		}
	}

	fmt.Println("Last challenge! Type this so I know that you're a human typing")
	timeout := time.NewTimer(2 * time.Second)
	finalWords := phrases[rand.Intn(len(phrases))]
	for i := 0; i < finalWordCnt; i++ {
		finalWords += " " + phrases[rand.Intn(len(phrases))]
	}
	finalWords = strings.ToUpper(finalWords)
	myFigure := figure.NewFigure(finalWords, "basic", true)
	myFigure.Print()
	fmt.Println("===")
	select {
	case word := <-wordChn:
		if word == finalWords {
			fmt.Printf("GG, you're faster than me. Here you go: TG21{Damn_Y0u_Two_Handed_Landlubber_At_Least_I_know_You're_Not_A_Robot}\n")
		}else {
			log.Printf("Yarr, that be close, but I knew I you were a robot all along, you wrote '%s' while I wanted '%s'\n", word, finalWords)
			os.Exit(15)
		}
	case <-timeout.C:
		log.Println("Too slow, I knew you were cheating!")
		os.Exit(16)
	}

}
```
