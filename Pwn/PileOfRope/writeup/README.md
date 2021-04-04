# Pile of ROPe
>Author: Nic#4234

This challenge was a ROP exploit that required a little knowledge of `x64 calling conventions`, since we had to provide two arguments to the `haul` function to execute `system("cat flag.txt");`.

Binary and protections shows that we are dealing with a 64-bit binary, this time with NX enabled (meaning we can NOT execute shellcode on the stack), but no binary address randomization (PIC) this time:
```sh
$ file pile-of-rope
pile-of-rope: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6ab9b8d0980bea7f9cbbd96da45343297c5e2415, for GNU/Linux 3.2.0, not stripped

$ checksec pile-of-rope
[*] '~/pile-of-rope'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The solution is quite simple. Once we have calculated the correct offset for padding (similar to how we did it for the LockedCoffer challenge), all we have to do is search through the binary for some useful segments of instructions (gadgets) we can use to achieve what we want.

Those familiar with x64 calling conventions know that the [first six arguments are in rdi, rsi, rdx, rcx, r8d, r9d; remaining arguments are on the stack.](https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start)

Since we have two program arguments we have to provide, we need to find gadgets to pop both RDI and RSI.

This can be done by using tools such as [ROPgadget]():
```sh
# $ ROPgadget --binary pile-of-rope | grep 'pop rdi'
# 0x00000000004012bb : pop rdi ; ret

# $ ROPgadget --binary pile-of-rope | grep 'pop rsi'
# 0x00000000004012b9 : pop rsi ; pop r15 ; ret
```

In the second gadget, we notice that it also includes `pop r15`. We can account for this by [popping null bytes](exploit.py#L46) into that register, since we do not care for it anyway.

For the registers `RDI` and `RSI`, we have to specify two parameters that ensures the if check returns true: `0xDEADBEEF` for `RDI`, and hex("R0PE") == `0x52305045` for `RSI`.

Finally, we create the payload: `PAYLOAD += POP_RDI + RDI + POP_RSI_R15 + RSI + R15 + X` and send this to the application. This payload will POP the value `var: RDI` into `reg: RDI`, POP the value `var: RSI` into `reg: RSI`, the value `var: R15` into `reg: R15`, and finally return to the address of the `haul` function.

Upon successful exploitation, we get the flag!
