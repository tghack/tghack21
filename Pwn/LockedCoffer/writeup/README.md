# Locked Coffer
>Author: Nic#4234

This challenge is quite similar to Squiffy Pirate, except it is a little more advanced.

We start by checking the file and its protections:
```sh
$ file locked-coffer
locked-coffer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2ba2b3c6b9f4af0d5a5ec68e59b2880d7f12c19b, for GNU/Linux 3.2.0, not stripped

$ checksec locked-coffer
[*] '~/locked-coffer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

By looking at the output from `checksec`, we can see that the NX bit (no execute) is disabled here. This makes it possible to execute shellcode residing on the stack, if we can control the return instruction pointer. This is also the goal of the challenge. However, we can also see that this is a PIE (Position Independent Executable) binary, meaning that it consists of Position Independent Code. This makes it harder for us since memory addresses are randomized on each program execution. We therefore have to leak an address to be able to control code execution.

Luckily for us, the binary contains a format string vulnerability in [chal.c#L17](insert-link-here). We can therefore send "format-strings" such as "%p " to *stdin*, which will cause `printf()` to start spitting out memory addresses of the program [exploit.py#L43](insert-link-here).

By debugging the binary in GDB with [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) disabled, we can locate what each leaked memory address is used for. Once we have found the stack address we want to use, we have a relative address to point the return instruction pointer (RIP) to! 

The next step is to enter our desired payload into the second program input, and continue debugging. First we have to find out how many bytes we have to send before we notice that the EIP/RIP is overwritten. This can easily be done with the output of `cyclic <num-bytes> -n 8` (-n 8 for x64) from `pwntools`, and providing this as the second program input while debugging in GDB:

With the `cyclic` output:
```
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaa
```

GDB produces the following:
```sh
gdb-peda$ info frame
Stack level 0, frame at 0x7fffffffe088:
 rip = 0x555555555282 in unlock_chest; saved rip = 0x6161616161616172
 called by frame at 0x7fffffffe098
 Arglist at 0x6161616161616171, args:
 Locals at 0x6161616161616171, Previous frame's sp is 0x7fffffffe090
 Saved registers:
  rip at 0x7fffffffe088
gdb-peda$
````

We can see that `saved rip = 0x6161616161616172`, and convert this to match our `cyclic` input and find the [correct offset](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Reverse('Character')&input=MHg2MTYxNjE2MTYxNjE2MTcy) to use for padding (junk bytes). 

In the example solution script [exploit.py](), we have used the exact location of where our shellcode starts on the stack and have therefore subtracted `0xA0` from the leaked address. It is also possible to use NOP-sleds (A chain of <N> no-operation instructions) here instead of subtractions, which will let the instruction pointer "slide" onto the shellcode to executed. 

Once we have successfully calculated the correct offset before sending data to control the application with and have obtained a leaked address, we can craft our [payload](exploit.py#L60) and send it to the application.

If your exploit worked, congratulations! You got a shell :-) 
