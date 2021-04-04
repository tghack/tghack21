To solve this challenge one has to be able to write somewhat creative assembly as the program filters out assembly programs containing ileglal instructions 

The ilegal instructions are 
jmp,pop,push,ret,int,call,syscall,jump

Because some of these are what is normally used for controll flow we need to find some alternative ways to controll the flow 
So for the first trick 
loppnz label will jump to label if after decrementing ecx becomes 0 using this we can use XOR to check if ecx contains a certain value 
i.e 
xor ecx, 0x464c457f
will check if ecx contains 0x46... if it doesn't contain this ecx will become something diffrent from zero even if ecx is already zero. 

since ecx will become zero we have to increment ecx so that when loopnz gets run ecx will become zero.

We can use this in combination with the return value that the applications prints after our assembly code has ran to extract the elf which is ran on the remote host 

resulting in Leak.py and leak_elf.s
Another interesting trick here is to look at [rsp] to check from where the function has been called from using this we can decrement rax until it points to the start of the executable marked by the elf magic bytes, from here we can start incrementing eax the amount we have already read to slowely leak out the binary. 

As we now have obtained the binary we discover that  we can easily retrive the offset of the got table. 
Here we can easily change function adresses to functions like strcmp or exit to make the protection mechanisms inneficent 

As the assembly is temporarly rwx when the application checks for ilegal instructions we can change exit to point to our shellcode which will allow us to take control, when the program dettects that there are ilegal instructions where it exits :)
