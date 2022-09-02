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

This allows us to then read in the processes stack canary from stdout. This then allows us to freely overflow the buffer, maintain the canary, and hijack the control flow - though we have to remember to add the null byte back into the canary!

# Defeating ASLR

