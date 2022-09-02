* TOC
{:toc}

This is a writeup about the 2022 MapleCTF challenge `Warmup2`

# Challenge Background

> Author: =)#9593  
> It's like warmup1, but harder.

This challenge was one of the earlier releases in the `pwn` category. It is also one of the simpler challenges of the CTF with 100 solves by the end. We are given the challenge binary `chal` and a netcat command to connect to the service hosting the binary `nc warmup2.ctf.maplebacon.org 1337`.

# Reconnaissance

First I downloaded the challenge binary - `chal` - from the provided link and ran the `file` command to get an idea of what we're dealing with.

