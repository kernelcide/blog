The first PWN challenge we faced was titled "File Handling on Demand". The description stated that it was a custom file handling server but that it had been tested thoroughly and shouldn't have any bugs.  

# Challenge Contents
A zip file was provided with the following contents:
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
.
.
.
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

