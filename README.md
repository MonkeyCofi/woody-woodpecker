# woody-woodpacker
A binary packer that takes an ELF64 file, encrypts it and injects code into it.

### ELF files
ELF stands for Executable and Linkable Format. These are programs that can be executed by the computer. In this project, we are only concerned with 64-bit ELF files.

### Sections vs Segments
Sections are the logical parts that make up the file. For example, the code usually lies within the .text section of an ELF file, and uninitialized but declared variables lie within the .bss section. Segments are sections bundled up together to be loaded into the computer's memory

### run.sh
A script that builds and execute an alpine docker container that can be used to compile 32-bit binaries. It has a secret bonus feature that you can find out by reading the script

## Preliminary steps

### Loading the binary file
The binary file is opened, and then mapped into memory using mmap(), which will store the contents of the file within the virtual space of the process calling mmap (in this case, woody_woodpacker). mmap returns the address of the loaded memory if successful, otherwise it returns MAP_FAILURE (which is not equivalent to NULL)

### Parsing the Elf header
The ELF header contains all the information about the ELF file. This includes, but is not limited to: the bit architecture (32-bit or 64-bit); the endianness; the offset to the Program header table as well as the offset to the Section header table; and so on and so forth.

Within the header is a 16-byte array of characters called the e_ident, which contains the primary information about the ELF file. The size of the array is a macro that is defined as follows:
```C
#define EI_IDENT 16
```

The Ehdr struct is as follows
```C
typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    ElfN_Addr     e_entry;
    ElfN_Off      e_phoff;
    ElfN_Off      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} ElfN_Ehdr;
```
The variable e_entry contains the entry point of the binary file and should be saved so that it can later be modified. The new entry point of the binary will be the address of the function that will be used to decrypt the encrypted segment.

### Encryption
For the encryption, 

## Resources
[Handcrafting x86_64 ELF from specification to bytes](https://medium.com/@dassomnath/handcrafting-x64-elf-from-specification-to-bytes-9986b342eb89)