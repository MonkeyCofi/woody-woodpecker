# Detailed Approach: woody_woodpacker

A binary packer that encrypts an ELF64 binary and injects a decryption stub, producing a new `woody` executable that self-decrypts at runtime.

## Current Status

Basic ELF64 header validator in `srcs/main.c` that:
- Opens and memory-maps the target binary
- Checks the ELF magic number (`\x7fELF`)
- Verifies 64-bit class (`EI_CLASS == 2`)

## Project Architecture

```
srcs/
├── main.c          # Entry point, argument handling, orchestration
├── elf_parser.c    # ELF parsing: headers, sections, segments
├── elf_parser.h    # Shared types and function declarations
├── encrypt.c       # RC4 key generation + encryption
├── encrypt.h       # Cipher interface
├── inject.c        # Binary reconstruction and stub injection
├── inject.h        # Injection interface
stub/
└── decrypt.s       # x86-64 decryption stub (assembled separately)
```

---

## Phase 1: Deep ELF Parsing

### Goal

Extract all metadata needed for encryption and injection from the input ELF64 binary.

### Data Structures to Use

The kernel provides these structures via `<elf.h>`:

```c
// The ELF file header — located at byte 0 of the file
typedef struct {
    unsigned char e_ident[16];  // Magic + class + data encoding + padding
    Elf64_Half    e_type;       // ET_EXEC (2) for executables
    Elf64_Half    e_machine;    // EM_X86_64 (0x3E)
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;      // ← ORIGINAL ENTRY POINT (OEP) — save this
    Elf64_Off     e_phoff;      // Offset to program header table
    Elf64_Off     e_shoff;      // Offset to section header table
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;     // Size of this header (64 for ELF64)
    Elf64_Half    e_phentsize;  // Size of one program header entry (56 for ELF64)
    Elf64_Half    e_phnum;      // Number of program header entries
    Elf64_Half    e_shentsize;  // Size of one section header entry (64 for ELF64)
    Elf64_Half    e_shnum;      // Number of section header entries
    Elf64_Half    e_shstrndx;   // Index of section name string table
} Elf64_Ehdr;

// Program header — describes a segment (what gets loaded into memory)
typedef struct {
    Elf64_Word  p_type;    // PT_LOAD (1), PT_DYNAMIC (2), etc.
    Elf64_Word  p_flags;   // PF_X (1), PF_W (2), PF_R (4)
    Elf64_Off   p_offset;  // Offset in file where segment starts
    Elf64_Addr  p_vaddr;   // Virtual address where segment is loaded
    Elf64_Addr  p_paddr;   // Physical address (usually = p_vaddr)
    Elf64_Xword p_filesz;  // Size of segment in file
    Elf64_Xword p_memsz;   // Size of segment in memory (>= p_filesz, BSS)
    Elf64_Xword p_align;   // Alignment (usually 0x1000 = 4096)
} Elf64_Phdr;

// Section header — describes a section (.text, .data, .bss, etc.)
typedef struct {
    Elf64_Word  sh_name;       // Offset into section name string table
    Elf64_Word  sh_type;       // SHT_PROGBITS (1), SHT_SYMTAB (2), etc.
    Elf64_Xword sh_flags;      // SHF_ALLOC (2), SHF_EXECINSTR (4), etc.
    Elf64_Addr  sh_addr;       // Virtual address of section in memory
    Elf64_Off   sh_offset;     // Offset in file
    Elf64_Xword sh_size;       // Size in bytes
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;
```

### Step-by-Step Parsing Logic

#### 1.1 — Memory-map the entire file

```c
int fd = open(filename, O_RDONLY);
off_t file_size = lseek(fd, 0, SEEK_END);
void *map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
```

**Why `MAP_PRIVATE` + `PROT_WRITE`:** We need a private copy we can modify (encrypt `.text`, patch headers) without touching the original file. `MAP_PRIVATE` gives us copy-on-write semantics.

#### 1.2 — Validate the ELF (existing code, extended)

```c
bool validate_elf64(Elf64_Ehdr *ehdr) {
    // Check magic: \x7f E L F
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
        return false;
    // Check class: 64-bit
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return false;
    // Check type: executable (ET_EXEC = 2) or shared object (ET_DYN = 3)
    // ET_DYN is used by PIE executables (compiled with -pie)
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
        return false;
    // Check machine: x86-64
    if (ehdr->e_machine != EM_X86_64)
        return false;
    return true;
}
```

#### 1.3 — Save the Original Entry Point (OEP)

```c
Elf64_Addr original_entry = ehdr->e_entry;
```

This is the address the program *would* have started at. We'll redirect `e_entry` to our stub, and the stub will jump back to `original_entry` after decrypting.

#### 1.4 — Find the `.text` section (what to encrypt)

```c
Elf64_Shdr *find_section(Elf64_Ehdr *ehdr, const char *name) {
    // Section name string table
    Elf64_Shdr *shstrtab = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff)
                           + ehdr->e_shstrndx;
    char *strtab = (char *)ehdr + shstrtab->sh_offset;

    // Iterate all section headers
    Elf64_Shdr *sections = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(&strtab[sections[i].sh_name], name) == 0)
            return &sections[i];
    }
    return NULL;
}

Elf64_Shdr *text_section = find_section(ehdr, ".text");
```

**What we get:**
- `text_section->sh_offset` — file offset where `.text` begins
- `text_section->sh_size` — how many bytes to encrypt
- `text_section->sh_addr` — virtual address (needed for stub to reference encrypted region)

**If `.text` is not found:** Fall back to finding the first `PT_LOAD` segment with `PF_X | PF_R` flags and encrypt its executable portion.

#### 1.5 — Find the last `PT_LOAD` segment (for injection)

```c
Elf64_Phdr *find_last_load_segment(Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    Elf64_Phdr *last_load = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD)
            last_load = &phdrs[i];
    }
    return last_load;
}

Elf64_Phdr *last_load = find_last_load_segment(ehdr);
```

**Why the last `PT_LOAD`:** This is where we'll append our stub + encrypted data. The last loadable segment has the highest virtual address, so extending it is the least disruptive.

**What we get:**
- `last_load->p_offset` — where the segment starts in the file
- `last_load->p_filesz` — current size in file
- `last_load->p_memsz` — current size in memory
- `last_load->p_vaddr` — virtual address base
- `last_load->p_align` — alignment requirement (typically 0x1000)

#### 1.6 — Collect all results into a context struct

```c
typedef struct {
    void            *map;            // mmap'd file
    size_t          file_size;       // original file size
    Elf64_Ehdr      *ehdr;           // ELF header
    Elf64_Addr      oep;             // original entry point
    Elf64_Shdr      *text_section;   // .text section (to encrypt)
    Elf64_Phdr      *last_load;      // last PT_LOAD segment (to extend)
    size_t          inject_offset;   // file offset where stub will be placed
    Elf64_Addr      inject_vaddr;    // virtual address where stub will be placed
} t_packer;
```

### Helper Functions to Write

```c
// elf_parser.c
bool        validate_elf64(Elf64_Ehdr *ehdr);
Elf64_Shdr  *find_section(Elf64_Ehdr *ehdr, const char *name);
Elf64_Phdr  *find_segment(Elf64_Ehdr *ehdr, Elf64_Word type);
Elf64_Phdr  *find_last_load_segment(Elf64_Ehdr *ehdr);
Elf64_Phdr  *find_text_segment(Elf64_Ehdr *ehdr);
char        *get_section_name(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);
```

---

## Phase 2: RC4 Encryption & Key Generation

### Why RC4

RC4 is a stream cipher consisting of two phases: a Key Scheduling Algorithm (KSA) and a Pseudo-Random Generation Algorithm (PRGA). It is:
- **Simple to implement** (~30 lines of C)
- **Symmetric** — the same algorithm decrypts as encrypts (just re-run with the same key)
- **Easy to implement in ASM** — the decryption loop is a simple byte-by-byte XOR with a keystream
- **Justifiable for evaluation** — it's a real cipher used historically in WEP/TLS

### RC4 Algorithm — Exact Specification

RC4 operates on a 256-byte permutation array `S[0..255]` (the "S-box").

#### 2.1 — Key Scheduling Algorithm (KSA)

Initializes the S-box using the secret key:

```c
void rc4_ksa(uint8_t S[256], const uint8_t *key, size_t key_len) {
    // Step 1: Initialize S to identity permutation
    for (int i = 0; i < 256; i++)
        S[i] = (uint8_t)i;

    // Step 2: Scramble S using the key
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + key[i % key_len];  // wraps at uint8_t
        // Swap S[i] and S[j]
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}
```

**How it works:** Each iteration, `j` is updated by adding `S[i]` and the next key byte (cycling). Then `S[i]` and `S[j]` are swapped. After 256 iterations, the S-box is a pseudorandom permutation determined by the key.

#### 2.2 — Pseudo-Random Generation Algorithm (PRGA) + Encryption

Generates a keystream and XORs it with the plaintext:

```c
void rc4_encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    uint8_t S[256];
    rc4_ksa(S, key, key_len);

    uint8_t i = 0, j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        // Swap S[i] and S[j]
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        // Keystream byte = S[(S[i] + S[j]) % 256]
        uint8_t keystream = S[(S[i] + S[j]) % 256];
        // XOR: encryption and decryption are the same operation
        data[k] ^= keystream;
    }
}
```

**Critical property:** RC4 encryption and decryption are identical — XORing the ciphertext with the same keystream recovers the plaintext. This means the ASM stub uses the exact same loop for decryption.

#### 2.3 — Key Generation

Generate a cryptographically random key using `/dev/urandom`:

```c
#include <fcntl.h>
#include <unistd.h>

#define KEY_LEN 16  // 128-bit key — good balance of security and stub simplicity

int generate_key(uint8_t *key, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, key, len);
    close(fd);
    if (n != (ssize_t)len)
        return -1;
    return 0;
}
```

**Key length choice:** 16 bytes (128 bits). Longer keys are more secure but add bytes to the stub. 16 bytes is the minimum recommended for real cryptographic use.

#### 2.4 — Print the Key

The subject requires the key to be printed to stdout during packing:

```c
void print_key(const uint8_t *key, size_t len) {
    printf("KEY=");
    for (size_t i = 0; i < len; i++)
        printf("%02x", key[i]);
    printf("\n");
}
```

Output example: `KEY=a3f1b2c4d5e6f708192a3b4c5d6e7f80`

#### 2.5 — Encryption Interface

```c
// encrypt.c
int     generate_key(uint8_t *key, size_t len);
void    rc4_ksa(uint8_t S[256], const uint8_t *key, size_t key_len);
void    rc4_encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len);
void    print_key(const uint8_t *key, size_t len);
```

### What Gets Encrypted

Only the `.text` section contents (the machine code). This ensures:
- The ELF headers remain readable (we need them for injection)
- Program headers remain readable (we need them to extend the last segment)
- Only the actual code is scrambled — `.data`, `.rodata`, etc. are untouched

**File offset to encrypt:** `text_section->sh_offset` through `text_section->sh_offset + text_section->sh_size`

---

## Phase 3: The Decryption Stub (Full x86-64 Assembly)

### Goal

A position-independent x86-64 assembly routine that:
1. Prints `....WOODY....\n` to stdout
2. Decrypts the `.text` section in memory using RC4
3. Jumps to the original entry point

### Memory Layout of the Stub (at injection time)

When injected, the stub region in the binary looks like this:

```
+-----------------------------------------------+
|  Stub code (decrypt_stub)                     |  <- inject_vaddr
|  ~130 bytes                                   |
+-----------------------------------------------+
|  Metadata (patched at injection time)         |
|  +-----------------------------------------+  |
|  | oep        (8 bytes, Elf64_Addr)        |  |  <- stub references via [rip + offset]
|  | enc_addr   (8 bytes, uint64_t)          |  |    (runtime VA of .text section)
|  | enc_size   (8 bytes, uint64_t)          |  |    (size of .text section in bytes)
|  | key        (16 bytes, uint8_t[16])      |  |    (RC4 key used for encryption)
|  +-----------------------------------------+  |
+-----------------------------------------------+
|  (rest of extended segment...)                |
+-----------------------------------------------+
```

### Full Annotated Assembly (`stub/decrypt.s`)

```asm
; decrypt.s — RC4 decryption stub for woody_woodpacker
; Assemble: nasm -f elf64 decrypt.s -o decrypt.o
; This is NOT linked — raw bytes are extracted and injected into the target binary.
;
; All addressing is RIP-relative, making the code position-independent.
; The metadata block (oep, enc_addr, enc_size, key) is placed immediately
; after the code and patched with actual values during injection.

section .text
global _start

_start:
    ; ========================================================
    ; STEP 1: Print "....WOODY....\n" via write(2) syscall
    ; ========================================================
    ; Prototype: ssize_t write(int fd, const void *buf, size_t count)
    ; Syscall number for write on x86-64 Linux: 1
    ; fd   = 1 (stdout)
    ; buf  = address of message (RIP-relative)
    ; count = 14 bytes

    mov     rax, 1              ; syscall number: SYS_write (1)
    mov     rdi, 1              ; fd: stdout
    lea     rsi, [rel msg]      ; pointer to "....WOODY....\n" (RIP-relative)
    mov     rdx, 14             ; message length: 14 bytes
    syscall                     ; invoke write(1, "....WOODY....\n", 14)

    ; ========================================================
    ; STEP 2: Decrypt the .text section using RC4
    ; ========================================================
    ; RC4 is symmetric: decryption = re-encrypting with the same key.
    ; We re-run KSA + PRGA on the encrypted bytes.
    ;
    ; Register usage:
    ;   r12 = runtime address of encrypted data (in memory)
    ;   r13 = number of encrypted bytes
    ;   r14 = pointer to the 16-byte key
    ;   r15 = pointer to the 256-byte S-box (on stack)

    ; --- Load metadata (RIP-relative) ---
    lea     r14, [rel key]              ; r14 = pointer to RC4 key (16 bytes)
    lea     r12, [rel enc_addr]         ; r12 = pointer to enc_addr value
    mov     r12, [r12]                  ; r12 = runtime VA of .text section
    lea     r13, [rel enc_size]         ; r13 = pointer to enc_size value
    mov     r13, [r13]                  ; r13 = enc_size (byte count)

    ; --- Allocate S-box on stack (256 bytes, 16-byte aligned) ---
    sub     rsp, 256                    ; allocate 256 bytes on stack
    and     rsp, -16                    ; align stack to 16 bytes
    mov     r15, rsp                    ; r15 = pointer to S-box

    ; ========================================================
    ; RC4 KSA (Key Scheduling Algorithm)
    ; ========================================================
    ; S[i] = i  for i in 0..255
    ; Then for i = 0..255:
    ;   j = (j + S[i] + key[i % 16]) % 256
    ;   swap(S[i], S[j])

    ; Initialize S-box: S[i] = i
    xor     rcx, rcx                   ; i = 0
.ksa_init:
    mov     byte [r15 + rcx], cl       ; S[i] = i
    inc     cl                         ; i++ (wraps at 256 -> 0, loop ends)
    jnz     .ksa_init                  ; loop until cl wraps to 0

    ; Scramble S-box
    xor     rcx, rcx                   ; i = 0
    xor     rdx, rdx                   ; j = 0
.ksa_scramble:
    movzx   eax, byte [r15 + rcx]     ; eax = S[i]
    add     dl, al                     ; j = j + S[i]
    movzx   ebx, cl                    ; ebx = i
    and     bl, 0x0F                   ; bl = i % 16 (key length = 16)
    movzx   ebx, byte [r14 + rbx]     ; ebx = key[i % 16]
    add     dl, bl                     ; j = j + S[i] + key[i % 16]
    ; dl already wraps at 256 (8-bit register)

    ; Swap S[i] and S[j]
    movzx   ebx, byte [r15 + rdx]     ; ebx = S[j]
    mov     byte [r15 + rdx], al      ; S[j] = S[i]
    mov     byte [r15 + rcx], bl      ; S[i] = S[j]

    inc     cl                         ; i++
    jnz     .ksa_scramble              ; loop until i wraps to 0 (256 iterations)

    ; ========================================================
    ; RC4 PRGA (Pseudo-Random Generation Algorithm) + Decrypt
    ; ========================================================
    ; For each byte k in 0..enc_size-1:
    ;   i = (i + 1) % 256
    ;   j = (j + S[i]) % 256
    ;   swap(S[i], S[j])
    ;   keystream = S[(S[i] + S[j]) % 256]
    ;   data[k] ^= keystream

    xor     rcx, rcx                   ; i = 0
    xor     rdx, rdx                   ; j = 0
    xor     rbx, rbx                   ; k = 0 (byte index into encrypted data)

.decrypt_loop:
    ; i = (i + 1) % 256
    inc     cl                         ; i++ (wraps at 256)

    ; j = (j + S[i]) % 256
    movzx   eax, byte [r15 + rcx]     ; eax = S[i]
    add     dl, al                     ; j = j + S[i]

    ; Swap S[i] and S[j]
    movzx   eax, byte [r15 + rcx]     ; eax = S[i] (reload after possible change)
    movzx   edi, byte [r15 + rdx]     ; edi = S[j]
    mov     byte [r15 + rdx], al      ; S[j] = S[i]
    mov     byte [r15 + rcx], dil     ; S[i] = S[j]

    ; keystream = S[(S[i] + S[j]) % 256]
    movzx   eax, byte [r15 + rcx]     ; eax = S[i]
    add     al, dil                    ; al = S[i] + S[j] (wraps at 256)
    movzx   eax, byte [r15 + rax]     ; eax = S[(S[i] + S[j]) % 256]

    ; data[k] ^= keystream
    xor     byte [r12 + rbx], al      ; encrypted_data[k] ^= keystream

    inc     rbx                        ; k++
    cmp     rbx, r13                   ; if k < enc_size
    jb      .decrypt_loop              ; continue loop

    ; ========================================================
    ; STEP 3: Jump to Original Entry Point (OEP)
    ; ========================================================
    add     rsp, 256                   ; deallocate S-box from stack

    lea     rax, [rel oep]            ; rax = pointer to OEP value
    mov     rax, [rax]                 ; rax = original entry point address
    jmp     rax                        ; jump to OEP — program runs normally

    ; ========================================================
    ; Data: "....WOODY....\n"
    ; ========================================================
msg:
    db "....WOODY....", 0x0A          ; 14 bytes including newline

    ; ========================================================
    ; Metadata block — patched with real values during injection
    ; These are placeholders; the injector overwrites them.
    ; ========================================================
oep:        dq 0x0000000000000000      ; 8 bytes: original entry point address
enc_addr:   dq 0x0000000000000000      ; 8 bytes: runtime VA of encrypted .text
enc_size:   dq 0x0000000000000000      ; 8 bytes: size of .text in bytes
key:        times 16 db 0x00           ; 16 bytes: RC4 encryption key
```

### Stub Size

- Code: ~130 bytes
- Message: 14 bytes
- Metadata: 40 bytes (8 + 8 + 8 + 16)
- **Total: ~184 bytes** (will be padded to page alignment when extending the segment)

### Assembling the Stub

```bash
nasm -f elf64 stub/decrypt.s -o objs/decrypt.o
# Extract raw bytes for injection:
objcopy -O binary -j .text objs/decrypt.o stub/decrypt.bin
xxd stub/decrypt.bin   # verify the bytes
```

The injector reads `decrypt.o` (ELF), locates the `.text` section, and copies its raw bytes into the target binary.

---

## Phase 4: Injection Strategy — Extending the Last `PT_LOAD` Segment

### Why Extend the Last `PT_LOAD`

| Approach | Verdict |
|---|---|
| Extend last `PT_LOAD` | **Chosen.** Reliable, clean, well-understood. |
| Code cave | Too fragile, hard to guarantee contiguous space. |
| Add new `PT_LOAD` | Requires adjusting `e_phoff` if headers don't have room. More complex for marginal benefit. |

### Step-by-Step Injection

#### 4.1 — Calculate the injection point

```c
// The stub goes right after the last PT_LOAD segment's current content.
size_t stub_size = align_to_page(sizeof(stub_bytes) + METADATA_SIZE);
// stub_bytes = raw bytes from decrypt.bin
// METADATA_SIZE = 40 (8 + 8 + 8 + 16)

// New file offset for injection:
size_t inject_offset = last_load->p_offset + last_load->p_filesz;

// New virtual address for injection:
Elf64_Addr inject_vaddr = last_load->p_vaddr + last_load->p_filesz;
// Note: p_filesz is used because at load time, the loader maps
// p_filesz bytes from file, then zero-fills (p_memsz - p_filesz) bytes for BSS.
// Our stub goes in the file portion.

// Align the vaddr to page boundary (for mprotect correctness)
inject_vaddr = align_to_page(inject_vaddr);
```

#### 4.2 — Update the last `PT_LOAD` segment header

```c
last_load->p_filesz += stub_size;   // new content in file
last_load->p_memsz  += stub_size;   // new content in memory
// Also ensure PF_X flag is set (stub contains code)
last_load->p_flags |= PF_X;
```

**Important:** If `p_filesz` and `p_memsz` cross a page boundary, the kernel's loader will map the extra page. The `p_align` field ensures this works correctly.

#### 4.3 — Update the ELF entry point

```c
ehdr->e_entry = inject_vaddr;       // redirect execution to our stub
```

#### 4.4 — Build the metadata block

Patch the placeholder values in the stub with actual addresses:

```c
// Find the metadata offset within the stub (at code_size + msg_size)
size_t metadata_offset_in_stub = CODE_SIZE + MSG_SIZE;

// Calculate where metadata sits in the file
size_t metadata_file_offset = inject_offset + metadata_offset_in_stub;

// Write metadata values into the file buffer:
uint8_t *meta = file_buffer + metadata_file_offset;

// oep (8 bytes, little-endian)
memcpy(meta,      &original_entry, 8);

// enc_addr (8 bytes) — runtime virtual address of .text section
Elf64_Addr text_vaddr = text_section->sh_addr;
memcpy(meta + 8,  &text_vaddr, 8);

// enc_size (8 bytes)
memcpy(meta + 16, &text_section->sh_size, 8);

// key (16 bytes)
memcpy(meta + 24, key, 16);
```

---

## Phase 5: Binary Reconstruction — Complete Walkthrough

### Input -> Output Pipeline

```
Original ELF              woody_woodpacker               woody
+--------------+         +------------------+         +--------------+
| ELF Header   |         | 1. Parse ELF     |         | ELF Header   | (patched e_entry)
| Prgm Headers | ------> | 2. Generate key  | ------> | Prgm Headers | (p_filesz, p_memsz updated)
| .text (code) |         | 3. Encrypt .text |         | .text (encrypted)
| .data        |         | 4. Build stub    |         | .data        | (unchanged)
| .rodata      |         | 5. Inject stub   |         | .rodata      | (unchanged)
| ...          |         | 6. Write woody   |         | ...          |
| Section Hdrs |         +------------------+         | Decryption   | (new, injected)
| ...          |                                      | Stub + Meta  |
+--------------+                                      +--------------+
```

### Detailed Steps

#### 5.1 — Open and mmap the source binary

```c
int src_fd = open(av[1], O_RDONLY);
off_t src_size = lseek(src_fd, 0, SEEK_END);
void *src_map = mmap(NULL, src_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
```

#### 5.2 — Create the output buffer (copy of original)

```c
size_t woody_size = src_size + stub_size;   // allocate room for stub
uint8_t *woody = malloc(woody_size);
memcpy(woody, src_map, src_size);           // start with exact copy
```

**Do not modify the mmap'd original** — work on the malloc'd copy.

#### 5.3 — Generate the RC4 key

```c
uint8_t key[KEY_LEN];
if (generate_key(key, KEY_LEN) != 0) {
    fprintf(stderr, "Failed to generate random key\n");
    return 1;
}
print_key(key, KEY_LEN);   // "KEY=a3f1b2c4..."
```

#### 5.4 — Encrypt the `.text` section

```c
// Pointer to .text in the woody buffer
uint8_t *text_in_woody = woody + text_section->sh_offset;
rc4_encrypt(text_in_woody, text_section->sh_size, key, KEY_LEN);
```

#### 5.5 — Write stub code into the buffer

```c
// Read the assembled stub bytes
uint8_t *stub_code = read_stub_binary("stub/decrypt.bin", &actual_code_size);

// Copy stub code into woody at inject_offset
memcpy(woody + inject_offset, stub_code, actual_code_size);
```

#### 5.6 — Patch metadata in the stub

```c
size_t meta_offset = inject_offset + actual_code_size;
uint8_t *meta = woody + meta_offset;

// Patch oep
memcpy(meta + OEP_OFFSET,     &original_entry, sizeof(Elf64_Addr));
// Patch enc_addr (runtime VA of .text)
Elf64_Addr text_vaddr = text_section->sh_addr;
memcpy(meta + ENC_ADDR_OFFSET, &text_vaddr, sizeof(uint64_t));
// Patch enc_size
memcpy(meta + ENC_SIZE_OFFSET, &text_section->sh_size, sizeof(uint64_t));
// Patch key
memcpy(meta + KEY_OFFSET,     key, KEY_LEN);
```

#### 5.7 — Patch ELF headers in the woody buffer

```c
Elf64_Ehdr *woody_ehdr = (Elf64_Ehdr *)woody;
Elf64_Phdr *woody_phdrs = (Elf64_Phdr *)(woody + woody_ehdr->e_phoff);

// Find the last PT_LOAD in the woody buffer's program headers
Elf64_Phdr *last_load = find_last_load_segment(woody_ehdr);

// Update entry point
woody_ehdr->e_entry = inject_vaddr;

// Update segment sizes
last_load->p_filesz += stub_size;
last_load->p_memsz  += stub_size;
last_load->p_flags  |= PF_X;
```

#### 5.8 — Write the output file

```c
int out_fd = open("./woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
write(out_fd, woody, src_size + stub_size);
close(out_fd);
```

**File permissions:** `0755` (rwxr-xr-x) — the output must be executable.

#### 5.9 — Cleanup

```c
munmap(src_map, src_size);
free(woody);
close(src_fd);
free(stub_code);
```

---

## Phase 6: Verification & Testing

### Basic Test

```bash
make
./woody_woodpacker resources/sample
# Expected output:
#   KEY=<32 hex chars>

chmod +x ./woody
./woody
# Expected output:
#   ....WOODY....
#   Hello, World!
```

### Binary Correctness Checks

```bash
# Compare output of original and packed binary
./resources/sample > /tmp/original_output.txt
./woody > /tmp/woody_output.txt
diff /tmp/original_output.txt /tmp/woody_output.txt
# Should produce no output (files identical)

# Compare exit codes
./resources/sample; echo "exit: $?"
./woody; echo "exit: $?"
# Both should show: exit: 0
```

### Test Matrix

| Binary | Type | What to check |
|---|---|---|
| `resources/sample` | Simple hello-world (static) | Prints "Hello, World!", exit 0 |
| `/bin/ls` | System utility (dynamic) | Lists files correctly, exit 0 |
| `/bin/cat` | System utility (dynamic) | Reads stdin, exit 0 |
| `/bin/echo` | System utility (dynamic) | Echoes args, exit 0 |
| PIE binary (`gcc -pie`) | Shared object type | Loads at 0x0, works correctly |
| Non-PIE binary (`gcc -no-pie`) | Fixed address | Loads at 0x400000, works correctly |

### Debugging Tips

```bash
# Inspect the packed binary's ELF headers:
readelf -h ./woody          # Check e_entry points to extended segment
readelf -l ./woody          # Check PT_LOAD sizes, flags
readelf -S ./woody          # Check .text section is encrypted (high entropy)

# Use strace to verify syscalls:
strace ./woody 2>&1 | grep -E "write|execve"
# Should see: write(1, "....WOODY....\n", 14)
# Then: execve(...)

# Debug the stub with gdb:
gdb ./woody
(gdb) break _start    # may not work; use: b *<stub_address>
(gdb) x/20i $rip     # disassemble from current instruction
(gdb) stepi           # step through instructions
```

### Edge Cases to Handle

1. **`.text` not found** — fallback to encrypting the first `PT_LOAD` segment with `PF_X`
2. **File too small** — reject binaries smaller than ELF header + program headers
3. **Already packed** — detect if `.text` is already encrypted (check for high entropy or a magic marker)
4. **No room for stub** — if extending the segment would exceed page alignment, add padding

---

## Suggested Implementation Order

| Step | File(s) | Description | Test independently? |
|---|---|---|---|
| 1 | `srcs/elf_parser.c`, `includes/elf_parser.h` | Full ELF parsing: program headers, section headers, `.text` lookup, OEP | Yes — print parsed info |
| 2 | `srcs/encrypt.c`, `includes/encrypt.h` | RC4 KSA + PRGA + key generation | Yes — encrypt/decrypt a test buffer |
| 3 | `stub/decrypt.s` | Write, assemble, extract raw bytes | Yes — test in isolation with known ciphertext |
| 4 | `srcs/inject.c`, `includes/inject.h` | Extend segment, patch headers, build metadata | Yes — inject stub into test binary |
| 5 | `srcs/main.c` | Wire everything together: parse -> encrypt -> inject -> write | End-to-end test |
| 6 | Tests | Run full test matrix, debug with gdb | Final validation |

## Key Insight

Phases 3 and 4 are tightly coupled: the stub's metadata block (enc_addr, enc_size, key, OEP) must be hardcoded into the stub during injection. The stub references this metadata via RIP-relative addressing, which works regardless of where the stub is placed in memory. The injector patches these 40 bytes after copying the stub code into the output buffer.
