# Approach: woody_woodpacker

A binary packer that encrypts an ELF64 binary and injects a decryption stub, producing a new `woody` executable that self-decrypts at runtime.

## Current Status

Basic ELF64 header validator in `srcs/main.c` that:
- Opens and memory-maps the target binary
- Checks the ELF magic number (`\x7fELF`)
- Verifies 64-bit class (`EI_CLASS == 2`)

## Phase 1: Deep ELF Parsing

Parse more than just the ELF header. Minimum requirements:

- **Program Headers** (`Elf64_Phdr`) — iterate via `e_phoff` / `e_phnum`. Identify `PT_LOAD` segments: the text segment (`PF_X | PF_R`) and data segment (`PF_R | PF_W`).
- **Section Headers** (`Elf64_Shdr`) — iterate via `e_shoff` / `e_shnum`. Locate `.text` (or another executable section) to determine what to encrypt.
- **Entry point** (`e_entry`) — save the original entry point (OEP); it will be redirected to the injected payload.

Helper functions to write:
```c
Elf64_Phdr *find_text_segment(Elf64_Ehdr *ehdr);
Elf64_Shdr *find_section(Elf64_Ehdr *ehdr, const char *name);
```

## Phase 2: Encryption Algorithm & Key Generation

Choose a real cipher (ROT is explicitly rejected by the subject).

| Algorithm | Complexity | Notes |
|---|---|---|
| XOR (multi-byte key) | Low | Simple but justifiable with a long random key |
| RC4 | Medium | Stream cipher, ~20 lines of C, reasonable strength |
| AES | High | Complex implementation, impressive for evaluation |

The subject mandates:
- Random key generation (as random as possible)
- Key printed to stdout during packing
- The key is embedded in the output binary for the stub to use

## Phase 3: The Decryption Stub (Assembly Payload)

This is the hardest part. Hand-written x86-64 position-independent assembly that gets injected into the target binary.

The stub must:

1. **Print** `"....WOODY....\n"` via the `write` syscall (to indicate the binary is packed)
2. **Decrypt** the encrypted region in memory — loop over encrypted bytes applying the inverse cipher
3. **Jump** to the original entry point (OEP)

Written in a `.s` file using RIP-relative addressing (no absolute addresses, since the stub's final location is unknown at assembly time):

```asm
; sys_write "....WOODY....\n"
mov rax, 1        ; SYS_write
mov rdi, 1        ; stdout
lea rsi, [rip + msg]
mov rdx, 14       ; length
syscall

; decryption loop
lea rsi, [rip + enc_start]
mov rcx, enc_size
dec_loop:
  ...
  loop dec_loop

; jump to OEP
mov rax, OEP
jmp rax
```

The stub must embed or reference:
- The encrypted data offset (relative to stub)
- The encrypted data size
- The decryption key
- The OEP

## Phase 4: Injection Strategy

Choose where to place the stub in the target binary.

| Approach | Pros | Cons |
|---|---|---|
| **Extend last `PT_LOAD`** | Clean, reliable | Requires page-aligning, may bloat file |
| **Code cave** (padding gaps) | No file size increase | Hard to find enough contiguous bytes, fragile |
| **Add new `PT_LOAD` segment** | Most flexible | Complex ELF manipulation |

**Recommended approach for this project:** Extend the last loadable segment. Increase `p_filesz` / `p_memsz`, place stub + encrypted data after the original content, update `e_entry` to point to the stub.

## Phase 5: Binary Reconstruction

Steps to produce the `woody` output file:

1. **Copy** the original ELF into a new buffer
2. **Encrypt** the `.text` section (or text segment) in-place
3. **Inject** the decryption stub at the extension point
4. **Patch** the ELF header:
   - `e_entry` → address of the stub
   - Last `PT_LOAD` segment: update `p_filesz` / `p_memsz`
5. **Embed metadata** (key, encrypted region offset, encrypted region size) where the stub can find it — typically immediately before or after the stub code
6. **Write** the result to `./woody`

## Phase 6: Verification & Testing

```bash
./woody_woodpacker /bin/ls
# => prints: KEY=<random_hex>
# => generates: ./woody

chmod +x ./woody
./woody
# => "....WOODY...."
# => runs ls identically (same output, same exit code)
```

Test with various ELF64 binaries:
- Simple hello-world (test.c / resources/sample.c compiled)
- System binaries (`/bin/ls`, `/bin/cat`, `/bin/echo`)
- Ensure no crashes, identical stdout/stderr, and identical exit codes

## Suggested Implementation Order

1. **Expand ELF parser** — program headers, section headers, `.text` lookup, OEP extraction
2. **Write encryption module** — cipher implementation + key generation (test standalone)
3. **Write decryption stub in assembly** — assemble, extract raw bytes, test in isolation
4. **Implement injection** — modify ELF, extend segment, patch entry point
5. **Wire everything together** — encrypt → inject → write `woody`
6. **Test, debug, refine**

## Key Insight

Phases 3 and 4 are tightly coupled: the stub's metadata (offset to encrypted data, size, key, OEP) must be hardcoded into the stub during injection. The stub reads this metadata via RIP-relative addressing at runtime.
