# woody-woodpacker
A binary packer that takes an ELF64 file, encrypts it and injects code into it.

### ELF files
ELF stands for Executable and Linkable Format. These are programs that can be executed by the computer. In this project, we are only concerned with 64-bit ELF files. 

### run.sh
A script that builds and execute an alpine docker container that can be used to compile 32-bit binaries. It has a secret bonus feature that you can find out by reading the script

### Steps
The binary file is opened, and then mapped into memory using mmap(), which will store the contents of the file within the virtual space of the process calling mmap (in this case, woody_woodpacker). mmap returns the address wherein the loaded content lies. 

## Resources
[Handcrafting x86_64 ELF from specification to bytes](https://medium.com/@dassomnath/handcrafting-x64-elf-from-specification-to-bytes-9986b342eb89)