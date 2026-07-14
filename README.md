# woody-woodpecker
A binary packer that takes an ELF64 file, encrypts it and injects code into it.

### ELF files
ELF stands for Executable and Linkable Format. These are programs that can be executed by the computer. In this project, we are only concerned with 64-bit ELF files. 

### run.sh
A script that builds and execute an alpine docker container that can be used to compile 32-bit binaries. It has a secret bonus feature that you can find out by reading the script

## Resources
[Handcrafting x86_64 ELF from specification to bytes](https://medium.com/@dassomnath/handcrafting-x64-elf-from-specification-to-bytes-9986b342eb89)