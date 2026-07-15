# Objective

The goal of this project is to code a program that will at first encrypt a program given
as parameter. Only 64 bits ELF files will be managed here.
A new program called woody will be generated from this execution. When this new
program (woody) will be executed, it will have to be decrypted to be run. Its execution
has to be totally identical to the program given as parameter in the last step.
Even though we won’t get into compression possibilities directly in this subject, we
strongly advise you to explore the possible methods!

## Implementation Instructions
Within the mandatory part, you are allowed to use the following functions:
◦ open, close, exit
◦ fpusts, fflush, lseek
◦ mmap, munmap, mprotect
◦ perror, strerror
◦ syscall
◦ the functions of the printf family
◦ the function authorized within your libft (read, write, malloc, free, for exam-
ple)

## Main Part
The executable must be named woody_woodpacker.
• Your program takes a binary file parameter (64 bits ELF only).
• At the end of the execution of your program, a second file will be created named
woody
• You are free to choose the encryption algorithm.

(The complexity of your algorithm will nonetheless be a very important
part of the grading. You have to justify your choice during the
evaluation. An easy ROT isn’t considered an advanced algorithm !)

• In the case of an algorithm based on an encryption key, it will have to be generated
the most randomly possible. It will be displayed on the standard output when
running the main program.
• When running the encrypted program, it will have to display the string “....WOODY....”,
followed by a newline, to indicate that the binary is encrypted. Its execution after
decryption must not be altered.
• Obviously, in no way the encrypted program is allowed to crash.
• Your program mustn’t modify the execution of the final binary produced, it must
be identical to the binary given as parameter to woody-woodpacker