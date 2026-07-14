#include <stdio.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>

bool    valid_elf64(int file)
{
	off_t		size;
	Elf64_Ehdr  header;
	char		ABI;
	void		*ptr;

	size = lseek(file, 0, SEEK_END);
	// map the file into memory
	ptr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_PRIVATE, file, 0);
	if (ptr == MAP_FAILED)
	{
		fprintf(stderr, "failed to map file into memory\n");
		return false;
	}
	if (fread(&header, 1, sizeof(Elf64_Ehdr), fp) != sizeof(Elf64_Ehdr))
	{
		fprintf(stderr, "File is missing Elf64 header\n");
		return false;
	}
	fclose(fp);
	if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 ||
		header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3)
	{
		fprintf(stderr, "Header lacks the magic number therefore not an ELF file\n");
		return false;
	}
	if (header.e_ident[EI_CLASS] != 2)
	{
		fprintf(stderr, "Binary file is not 64-bit\n");
		return false;
	}
	printf("File is an ELF-64 binary\n");
	ABI = header.e_ident[EI_OSABI];
	printf("%d\n", ABI);
	return true;
}

// 

int main(int ac, char **av)
{
	int		file;

	if (ac != 2)
	{
		fprintf(stderr, "Usage: ./out <binary>\n");
		return 1;
	}
	file = open(av[1], O_RDONLY);
	if (file < 0)
		fprintf(stderr, "Failed to open binary file\n");
	valid_elf64(file);
	return 0;
}