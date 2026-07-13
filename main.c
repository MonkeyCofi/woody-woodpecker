#include <stdio.h>
#include <elf.h>
#include <stdbool.h>

bool    valid_elf64(FILE *fp)
{
	Elf64_Ehdr  header;
	char		ABI;

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

int main(int ac, char **av)
{
	if (ac != 2)
	{
		fprintf(stderr, "Usage: ./out <binary>\n");
		return 1;
	}
	FILE *fp = fopen(av[1], "rb");
	if (!fp)
	{
		fprintf(stderr, "Failed to open binary file\n");
		return 1;
	}
	valid_elf64(fp);
	return 0;
}