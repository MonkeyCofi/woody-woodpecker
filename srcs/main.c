#include <stdio.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>

bool    valid_elf64(int file, void **file_map)
{
	off_t			size;
	Elf64_Ehdr  	*header;
	void			*ptr;
	unsigned char	*ident;

	size = lseek(file, 0, SEEK_END);
	ptr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_PRIVATE, file, 0);
	header = ptr;
	ident = (*header).e_ident;
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
		ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
	{
		fprintf(stderr, "Header lacks the magic number therefore not an ELF file\n");
		return false;
	}
	if (ident[EI_CLASS] != 2)
	{
		fprintf(stderr, "Binary file is not 64-bit\n");
		return false;
	}
	*file_map = ptr;
	return true;
}

int main(int ac, char **av)
{
	int		file;
	void	*file_map;

	if (ac != 2)
	{
		fprintf(stderr, "Usage: ./out <binary>\n");
		return 1;
	}
	file = open(av[1], O_RDONLY);
	if (file < 0)
		fprintf(stderr, "Failed to open binary file\n");
	valid_elf64(file, &file_map);
	return 0;
}