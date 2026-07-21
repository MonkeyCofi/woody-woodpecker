#include <stdio.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>

bool    valid_elf64(int file, void **file_map, Elf64_Ehdr **ehdr)
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
	*ehdr = header;
	return true;
}

const char *p_type_string(Elf64_Word type)
{
	switch(type)
	{
		case PT_NULL:
			return ("NULL");
		case PT_LOAD:
			return ("PT_LOAD");
		case PT_DYNAMIC:
			return ("PT_DYNAMIC");
		case PT_INTERP:
			return ("PT_INTERP");
		case PT_NOTE:
			return ("PT_NOTE");
		case PT_SHLIB:
			return ("PT_SHLIB");
		case PT_PHDR:
			return ("PT_PHDR");
		case PT_TLS:
			return ("PT_TLS");
		default:
			return ("Unknown");
	}
}

const char	*p_flag(Elf64_Word flag)
{
	switch(flag)
	{
		case 0:
			return ("No access");
		case 1:
			return ("PF_X: Execute only");
		case 2:
			return ("PF_W: Write only");
		case 3:
			return ("PF_W + PF_X: Read and execute");
		case 4:
			return ("PF_R: Read only");
		default:
			return ("no idea");
	}
}

void	parse_phdr(int file, void *map, Elf64_Ehdr *ehdr)
{
	Elf64_Phdr	*phdr;

	// get the program header, which i assume so far is right after the Elf_64_Ehdr
	phdr = map + ehdr->e_phoff;
	printf("The current segment is of type %s\n", p_type_string(phdr->p_type));
	printf("The flags are %s\n", p_flag(phdr->p_flags));
	(void)file;
	(void)map;
	(void)phdr;
}

int main(int ac, char **av)
{
	int			file;
	void		*file_map;
	Elf64_Ehdr	*ehdr;

	if (ac != 2)
	{
		fprintf(stderr, "Usage: ./out <binary>\n");
		return 1;
	}
	file = open(av[1], O_RDONLY);
	if (file < 0)
		fprintf(stderr, "Failed to open binary file\n");
	valid_elf64(file, &file_map, &ehdr);
	printf("there are %d program header entries each of size %d\n", ehdr->e_phnum, ehdr->e_phentsize);
	printf("there are %d section header entries each of size %d\n", ehdr->e_shnum, ehdr->e_shentsize);
	parse_phdr(file, file_map, ehdr);
	Elf64_Shdr *shdr = ehdr + ehdr->e_shoff;
	Elf64_Shdr *table = shdr + ehdr->e_shstrndx;
	printf("%s\n", (char *)table);
	return 0;
}