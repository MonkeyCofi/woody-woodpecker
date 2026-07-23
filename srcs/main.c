#include <stdio.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <string.h>

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
		case PT_LOOS:
			return ("PT_LOOS");
		case PT_HIOS:
			return ("PT_HIOS");
		case PT_LOPROC:
			return ("PT_LOPROC");
		case PT_HIPROC:
			return ("PT_HIPROC");
		case PT_GNU_PROPERTY:
			return ("GNU_PROPERTY");
		case PT_GNU_EH_FRAME:
			return ("GNU_EH_FRAME");
		case PT_GNU_STACK:
			return ("GNU_STACK");
		case PT_GNU_RELRO:
			return ("GNU_RELRO");
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
		case 5:
			return ("PF_R + PF_X: Read, execute");
		case 6:
			return ("PF_R + PF_W: Read, write");
		case 7:
			return ("PF_R + PF_W + PF_X: Read, write, execute");
		default:
			return ("no idea");
	}
}

const char	*get_sh_type_str(Elf64_Word flag)
{
	switch (flag)
	{
		case SHT_NULL:
			return ("SHT_NULL");
		case SHT_PROGBITS:
			return ("SHT_PROGBITS");
		case SHT_SYMTAB:
			return ("SHT_SYMTAB");
		case SHT_STRTAB:
			return ("SHT_STRTAB");
		case SHT_RELA:
			return ("SHT_RELA");
		case SHT_HASH:
			return ("SHT_HASH");
		case SHT_DYNAMIC:
			return ("SHT_DYNAMIC");
		case SHT_NOTE:
			return ("SHT_NOTE");
		case SHT_NOBITS:
			return ("SHT_NOBITS");
		case SHT_REL:
			return ("SHT_REL");
		case SHT_SHLIB:
			return ("SHT_SHLIB");
		case SHT_DYNSYM:
			return ("SHT_DYNSYM");
		case SHT_INIT_ARRAY:
			return ("SHT_INIT_ARRAY");
		case SHT_FINI_ARRAY:
			return ("SHT_FINI_ARRAY");
		case SHT_PREINIT_ARRAY:
			return ("SHT_PREINIT_ARRAY");
		case SHT_GROUP:
			return ("SHT_GROUP");
		case SHT_SYMTAB_SHNDX:
			return ("SHT_SYMTAB_SHNDX");
		case SHT_NUM:
			return ("SHT_NUM");
		case SHT_LOOS:
			return ("SHT_LOOS");
		default:
			return ("Unknown");
	}
}

void	parse_phdrs(void *map, Elf64_Ehdr *ehdr)
{
	Elf64_Phdr	*phtable;

	phtable = map + ehdr->e_phoff;	// the start of the program header table
	Elf64_Half entsize = ehdr->e_phentsize;
	Elf64_Half entries = ehdr->e_phnum;
	printf("Each entry is of size %d and there are %d entries\n", entsize, entries);
	for (int i = 0; i < entries; i++)
	{
		Elf64_Phdr *curr = ((Elf64_Phdr *)((char *)phtable + (entsize * i)));
		printf("--------------\n");
		printf("Entry %d\n", i);
		printf("program header type %s\n", p_type_string(curr->p_type));
		printf("The flags are %s\n", p_flag(curr->p_flags));
		printf("Virtual address: %p\n", (void *)curr->p_vaddr);
		printf("Physical address: %p\n", (void *)curr->p_paddr);
		printf("File size %ld\n", curr->p_filesz);
		printf("Memory size %ld\n", curr->p_memsz);
		printf("Align %ld\n", curr->p_align);
		printf("Offset: %ld\n", curr->p_offset);
		printf("--------------\n\n");
	}
}

void	parse_shdrs(void *map, Elf64_Ehdr *ehdr)
{
	Elf64_Shdr	*shtable;
	Elf64_Shdr	*shstrtable;
	Elf64_Half	entsize;
	Elf64_Half	entries;
	Elf64_Half	shstrndx;
	char		*names;
	
	shtable = map + ehdr->e_shoff;
	entsize = ehdr->e_shentsize;
	entries = ehdr->e_shnum;
	shstrndx = ehdr->e_shstrndx;
	shstrtable = (Elf64_Shdr *)((char *)shtable + (entsize * shstrndx));
	names = (char *)ehdr + shstrtable->sh_offset;
	for (int i = 0; i < entries; i++)
	{
		printf("section %s\n", &names[shtable[i].sh_name]);
	}
}

Elf64_Shdr *find_section(Elf64_Ehdr *ehdr, const char *name)
{
	Elf64_Shdr	*shstrtable;
	Elf64_Shdr	*sections;
	char		*strtab;

	shstrtable = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff)
							+ ehdr->e_shstrndx;
	strtab = (char *)ehdr + shstrtable->sh_offset;
	sections = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff);
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		if (strcmp(&strtab[sections[i].sh_name], name) == 0)
			return &sections[i];
	}
	return NULL;
}

int main(int ac, char **av)
{
	int			file;
	void		*file_map;
	Elf64_Ehdr	*ehdr;
	Elf64_Shdr	*text;

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
	parse_phdrs(file_map, ehdr);
	parse_shdrs(file_map, ehdr);
	text = find_section(ehdr, ".text");
	if (text == NULL)
		fprintf(stderr, "No .text section\n");
	else
		printf(".text section found\n");
	return 0;
}