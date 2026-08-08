#include "elf_info.h"

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

bool    valid_elf64(e_elf_info *info)
{
	off_t			size;
	Elf64_Ehdr  	*header;
	void			*ptr;
	unsigned char	*ident;

	size = lseek(info->fd, 0, SEEK_END);
	ptr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_PRIVATE, info->fd, 0);
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
	info->file_map = ptr;
	info->ehdr = header;
	info->phtable = (Elf64_Phdr *)((char *)header + header->e_phoff);
	info->phentries = header->e_phnum;
	info->phentry_size = header->e_phentsize;
	info->shtable = (Elf64_Shdr *)((char *)header + header->e_shoff);
	info->shentries = header->e_shnum;
	info->shentry_size = header->e_shentsize;
	return true;
}

void	parse_phdrs(e_elf_info *info)
{
	Elf64_Phdr	*curr;

	for (int i = 0; i < info->phentries; i++)
	{
		curr = ((Elf64_Phdr *)((char *)info->phtable + (info->phentry_size * i)));
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

void    sections_in_segment(e_elf_info *info, Elf64_Phdr *segment)
{
    // go through every section. check if each section's file size is within the 
    for (int i = 0; i < info->shentries; i++)
    {
        Elf64_Shdr  *current = &info->shtable[i];
        // check section file offset and make sure its within the bounds
        int fsize = (current->sh_type != SHT_NOBITS) && (current->sh_offset >= segment->p_offset) && \
                    ((current->sh_offset + current->sh_size) <= (segment->p_offset + segment->p_filesz));
        // sections like .bss (NOBITS) have an sh_size but occupy 0 bytes in the file
        // if the type is PT_LOAD and the section's addr is within the program's vaddr, and the 
        int memspace = (segment->p_type == PT_LOAD) && (current->sh_addr >= segment->p_vaddr) && \
                        ((current->sh_size + current->sh_offset) <= (segment->p_vaddr + segment->p_memsz));
        if (fsize || memspace)
        {
            printf("Section name: %s\n", get_sh_type_str(current->sh_type));
        }
    }
}