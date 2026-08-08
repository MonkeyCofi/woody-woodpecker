#include "elf_info.h"

Elf64_Phdr	*find_last_load_segment(Elf64_Ehdr *ehdr)
{
	Elf64_Phdr	*phdrs;
	Elf64_Phdr	*curr;
	Elf64_Half	entries;
	Elf64_Phdr	*last_segment;

	phdrs = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
	entries = ehdr->e_phnum;
	last_segment = NULL;
	for (int i = 0; i < entries; i++)
	{
		curr = ((Elf64_Phdr *)((char *)phdrs + (ehdr->e_phentsize * i)));
		if (curr->p_type == PT_LOAD)
			last_segment = &phdrs[i];
	}
	return last_segment;
}

int main(int ac, char **av)
{
	e_elf_info	info;

	if (ac != 2)
	{	
		fprintf(stderr, "Usage: ./out <binary>\n");
		return 1;
	}
	info.fd = open(av[1], O_RDONLY);
	if (info.fd < 0)
		fprintf(stderr, "Failed to open binary file\n");
	if (valid_elf64(&info) == false)
		return 1;
	// after receiving all ELF file information, 
	return 0;
}