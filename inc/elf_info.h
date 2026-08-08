#ifndef ELF_INFO_H
# define ELF_INFO_H

# include <stdio.h>
# include <elf.h>
# include <stdbool.h>
# include <unistd.h>

# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>

# include <sys/mman.h>
# include <string.h>

typedef struct s_elf_info
{
	int			fd;
	void		*file_map;
	Elf64_Ehdr	*ehdr;
	Elf64_Shdr	*shtable;
	Elf64_Half	shentry_size;
	Elf64_Half	shentries;
	Elf64_Phdr	*phtable;
	Elf64_Half	phentry_size;
	Elf64_Half	phentries;
	Elf64_Addr	*origin_entry;
	Elf64_Shdr	*load_segment;
}	e_elf_info;

bool    	valid_elf64(e_elf_info *info);
void		parse_phdrs(e_elf_info *info);
void		parse_shdrs(void *map, Elf64_Ehdr *ehdr);
void    	sections_in_segment(e_elf_info *info, Elf64_Phdr *segment);

Elf64_Shdr *find_section(Elf64_Ehdr *ehdr, const char *name);

// utilities
const char	*get_sh_type_str(Elf64_Word flag);
const char	*p_type_string(Elf64_Word type);
const char	*p_flag(Elf64_Word flag);

#endif