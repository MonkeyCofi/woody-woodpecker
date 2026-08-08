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
