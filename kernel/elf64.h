#ifndef ELF64_H
#define ELF64_H

#include "misc.h"

#define ELF_AARCH64 183

struct elf64_header {
    uint32_t magic;
    byte_t bitness;
    byte_t endian;
    byte_t elfversion1;
    byte_t abi;
    byte_t abi_version;
    byte_t padding[7];
    uint16_t type;
    uint16_t machine;
    uint32_t elfversion2;
    qword_t entry_point;
    qword_t prghead_off;
    qword_t secthead_off;
    uint32_t flags;
    uint16_t header_size;
    uint16_t phent_size;
    uint16_t phent_count;
    uint16_t shent_size;
    uint16_t shent_count;
    uint16_t sectname_index;
};

struct prg64_header {
    uint32_t type;
    uint32_t flags;
    qword_t offset;
    qword_t vaddr;
    qword_t paddr;
    qword_t filesize;
    qword_t memsize;
    qword_t alignment;
};

struct aux64_ent {
    qword_t type;
    qword_t value;
};

#define AX64_PHDR 3
#define AX64_PHENT 4
#define AX64_PHNUM 5
#define AX64_PAGESZ 6
#define AX64_BASE 7
#define AX64_FLAGS 8
#define AX64_ENTRY 9
#define AX64_UID 11
#define AX64_EUID 12
#define AX64_GID 13
#define AX64_EGID 14
#define AX64_PLATFORM 15
#define AX64_HWCAP 16
#define AX64_CLKTCK 17
#define AX64_SECURE 23
#define AX64_RANDOM 25
#define AX64_HWCAP2 26
#define AX64_EXECFN 31
#define AX64_SYSINFO 32
#define AX64_SYSINFO_EHDR 33

#endif
