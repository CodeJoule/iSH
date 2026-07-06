#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/elf.h"
#include "guest/guest-config.h"
#if GUEST_AARCH64
#include "kernel/elf64.h"
#endif
#include "kernel/vdso.h"

__asm__(".data\n"
        ".global vdso_data\n"
        "vdso_data:\n"
        ".incbin \"vdso/libvdso.so.elf\"\n"
        ".skip "str(VDSO_PAGES)" * (1 << 12) - (. - vdso_data)\n");

int vdso_symbol(const char *name) {
#if GUEST_AARCH64
    struct elf64_header *header = (void *) vdso_data;
    struct prg64_header *ph = (void *) ((char *) header + header->prghead_off);
    struct dyn_ent {
        qword_t tag;
        qword_t val;
    } *dyn = NULL;
    for (int i = 0; i < header->phent_count; i++) {
        if (ph[i].type == PT_DYNAMIC) {
            dyn = (void *) ((char *) header + ph[i].offset);
            break;
        }
    }
#else
    struct elf_header *header = (void *) vdso_data;
    struct prg_header *ph = (void *) ((char *) header + header->prghead_off);
    struct dyn_ent *dyn = NULL;
    for (int i = 0; i < header->phent_count; i++) {
        if (ph[i].type == PT_DYNAMIC) {
            dyn = (void *) ((char *) header + ph[i].offset);
            break;
        }
    }
#endif
    if (dyn == NULL)
        goto fail;

    char *strings = NULL;
    struct elf_sym *syms = NULL;
    uint32_t *hash = NULL;
    for (; dyn->tag != DT_NULL; dyn++) {
        void *p = (char *) header + dyn->val;
        if (dyn->tag == DT_STRTAB)
            strings = p;
        else if (dyn->tag == DT_SYMTAB)
            syms = p;
        else if (dyn->tag == DT_HASH)
            hash = p;
    }
    if (strings == NULL || syms == NULL || hash == NULL)
        goto fail;

    int num_syms = hash[1];
    for (int i = 0; i < num_syms; i++) {
        char *sym_name = strings + syms[i].name;
        if (strcmp(name, sym_name) == 0)
            return syms[i].value;
    }
    return 0;

fail:
    // It shouldn't be possible to actually end up with an invalid vsdo compiled in
    fflush(stdout);
    fprintf(stderr, "invalid vdso. this should never happen.\n");
    fflush(stderr);
    abort();
}
