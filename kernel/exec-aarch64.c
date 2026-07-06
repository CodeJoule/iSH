#include "kernel/signal.h"
#include "task.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "kernel/calls.h"
#include "kernel/random.h"
#include "kernel/errno.h"
#include "fs/fd.h"
#include "kernel/elf.h"
#include "kernel/elf64.h"
#include "kernel/vdso.h"
#include "tools/ptraceomatic-config.h"

#define ARGV_MAX 32 * PAGE_SIZE

struct exec_args {
    size_t count;
    const char *args;
};

static inline qword_t align_stack(qword_t sp) {
    return sp & ~0xf;
}

static inline int user_memset64(addr_t start, byte_t val, qword_t len) {
    for (qword_t i = 0; i < len; i++) {
        if (user_put(start + i, val))
            return 1;
    }
    return 0;
}

static inline qword_t copy_string64(qword_t sp, const char *string) {
    size_t len = strlen(string) + 1;
    sp -= len;
    if (user_write(sp, string, len))
        return 0;
    return sp;
}

static inline qword_t args_copy64(qword_t sp, struct exec_args args) {
    const char *p = args.args;
    for (size_t i = 0; i < args.count; i++) {
        sp = copy_string64(sp, p);
        if (sp == 0)
            return 0;
        p += strlen(p) + 1;
    }
    return sp;
}

static size_t args_size64(struct exec_args args) {
    size_t size = 0;
    const char *p = args.args;
    for (size_t i = 0; i < args.count; i++) {
        size += strlen(p) + 1;
        p += strlen(p) + 1;
    }
    return size;
}

static int read_header64(struct fd *fd, struct elf64_header *header) {
    if (fd->ops->lseek(fd, 0, SEEK_SET))
        return _EIO;
    if (fd->ops->read(fd, header, sizeof(*header)) != sizeof(*header))
        return _ENOEXEC;
    if (memcmp(&header->magic, ELF_MAGIC, 4) != 0
            || (header->type != ELF_EXECUTABLE && header->type != ELF_DYNAMIC)
            || header->bitness != ELF_64BIT
            || header->endian != ELF_LITTLEENDIAN
            || header->elfversion1 != 1
            || header->machine != ELF_AARCH64)
        return _ENOEXEC;
    return 0;
}

static int read_prg_headers64(struct fd *fd, struct elf64_header header, struct prg64_header **ph_out) {
    ssize_t ph_size = sizeof(struct prg64_header) * header.phent_count;
    struct prg64_header *ph = malloc(ph_size);
    if (ph == NULL)
        return _ENOMEM;
    if (fd->ops->lseek(fd, header.prghead_off, SEEK_SET) < 0) {
        free(ph);
        return _EIO;
    }
    if (fd->ops->read(fd, ph, ph_size) != ph_size) {
        free(ph);
        return _ENOEXEC;
    }
    *ph_out = ph;
    return 0;
}

static int load_entry64(struct prg64_header ph, addr_t bias, struct fd *fd) {
    addr_t addr = ph.vaddr + bias;
    addr_t offset = ph.offset;
    qword_t memsize = ph.memsize;
    qword_t filesize = ph.filesize;

    int flags = P_READ;
    if (ph.flags & PH_W) flags |= P_WRITE;

    int err = fd->ops->mmap(fd, current->mem, PAGE(addr),
            PAGE_ROUND_UP(filesize + PGOFFSET(addr)),
            offset - PGOFFSET(addr), flags, MMAP_PRIVATE);
    if (err < 0)
        return err;

    mem_pt(current->mem, PAGE(addr))->data->fd = fd_retain(fd);
    mem_pt(current->mem, PAGE(addr))->data->file_offset = offset - PGOFFSET(addr);

    if (memsize > filesize) {
        qword_t bss_size = memsize - filesize;
        addr_t file_end = addr + filesize;
        qword_t tail_size = PAGE_SIZE - PGOFFSET(file_end);
        if (tail_size == PAGE_SIZE)
            tail_size = 0;
        if (tail_size != 0) {
            write_wrunlock(&current->mem->lock);
            user_memset64(file_end, 0, tail_size);
            write_wrlock(&current->mem->lock);
        }
        if (tail_size > bss_size)
            tail_size = bss_size;
        if (bss_size - tail_size != 0) {
            err = pt_map_nothing(current->mem, PAGE_ROUND_UP(addr + filesize),
                    PAGE_ROUND_UP(bss_size - tail_size), flags);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static addr_t find_hole_for_elf64(struct elf64_header *header, struct prg64_header *ph) {
    struct prg64_header *first = NULL, *last = NULL;
    for (int i = 0; i < header->phent_count; i++) {
        if (ph[i].type == PT_LOAD) {
            if (first == NULL)
                first = &ph[i];
            last = &ph[i];
        }
    }
    pages_t size = 0;
    if (first != NULL) {
        pages_t a = PAGE_ROUND_UP(last->vaddr + last->memsize);
        pages_t b = PAGE(first->vaddr);
        size = a - b;
    }
    page_t hole = pt_find_hole(current->mem, size);
    if (hole == BAD_PAGE)
        return 0;
    return (addr_t) hole << PAGE_BITS;
}

int elf_exec_aarch64(struct fd *fd, const char *file, struct exec_args argv, struct exec_args envp) {
    int err = 0;
    struct elf64_header header;
    if ((err = read_header64(fd, &header)) < 0)
        return err;
    struct prg64_header *ph;
    if ((err = read_prg_headers64(fd, header, &ph)) < 0)
        return err;

    lock(&current->general_lock);
    mm_release(current->mm);
    task_set_mm(current, mm_new());
    unlock(&current->general_lock);
    write_wrlock(&current->mem->lock);

    current->mm->exefile = fd_retain(fd);

    addr_t load_addr = 0;
    bool load_addr_set = false;
    addr_t bias = 0;

    for (unsigned i = 0; i < header.phent_count; i++) {
        if (ph[i].type != PT_LOAD)
            continue;
        if (!load_addr_set && header.type == ELF_DYNAMIC)
            bias = find_hole_for_elf64(&header, ph);
        if ((err = load_entry64(ph[i], bias, fd)) < 0)
            goto beyond_hope;
        if (!load_addr_set) {
            load_addr = bias + ph[i].vaddr - ph[i].offset;
            load_addr_set = true;
        }
        addr_t brk = bias + ph[i].vaddr + ph[i].memsize;
        if (brk > current->mm->start_brk)
            current->mm->start_brk = current->mm->brk = BYTES_ROUND_UP(brk);
    }

    addr_t entry = bias + header.entry_point;

    pages_t vdso_pages = sizeof(vdso_data) >> PAGE_BITS;
    page_t vdso_page = pt_find_hole(current->mem, vdso_pages + 1);
    if (vdso_page == BAD_PAGE) {
        err = _ENOMEM;
        goto beyond_hope;
    }
    vdso_page += 1;
    if ((err = pt_map(current->mem, vdso_page, vdso_pages, (void *) vdso_data, 0, P_READ | P_EXEC)) < 0)
        goto beyond_hope;
    mem_pt(current->mem, vdso_page)->data->name = "[vdso]";
    current->mm->vdso = (addr_t) vdso_page << PAGE_BITS;
    addr_t vdso_entry = current->mm->vdso + ((struct elf64_header *) vdso_data)->entry_point;

    page_t vvar_page = pt_find_hole(current->mem, VVAR_PAGES);
    if (vvar_page == BAD_PAGE) {
        err = _ENOMEM;
        goto beyond_hope;
    }
    if ((err = pt_map_nothing(current->mem, vvar_page, VVAR_PAGES, 0)) < 0)
        goto beyond_hope;
    mem_pt(current->mem, vvar_page)->data->name = "[vvar]";

    /* AArch64 stack near top of user VA */
    page_t stack_page = 0xfffff;
    if ((err = pt_map_nothing(current->mem, stack_page, 1, P_WRITE | P_GROWSDOWN)) < 0)
        goto beyond_hope;
    write_wrunlock(&current->mem->lock);

    qword_t sp = ((qword_t) stack_page << PAGE_BITS) + PAGE_SIZE;
    sp -= sizeof(qword_t);

    addr_t file_addr = sp = copy_string64(sp, file);
    if (sp == 0) goto beyond_hope;
    addr_t envp_addr = sp = args_copy64(sp, envp);
    if (sp == 0) goto beyond_hope;
    current->mm->argv_end = sp;
    addr_t argv_addr = sp = args_copy64(sp, argv);
    if (sp == 0) goto beyond_hope;
    current->mm->argv_start = sp;
    sp = align_stack(sp);

    addr_t platform_addr = sp = copy_string64(sp, "aarch64");
    if (sp == 0) goto beyond_hope;

    char random[16] = {};
    get_random(random, sizeof(random));
    addr_t random_addr = sp -= sizeof(random);
    if (user_put(sp, random))
        goto beyond_hope;

    size_t argc = argv.count;
    size_t envc = envp.count;
    struct aux64_ent aux[] = {
        {AX64_SYSINFO, vdso_entry},
        {AX64_SYSINFO_EHDR, current->mm->vdso},
        {AX64_HWCAP, 0},
        {AX64_PAGESZ, PAGE_SIZE},
        {AX64_CLKTCK, 0x64},
        {AX64_PHDR, load_addr + header.prghead_off},
        {AX64_PHENT, sizeof(struct prg64_header)},
        {AX64_PHNUM, header.phent_count},
        {AX64_BASE, 0},
        {AX64_FLAGS, 0},
        {AX64_ENTRY, bias + header.entry_point},
        {AX64_UID, 0},
        {AX64_EUID, 0},
        {AX64_GID, 0},
        {AX64_EGID, 0},
        {AX64_SECURE, 0},
        {AX64_RANDOM, random_addr},
        {AX64_HWCAP2, 0},
        {AX64_EXECFN, file_addr},
        {AX64_PLATFORM, platform_addr},
        {0, 0},
    };

    size_t aux_count = 0;
    while (aux[aux_count].type != 0)
        aux_count++;

    size_t stack_words = argc + 1 + envc + 1 + 1 + aux_count * 2 + 2;
    qword_t stack_data_size = stack_words * sizeof(qword_t);
    sp = align_stack(sp - stack_data_size);

    qword_t *stack = calloc(1, stack_data_size);
    if (stack == NULL) {
        err = _ENOMEM;
        goto beyond_hope;
    }

    size_t idx = 0;
    stack[idx++] = argc;
    for (size_t i = 0; i < argc; i++) {
        const char *p = argv.args;
        for (size_t j = 0; j < i; j++)
            p += strlen(p) + 1;
        stack[idx++] = argv_addr + (p - argv.args);
    }
    stack[idx++] = 0;
    for (size_t i = 0; i < envc; i++) {
        const char *p = envp.args;
        for (size_t j = 0; j < i; j++)
            p += strlen(p) + 1;
        stack[idx++] = envp_addr + (p - envp.args);
    }
    stack[idx++] = 0;
    for (size_t i = 0; i < aux_count; i++) {
        stack[idx++] = aux[i].type;
        stack[idx++] = aux[i].value;
    }
    stack[idx++] = 0;
    stack[idx++] = 0;

    if (user_write(sp, stack, idx * sizeof(qword_t))) {
        free(stack);
        err = _EFAULT;
        goto beyond_hope;
    }
    free(stack);

    current->cpu.pc = entry;
    current->cpu.sp = sp;
    current->cpu.x[0] = sp;
    memset(&current->cpu.x[1], 0, sizeof(current->cpu.x) - sizeof(current->cpu.x[0]));
    current->cpu.pstate = 0;

    free(ph);
    return 0;

beyond_hope:
    write_wrunlock(&current->mem->lock);
    free(ph);
    return err;
}
