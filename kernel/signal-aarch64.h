#ifndef SIGNAL_AARCH64_H
#define SIGNAL_AARCH64_H

#include "kernel/signal.h"
#include "emu/cpu.h"

struct sigcontext_aarch64 {
    qword_t fault_address;
    qword_t regs[31];
    qword_t sp;
    qword_t pc;
    qword_t pstate;
    union {
        byte_t __reserved[512];
    };
};

struct ucontext_aarch64 {
    qword_t flags;
    qword_t link;
    struct stack_t_ stack;
    struct sigcontext_aarch64 mcontext;
    sigset_t_ sigmask;
} __attribute__((packed));

struct rt_sigframe_aarch64 {
    qword_t restorer;
    int_t sig;
    qword_t pinfo;
    qword_t puc;
    union {
        struct siginfo_ info;
        char __pad[128];
    };
    struct ucontext_aarch64 uc;
    char retcode[8];
};

void aarch64_setup_sigcontext(struct sigcontext_aarch64 *sc, struct cpu_state *cpu);
void aarch64_restore_sigcontext(struct sigcontext_aarch64 *context, struct cpu_state *cpu);

#endif
