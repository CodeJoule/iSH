#include <string.h>
#include "kernel/signal-aarch64.h"
#include "guest/interrupt.h"

void aarch64_setup_sigcontext(struct sigcontext_aarch64 *sc, struct cpu_state *cpu) {
    memset(sc, 0, sizeof(*sc));
    for (int i = 0; i < 31; i++)
        sc->regs[i] = cpu->x[i];
    sc->sp = cpu->sp;
    sc->pc = cpu->pc;
    sc->pstate = cpu->pstate;
    if (cpu->trapno == INT_GPF)
        sc->fault_address = cpu->segfault_addr;
}

void aarch64_restore_sigcontext(struct sigcontext_aarch64 *context, struct cpu_state *cpu) {
    for (int i = 0; i < 31; i++)
        cpu->x[i] = context->regs[i];
    cpu->sp = context->sp;
    cpu->pc = context->pc;
    cpu->pstate = context->pstate;
}
