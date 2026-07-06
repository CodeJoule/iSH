#include "emu/cpu.h"
#include "emu/tlb.h"

int aarch64_run_to_interrupt(struct cpu_state *cpu, struct tlb *tlb);

int cpu_run_to_interrupt(struct cpu_state *cpu, struct tlb *tlb) {
    return aarch64_run_to_interrupt(cpu, tlb);
}
