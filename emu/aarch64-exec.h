#ifndef AARCH64_EXEC_H
#define AARCH64_EXEC_H

#include "emu/cpu.h"
#include "emu/tlb.h"

/* Execute one AArch64 instruction at pc. Updates cpu->pc unless returning fault. */
int aarch64_exec_insn(struct cpu_state *cpu, struct tlb *tlb, addr_t pc, uint32_t insn);

/* True if this instruction ends a basic block at compile time. */
bool aarch64_insn_ends_block(uint32_t insn);

#endif
