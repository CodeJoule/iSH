#include <stdint.h>
#include "asbestos/gadgets-guest-aarch64/gadgets.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

#define GADGET_CONTINUE A64_GADGET_CONTINUE
#define GADGET_END_BLOCK A64_GADGET_END_BLOCK
#define GADGET_INTERRUPT A64_GADGET_INTERRUPT

static int gadget_interrupt_emit(struct fiber_frame *frame, int interrupt, addr_t pc, addr_t addr) {
    frame->cpu.pc = pc;
    frame->cpu.segfault_addr = addr;
    frame->cpu.segfault_was_write = false;
    return GADGET_INTERRUPT | (interrupt << 8);
}

static inline qword_t read_x(struct cpu_state *cpu, unsigned reg) {
    if (reg == 31)
        return cpu->sp;
    return cpu->x[reg];
}

static inline void write_x(struct cpu_state *cpu, unsigned reg, qword_t val) {
    if (reg == 31)
        cpu->sp = val;
    else
        cpu->x[reg] = val;
}

int gadget_a64_exit(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    frame->cpu.pc = (addr_t) (*ip)[0];
    (*ip)++;
    return GADGET_END_BLOCK;
}

int gadget_a64_interrupt(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    int interrupt = (int) (*ip)[0];
    addr_t pc = (addr_t) (*ip)[1];
    addr_t addr = (addr_t) (*ip)[2];
    (*ip) += 3;
    return gadget_interrupt_emit(frame, interrupt, pc, addr);
}

int gadget_a64_nop(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb; (void) ip;
    frame->cpu.pc += 4;
    return GADGET_CONTINUE;
}

int gadget_a64_svc(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb; (void) ip;
    return gadget_interrupt_emit(frame, INT_SYSCALL, frame->cpu.pc + 4, 0);
}

int gadget_a64_brk(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb; (void) ip;
    return gadget_interrupt_emit(frame, INT_BREAKPOINT, frame->cpu.pc + 4, 0);
}

int gadget_a64_ret(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned rn = (unsigned) (*ip)[0];
    (*ip)++;
    frame->cpu.pc = read_x(&frame->cpu, rn);
    return GADGET_END_BLOCK;
}

int gadget_a64_branch(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    int64_t offset = (int64_t) (intptr_t) (*ip)[0];
    unsigned link = (unsigned) (*ip)[1];
    (*ip) += 2;
    addr_t pc = frame->cpu.pc;
    if (link)
        write_x(&frame->cpu, 30, pc + 4);
    frame->cpu.pc = pc + offset;
    return GADGET_END_BLOCK;
}

int gadget_a64_mov_wide(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned opc = (unsigned) (*ip)[0];
    unsigned hw = (unsigned) (*ip)[1];
    unsigned rd = (unsigned) (*ip)[2];
    uint16_t imm = (uint16_t) (*ip)[3];
    (*ip) += 4;
    qword_t shift = (qword_t) imm << (hw * 16);
    qword_t val;
    if (opc == 0)
        val = ~shift;
    else if (opc == 2)
        val = shift;
    else if (opc == 3)
        val = (read_x(&frame->cpu, rd) & ~(0xffffull << (hw * 16))) | shift;
    else
        val = read_x(&frame->cpu, rd);
    write_x(&frame->cpu, rd, val);
    frame->cpu.pc += 4;
    return GADGET_CONTINUE;
}
