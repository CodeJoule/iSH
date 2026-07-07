#include <stdint.h>
#include "asbestos/gadgets-guest-aarch64/gadgets.h"
#include "asbestos/asbestos.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

extern int helper_a64_run_insn_word(struct fiber_frame *frame, struct tlb *tlb, uint32_t insn);

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

static inline bool cond_true(struct cpu_state *cpu, unsigned cond) {
    bool n = cpu_flag_n(cpu);
    bool z = cpu_flag_z(cpu);
    bool c = cpu_flag_c(cpu);
    bool v = cpu_flag_v(cpu);
    switch (cond) {
        case 0x0: return z;
        case 0x1: return !z;
        case 0x2: return c;
        case 0x3: return !c;
        case 0x4: return n;
        case 0x5: return !n;
        case 0x6: return v;
        case 0x7: return !v;
        case 0x8: return c && !z;
        case 0x9: return !c || z;
        case 0xa: return n == v;
        case 0xb: return n != v;
        case 0xc: return !z && (n == v);
        case 0xd: return z || (n != v);
        case 0xe: return true;
        case 0xf: return false;
        default: return false;
    }
}

int gadget_a64_branch_cond(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned cond = (unsigned) (*ip)[0];
    int64_t offset = (int64_t) (intptr_t) (*ip)[1];
    (*ip) += 2;
    addr_t pc = frame->cpu.pc;
    if (cond_true(&frame->cpu, cond))
        frame->cpu.pc = pc + offset;
    else
        frame->cpu.pc = pc + 4;
    return frame->cpu.pc == pc + 4 ? GADGET_CONTINUE : GADGET_END_BLOCK;
}

int gadget_a64_cbz(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned sf = (unsigned) (*ip)[0];
    unsigned op = (unsigned) (*ip)[1];
    unsigned rt = (unsigned) (*ip)[2];
    int64_t offset = (int64_t) (intptr_t) (*ip)[3];
    (*ip) += 4;
    qword_t val = read_x(&frame->cpu, rt);
    if (!sf)
        val = (uint32_t) val;
    bool is_zero = val == 0;
    addr_t pc = frame->cpu.pc;
    if (is_zero == (op == 0))
        frame->cpu.pc = pc + offset;
    else
        frame->cpu.pc = pc + 4;
    return frame->cpu.pc == pc + 4 ? GADGET_CONTINUE : GADGET_END_BLOCK;
}

int gadget_a64_tbz(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned op = (unsigned) (*ip)[0];
    unsigned rt = (unsigned) (*ip)[1];
    unsigned bit = (unsigned) (*ip)[2];
    int64_t offset = (int64_t) (intptr_t) (*ip)[3];
    (*ip) += 4;
    bool bit_set = (read_x(&frame->cpu, rt) >> bit) & 1;
    addr_t pc = frame->cpu.pc;
    if (bit_set == op)
        frame->cpu.pc = pc + offset;
    else
        frame->cpu.pc = pc + 4;
    return frame->cpu.pc == pc + 4 ? GADGET_CONTINUE : GADGET_END_BLOCK;
}

int gadget_a64_adr(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned rd = (unsigned) (*ip)[0];
    int64_t offset = (int64_t) (intptr_t) (*ip)[1];
    (*ip) += 2;
    write_x(&frame->cpu, rd, frame->cpu.pc + offset);
    frame->cpu.pc += 4;
    return GADGET_CONTINUE;
}

int gadget_a64_adrp(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    unsigned rd = (unsigned) (*ip)[0];
    int64_t offset = (int64_t) (intptr_t) (*ip)[1];
    (*ip) += 2;
    addr_t page = (frame->cpu.pc & ~0xfffull) + (offset << 12);
    write_x(&frame->cpu, rd, page);
    frame->cpu.pc += 4;
    return GADGET_CONTINUE;
}

int gadget_a64_insn(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    uint32_t insn = (uint32_t) (*ip)[0];
    (*ip)++;
    return helper_a64_run_insn_word(frame, tlb, insn);
}

int gadget_a64_ldst(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_ldst_reg(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_pair(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_exclusive(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_add_sub_imm(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_logical_imm(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_add_sub_reg(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_logical_reg(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}

int gadget_a64_system(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    return gadget_a64_insn(frame, tlb, ip);
}
