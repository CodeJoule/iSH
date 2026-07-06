#include <stdint.h>
#include <string.h>
#include "asbestos/gadgets-guest-aarch64/gadgets.h"
#include "asbestos/asbestos.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

extern uint64_t helper_a64_decode_logical_imm(uint32_t insn);

#define GADGET_CONTINUE A64_GADGET_CONTINUE
#define GADGET_END_BLOCK A64_GADGET_END_BLOCK
#define GADGET_INTERRUPT A64_GADGET_INTERRUPT

static inline uint32_t bits32(uint32_t insn, int hi, int lo) {
    return (insn >> lo) & ((1u << (hi - lo + 1)) - 1);
}

static inline int64_t sign_extend(uint64_t val, int bits) {
    uint64_t shift = 64 - bits;
    return (int64_t) (val << shift) >> shift;
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

static int gadget_interrupt_emit(struct fiber_frame *frame, int interrupt, addr_t pc, addr_t addr) {
    frame->cpu.pc = pc;
    frame->cpu.segfault_addr = addr;
    frame->cpu.segfault_was_write = false;
    return GADGET_INTERRUPT | (interrupt << 8);
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
    addr_t pc = frame->cpu.pc + 4;
    return gadget_interrupt_emit(frame, INT_SYSCALL, pc, 0);
}

int gadget_a64_brk(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb; (void) ip;
    addr_t pc = frame->cpu.pc + 4;
    return gadget_interrupt_emit(frame, INT_BREAKPOINT, pc, 0);
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

int gadget_a64_insn(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    uint32_t insn = (uint32_t) (*ip)[0];
    (*ip)++;
    addr_t pc = frame->cpu.pc;
    int interrupt = aarch64_exec_insn(&frame->cpu, tlb, pc, insn);
    if (interrupt != INT_NONE)
        return gadget_interrupt_emit(frame, interrupt, frame->cpu.pc, frame->cpu.segfault_addr);
    if (frame->cpu.pc != pc + 4)
        return GADGET_END_BLOCK;
    return GADGET_CONTINUE;
}
