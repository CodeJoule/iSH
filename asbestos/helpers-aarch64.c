#include <stdint.h>
#include "asbestos/frame.h"
#include "asbestos/gadgets-guest-aarch64/gadgets.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

uint64_t helper_a64_decode_logical_imm(uint32_t insn) {
    unsigned n = (insn >> 22) & 1;
    unsigned immr = (insn >> 16) & 0x3f;
    unsigned imms = (insn >> 10) & 0x3f;
    unsigned size = 0;
    while (size < 6 && !((n >> size) & 1))
        size++;
    if (size >= 6)
        return 0;
    unsigned len = 64 - size;
    unsigned levels = size - 1;
    unsigned S = imms & levels;
    unsigned R = immr & levels;
    unsigned diff = S - R;
    uint64_t t = 0;
    for (unsigned i = 0; i < len; i++) {
        if ((diff & levels) == (i & levels))
            t |= 1ull << i;
    }
    uint64_t wmask = t & ((1ull << (S + 1)) - 1);
    uint64_t res = 0;
    for (unsigned i = 0; i < 64; i += len)
        res |= wmask << i;
    return res >> R | res << (len - R);
}

int helper_a64_run_insn_word(struct fiber_frame *frame, struct tlb *tlb, uint32_t insn) {
    addr_t pc = frame->cpu.pc;
    int interrupt = aarch64_exec_insn(&frame->cpu, tlb, pc, insn);
    if (interrupt != INT_NONE) {
        // Preserve segfault_was_write set by aarch64_exec_insn on store faults.
        return A64_GADGET_INTERRUPT | (interrupt << 8);
    }
    if (frame->cpu.pc != pc + 4)
        return A64_GADGET_END_BLOCK;
    return A64_GADGET_CONTINUE;
}

int helper_a64_cond_true(struct cpu_state *cpu, unsigned cond) {
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
