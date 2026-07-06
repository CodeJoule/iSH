#include "asbestos/asbestos.h"
#include "asbestos/frame.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

enum {
    GADGET_CONTINUE = 0,
    GADGET_END_BLOCK = 1,
    GADGET_INTERRUPT = 2,
};

int gadget_a64_insn(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    uint32_t insn = (uint32_t) (*ip)[0];
    (*ip)++;
    addr_t pc = frame->cpu.pc;
    int interrupt = aarch64_exec_insn(&frame->cpu, tlb, pc, insn);
    if (interrupt != INT_NONE)
        return GADGET_INTERRUPT | (interrupt << 8);
    if (frame->cpu.pc != pc + 4)
        return GADGET_END_BLOCK;
    return GADGET_CONTINUE;
}

int gadget_a64_interrupt(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    int interrupt = (int) (*ip)[0];
    addr_t fault_ip = (addr_t) (*ip)[1];
    addr_t fault_addr = (addr_t) (*ip)[2];
    (*ip) += 3;
    frame->cpu.pc = fault_ip;
    frame->cpu.segfault_addr = fault_addr;
    frame->cpu.segfault_was_write = false;
    return GADGET_INTERRUPT | (interrupt << 8);
}

int gadget_a64_exit(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip) {
    (void) tlb;
    frame->cpu.pc = (addr_t) (*ip)[0];
    (*ip)++;
    return GADGET_END_BLOCK;
}

int fiber_enter(struct fiber_block *block, struct fiber_frame *frame, struct tlb *tlb) {
    unsigned long *ip = block->code;
    while (true) {
        int (*gadget)(struct fiber_frame *, struct tlb *, unsigned long **) =
                (int (*)(struct fiber_frame *, struct tlb *, unsigned long **)) *ip++;
        int result = gadget(frame, tlb, &ip);
        int kind = result & 0xff;
        if (kind == GADGET_INTERRUPT)
            return result >> 8;
        if (kind == GADGET_END_BLOCK)
            return INT_NONE;
    }
}
