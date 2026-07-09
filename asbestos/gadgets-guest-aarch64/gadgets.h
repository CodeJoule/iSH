#ifndef GADGETS_GUEST_AARCH64_H
#define GADGETS_GUEST_AARCH64_H

#include "asbestos/frame.h"
#include "emu/tlb.h"

enum a64_gadget_result {
    A64_GADGET_CONTINUE = 0,
    A64_GADGET_END_BLOCK = 1,
    A64_GADGET_INTERRUPT = 2,
};

typedef int (*a64_gadget_fn)(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);

int fiber_enter(struct fiber_block *block, struct fiber_frame *frame, struct tlb *tlb);

#endif
