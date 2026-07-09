#include "asbestos/asbestos.h"
#include "asbestos/gadgets-guest-aarch64/gadgets.h"
#include "guest/interrupt.h"

int fiber_enter(struct fiber_block *block, struct fiber_frame *frame, struct tlb *tlb) {
    unsigned long *ip = block->code;
    while (true) {
        a64_gadget_fn gadget = (a64_gadget_fn) *ip++;
        int result = gadget(frame, tlb, &ip);
        int kind = result & 0xff;
        if (kind == A64_GADGET_INTERRUPT)
            return result >> 8;
        if (kind == A64_GADGET_END_BLOCK)
            return INT_NONE;
    }
}
