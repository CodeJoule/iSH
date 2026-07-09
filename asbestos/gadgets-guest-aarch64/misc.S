#include "gadgets-asm.h"

insn_gadget system
insn_gadget insn

.global fiber_interrupt
fiber_interrupt:
    // insn_gadget leaves packed result in w23: kind | (interrupt << 8)
    lsr _tmp, w23, #8
    b fiber_exit

# vim: ft=gas
