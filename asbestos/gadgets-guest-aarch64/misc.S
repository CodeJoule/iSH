#include "gadgets-asm.h"

insn_gadget system
insn_gadget insn

.global fiber_interrupt
fiber_interrupt:
    lsr _tmp, w20, #8
    b fiber_exit

# vim: ft=gas
