#include "../gadgets-generic.h"
#include "gadgets-asm.h"
#include "guest/interrupt.h"

.global NAME(fiber_enter)
.type_compat fiber_enter,function
NAME(fiber_enter):
    stp x19, x20, [sp, -0x60]!
    stp x21, x22, [sp, 0x10]
    stp x23, x24, [sp, 0x20]
    stp x25, x26, [sp, 0x30]
    str x27, [sp, 0x40]
    str lr, [sp, 0x48]

    mov x19, x1
    mov x20, x2
    add x21, x0, FIBER_BLOCK_code
    str x21, [sp, 0x50]

fiber_loop:
    ldr x8, [x21], #8
    str x21, [sp, 0x50]
    mov x0, x19
    mov x1, x20
    add x2, sp, 0x50
    blr x8
    and w9, w0, #0xff
    cmp w9, #1
    b.eq fiber_end_block
    cmp w9, #2
    b.eq fiber_interrupt
    ldr x21, [sp, 0x50]
    b fiber_loop

fiber_end_block:
    mov w0, INT_NONE
    b fiber_return

fiber_interrupt:
    lsr w0, w0, #8

fiber_return:
    ldr lr, [sp, 0x48]
    ldr x27, [sp, 0x40]
    ldp x25, x26, [sp, 0x30]
    ldp x23, x24, [sp, 0x20]
    ldp x21, x22, [sp, 0x10]
    ldp x19, x20, [sp], 0x60
    ret

# vim: ft=gas
