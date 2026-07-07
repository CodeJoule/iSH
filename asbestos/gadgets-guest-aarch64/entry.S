#include "gadgets-asm.h"
#include "guest/interrupt.h"

.global NAME(fiber_enter)
.type_compat fiber_enter,function
NAME(fiber_enter):
    stp x19, x20, [sp, -0x50]!
    stp x21, x22, [sp, 0x10]
    stp x23, x24, [sp, 0x20]
    str x25, [sp, 0x30]
    str lr, [sp, 0x38]

    add _ip, x0, FIBER_BLOCK_code
    mov _cpu, x1
    add _tlb, x2, TLB_entries
    gret

.global fiber_ret_chain
fiber_ret_chain:
    tbz _ip, #63, 1f
    b fiber_ret
1:
    ldr x8, [_cpu, CPU_poked_ptr]
    ldrb w8, [x8]
    cbnz w8, poke
    sub x8, _ip, FIBER_BLOCK_code
    str x8, [_cpu, LOCAL_last_block]
    gret

poke:
    ldr _tmp, [_ip, -FIBER_BLOCK_code+FIBER_BLOCK_addr]
    str _tmp, [_cpu, CPU_pc]
    b fiber_ret

.global fiber_ret
fiber_ret:
    mov _tmp, #-1
    b fiber_exit

.global fiber_exit
fiber_exit:
    ldr lr, [sp, 0x38]
    ldr x25, [sp, 0x30]
    ldp x23, x24, [sp, 0x20]
    ldp x21, x22, [sp, 0x10]
    ldp x19, x20, [sp], 0x50
    ret

# vim: ft=gas
