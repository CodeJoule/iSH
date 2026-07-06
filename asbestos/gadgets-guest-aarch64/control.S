#include "gadgets-asm.h"

.gadget exit
    ldr x10, [_ip], #8
    str x10, [_cpu, CPU_pc]
    mov w0, #1
    ret

.gadget interrupt
    ldr w8, [_ip], #8
    ldr x10, [_ip], #8
    str x10, [_cpu, CPU_pc]
    ldr x11, [_ip], #8
    str x11, [_cpu, CPU_segfault_addr]
    strb wzr, [_cpu, CPU_segfault_was_write]
    mov w0, #2
    bfi w0, w8, #8, #24
    ret

.gadget nop
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov w0, #0
    ret

.gadget svc
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov w8, #INT_SYSCALL
    mov w0, #2
    bfi w0, w8, #8, #24
    ret

.gadget brk
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov w8, #INT_BREAKPOINT
    mov w0, #2
    bfi w0, w8, #8, #24
    ret

.gadget ret
    ldr w10, [_ip], #8
    read_xn x11, w10
    str x11, [_cpu, CPU_pc]
    mov w0, #1
    ret

.gadget branch
    ldr x10, [_ip], #8
    ldr w11, [_ip], #8
    ldr x12, [_cpu, CPU_pc]
    add x12, x12, x10
    cbnz w11, 1f
    b 2f
1:
    add x13, x12, #4
    str x13, [_cpu, CPU_x + 30*8]
2:
    str x12, [_cpu, CPU_pc]
    mov w0, #1
    ret

.gadget mov_wide
    ldr w8, [_ip], #8
    ldr w9, [_ip], #8
    ldr w10, [_ip], #8
    ldr w11, [_ip], #8
    lsl w12, w11, w9, lsl #4
    uxtw x12, w12
    cmp w8, #0
    b.eq 1f
    cmp w8, #2
    b.eq 2f
    cmp w8, #3
    b.ne 3f
    read_xn x13, w10
    mov x14, #0xffff
    lsl x14, x14, x9, lsl #4
    mvn x14, x14
    and x13, x13, x14
    orr x12, x13, x12
    b 3f
1:
    mvn x12, x12
    b 3f
2:
    nop
3:
    write_xn w10, x12
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov w0, #0
    ret

# vim: ft=gas
