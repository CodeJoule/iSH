#include "gadgets-asm.h"
#include "guest/interrupt.h"

.gadget exit
    ldr x10, [_ip], #8
    str x10, [_cpu, CPU_pc]
    b fiber_ret

.gadget interrupt
    ldr w8, [_ip], #8
    ldr x10, [_ip], #8
    str x10, [_cpu, CPU_pc]
    ldr x11, [_ip], #8
    str x11, [_cpu, CPU_segfault_addr]
    strb wzr, [_cpu, CPU_segfault_was_write]
    mov _tmp, w8
    b fiber_exit

.gadget nop
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    gret

.gadget svc
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov _tmp, #INT_SYSCALL
    b fiber_exit

.gadget brk
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    mov _tmp, #INT_BREAKPOINT
    b fiber_exit

.gadget ret
    ldr w10, [_ip], #8
    read_xn x11, w10
    str x11, [_cpu, CPU_pc]
    b fiber_ret

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
    b fiber_ret

.gadget mov_wide
    ldr w8, [_ip], #8
    ldr w9, [_ip], #8
    ldr w10, [_ip], #8
    ldr w11, [_ip], #8
    lsl w9, w9, #4
    lsl w12, w11, w9
    uxtw x12, w12
    cmp w8, #0
    b.eq 1f
    cmp w8, #2
    b.eq 2f
    cmp w8, #3
    b.ne 3f
    read_xn x13, w10
    mov x14, #0xffff
    uxtw x9, w9
    lsl x14, x14, x9
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
    gret

.gadget branch_cond
    ldr w8, [_ip], #8
    ldr x10, [_ip], #8
    stp x29, x30, [sp, -0x10]!
    mov x0, _cpu
    mov w1, w8
    bl helper_a64_cond_true
    ldp x29, x30, [sp], 0x10
    cbz w0, cond_false
    ldr x14, [_cpu, CPU_pc]
    add x14, x14, x10
    str x14, [_cpu, CPU_pc]
    b fiber_ret
cond_false:
    ldr x14, [_cpu, CPU_pc]
    add x14, x14, #4
    str x14, [_cpu, CPU_pc]
    gret

.gadget cbz
    // args: sf, op (0=cbz/1=cbnz), rt, imm
    ldr w8, [_ip], #8
    ldr w9, [_ip], #8
    ldr w10, [_ip], #8
    ldr x11, [_ip], #8
    read_xn x12, w10
    cbnz w8, 1f
    // sf=0: compare as 32-bit (W-form CBZ/CBNZ)
    uxtw x12, w12
1:
    // take branch when (val==0) == (op==0), i.e. is_zero != op
    cmp x12, #0
    cset w12, eq
    cmp w12, w9
    b.eq 2f
    // take branch
    ldr x13, [_cpu, CPU_pc]
    add x13, x13, x11
    str x13, [_cpu, CPU_pc]
    b fiber_ret
2:
    ldr x13, [_cpu, CPU_pc]
    add x13, x13, #4
    str x13, [_cpu, CPU_pc]
    gret

.gadget tbz
    ldr w8, [_ip], #8
    ldr w9, [_ip], #8
    ldr w10, [_ip], #8
    ldr x11, [_ip], #8
    read_xn x12, w9
    uxtw x10, w10
    lsr x12, x12, x10
    and x12, x12, #1
    cmp w12, w8
    b.ne 1f
    ldr x13, [_cpu, CPU_pc]
    add x13, x13, x11
    str x13, [_cpu, CPU_pc]
    b fiber_ret
1:
    ldr x13, [_cpu, CPU_pc]
    add x13, x13, #4
    str x13, [_cpu, CPU_pc]
    gret

.gadget adr
    ldr w9, [_ip], #8
    ldr x10, [_ip], #8
    ldr x11, [_cpu, CPU_pc]
    add x11, x11, x10
    write_xn w9, x11
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    gret

.gadget adrp
    ldr w9, [_ip], #8
    ldr x10, [_ip], #8
    ldr x11, [_cpu, CPU_pc]
    bic x11, x11, #0xfff
    add x11, x11, x10, lsl #12
    write_xn w9, x11
    ldr x10, [_cpu, CPU_pc]
    add x10, x10, #4
    str x10, [_cpu, CPU_pc]
    gret

# vim: ft=gas
