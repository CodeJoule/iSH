#include "../gadgets-generic.h"

_cpu .req x20
_tlb .req x21
_ip .req x22
_tmp .req w0
_xtmp .req x0

.extern fiber_exit
.extern fiber_ret
.extern fiber_interrupt
.extern helper_a64_run_insn_word
.extern helper_a64_cond_true

.macro .gadget name
    .global NAME(gadget_a64_\()\name)
    .align 4
    NAME(gadget_a64_\()\name) :
.endm

.macro gret pop=0
    ldr x8, [_ip, \pop*8]!
    br x8
.endm

// Runtime register index in \reg (wN). x16 is IP0 and safe to clobber.
.macro read_xn dst, reg
    cmp \reg, #31
    b.eq 1f
    add x16, _cpu, CPU_x
    ldr \dst, [x16, \reg, uxtw #3]
    b 2f
1:  ldr \dst, [_cpu, CPU_sp]
2:
.endm

.macro write_xn reg, src
    cmp \reg, #31
    b.eq 1f
    add x16, _cpu, CPU_x
    str \src, [x16, \reg, uxtw #3]
    b 2f
1:  str \src, [_cpu, CPU_sp]
2:
.endm

.macro insn_gadget name
.gadget \name
    ldr w19, [_ip], #8
    stp x19, x20, [sp, -0x20]!
    stp x29, x30, [sp, 0x10]
    mov x0, _cpu
    sub x1, _tlb, TLB_entries
    mov w2, w19
    bl helper_a64_run_insn_word
    mov w23, w0
    ldp x29, x30, [sp, 0x10]
    ldp x19, x20, [sp], 0x20
    and w8, w23, #0xff
    cmp w8, #1
    b.ne 1f
    b fiber_ret
1:  cmp w8, #2
    b.ne 2f
    b fiber_interrupt
2:  gret
.endm

# vim: ft=gas
