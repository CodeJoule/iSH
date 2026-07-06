#include "../gadgets-generic.h"
#include "guest/interrupt.h"

_cpu .req x0
_tlb .req x1
_ip .req x2

.macro .gadget name
    .global NAME(gadget_a64_\()\name)
    .align 4
    NAME(gadget_a64_\()\name) :
.endm

.macro read_xn dst, reg
    .if \reg == 31
        ldr \dst, [_cpu, CPU_sp]
    .else
        ldr \dst, [_cpu, CPU_x + \reg*8]
    .endif
.endm

.macro write_xn reg, src
    .if \reg == 31
        str \src, [_cpu, CPU_sp]
    .else
        str \src, [_cpu, CPU_x + \reg*8]
    .endif
.endm

# vim: ft=gas
