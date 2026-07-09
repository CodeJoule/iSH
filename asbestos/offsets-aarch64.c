#include "asbestos/asbestos.h"
#include "asbestos/frame.h"
#include "emu/cpu-aarch64.h"
#include "emu/tlb.h"

void cpu(void) {
    OFFSET(CPU, cpu_state, x);
    OFFSET(CPU, cpu_state, sp);
    OFFSET(CPU, cpu_state, pc);
    OFFSET(CPU, cpu_state, pstate);
    OFFSET(CPU, cpu_state, tls_ptr);
    OFFSET(CPU, cpu_state, segfault_addr);
    OFFSET(CPU, cpu_state, segfault_was_write);
    OFFSET(CPU, cpu_state, poked_ptr);
    OFFSET(CPU, cpu_state, exclusive_addr);
    OFFSET(CPU, cpu_state, exclusive_valid);

    MACRO(PSTATE_N);
    MACRO(PSTATE_Z);
    MACRO(PSTATE_C);
    MACRO(PSTATE_V);

    OFFSET(LOCAL, fiber_frame, bp);
    OFFSET(LOCAL, fiber_frame, value);
    OFFSET(LOCAL, fiber_frame, value_addr);
    OFFSET(LOCAL, fiber_frame, last_block);
    OFFSET(LOCAL, fiber_frame, ret_cache);

    OFFSET(FIBER_BLOCK, fiber_block, addr);
    OFFSET(FIBER_BLOCK, fiber_block, code);

    OFFSET(TLB, tlb, entries);
    OFFSET(TLB, tlb, dirty_page);
    OFFSET(TLB, tlb, segfault_addr);
    OFFSET(TLB_ENTRY, tlb_entry, page);
    OFFSET(TLB_ENTRY, tlb_entry, page_if_writable);
    OFFSET(TLB_ENTRY, tlb_entry, data_minus_addr);
}
