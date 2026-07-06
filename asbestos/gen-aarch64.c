#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "asbestos/frame.h"
#include "asbestos/gen.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

typedef int (*aarch64_gadget_fn)(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);

extern int gadget_a64_insn(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_interrupt(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_exit(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);

static void gen(struct gen_state *state, unsigned long thing) {
    assert(state->size <= state->capacity);
    if (state->size >= state->capacity) {
        state->capacity *= 2;
        struct fiber_block *bigger_block = realloc(state->block,
                sizeof(struct fiber_block) + state->capacity * sizeof(unsigned long));
        if (bigger_block == NULL)
            die("out of memory while carcinizing");
        state->block = bigger_block;
    }
    state->block->code[state->size++] = thing;
}

void gen_start(addr_t addr, struct gen_state *state) {
    state->capacity = FIBER_BLOCK_INITIAL_CAPACITY;
    state->size = 0;
    state->ip = addr;
    for (int i = 0; i <= 1; i++)
        state->jump_ip[i] = 0;
    state->block_patch_ip = 0;

    struct fiber_block *block = malloc(sizeof(struct fiber_block) + state->capacity * sizeof(unsigned long));
    state->block = block;
    block->addr = addr;
}

void gen_end(struct gen_state *state) {
    struct fiber_block *block = state->block;
    for (int i = 0; i <= 1; i++) {
        if (state->jump_ip[i] != 0) {
            block->jump_ip[i] = &block->code[state->jump_ip[i]];
            block->old_jump_ip[i] = *block->jump_ip[i];
        } else {
            block->jump_ip[i] = NULL;
        }
        list_init(&block->jumps_from[i]);
        list_init(&block->jumps_from_links[i]);
    }
    if (state->block_patch_ip != 0)
        block->code[state->block_patch_ip] = (unsigned long) block;
    if (block->addr != state->ip)
        block->end_addr = state->ip - 1;
    else
        block->end_addr = block->addr;
    list_init(&block->chain);
    block->is_jetsam = false;
    for (int i = 0; i <= 1; i++)
        list_init(&block->page[i]);
}

void gen_exit(struct gen_state *state) {
    gen(state, (unsigned long) gadget_a64_exit);
    gen(state, state->ip);
}

#define GEN(thing) gen(state, (unsigned long) (thing))

int gen_step(struct gen_state *state, struct tlb *tlb) {
    state->orig_ip = state->ip;
    uint32_t insn;
    if (!tlb_read(tlb, state->ip, &insn, 4)) {
        GEN(gadget_a64_interrupt);
        GEN(INT_GPF);
        GEN(state->orig_ip);
        GEN(tlb->segfault_addr);
        return 0;
    }

    GEN(gadget_a64_insn);
    GEN(insn);
    state->ip += 4;

    if (aarch64_insn_ends_block(insn))
        return 0;
    return 1;
}
