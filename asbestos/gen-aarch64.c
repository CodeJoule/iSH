#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "asbestos/gen.h"
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"

typedef int (*a64_gadget_fn)(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);

extern int gadget_a64_exit(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_interrupt(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_nop(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_svc(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_brk(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_ret(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_branch(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_branch_cond(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_cbz(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_tbz(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_adr(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_adrp(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_mov_wide(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);
extern int gadget_a64_insn(struct fiber_frame *frame, struct tlb *tlb, unsigned long **ip);

static inline uint32_t bits32(uint32_t insn, int hi, int lo) {
    return (insn >> lo) & ((1u << (hi - lo + 1)) - 1);
}

static inline int64_t sign_extend(uint64_t val, int bits) {
    uint64_t shift = 64 - bits;
    return (int64_t) (val << shift) >> shift;
}

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

#define GEN(thing) gen(state, (unsigned long) (thing))
#define g(gadget) GEN(gadget)
#define gg(gadget, a) do { g(gadget); GEN(a); } while (0)
#define ggg(gadget, a, b) do { g(gadget); GEN(a); GEN(b); } while (0)
#define gggg(gadget, a, b, c) do { g(gadget); GEN(a); GEN(b); GEN(c); } while (0)
#define ggggg(gadget, a, b, c, d) do { g(gadget); GEN(a); GEN(b); GEN(c); GEN(d); } while (0)
#define INTERRUPT(code) do { gggg(gadget_a64_interrupt, code, state->orig_ip, 0); return 0; } while (0)
#define SEGFAULT do { gggg(gadget_a64_interrupt, INT_GPF, state->orig_ip, tlb->segfault_addr); return 0; } while (0)

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
    g(gadget_a64_exit);
    GEN(state->ip);
}

int gen_step(struct gen_state *state, struct tlb *tlb) {
    state->orig_ip = state->ip;
    uint32_t insn;
    if (!tlb_read(tlb, state->ip, &insn, 4))
        SEGFAULT;

    bool end_block = false;

    if ((insn & 0xffe0001fu) == 0xd4000001u) {
        g(gadget_a64_svc);
        end_block = true;
    } else if ((insn & 0xfffffc1fu) == 0xd61f0000u) {
        g(gadget_a64_ret);
        GEN(bits32(insn, 9, 5));
        end_block = true;
    } else if (bits32(insn, 31, 26) == 0x25) {
        int64_t imm = sign_extend(bits32(insn, 25, 0) << 2, 28);
        ggg(gadget_a64_branch, (unsigned long) imm, insn >> 31);
        end_block = true;
    } else if ((insn & 0xff000010u) == 0x54000000u) {
        int64_t imm = sign_extend(bits32(insn, 23, 5) << 2, 21);
        ggg(gadget_a64_branch_cond, bits32(insn, 3, 0), (unsigned long) imm);
        end_block = true;
    } else if (bits32(insn, 31, 24) == 0xb4 || bits32(insn, 31, 24) == 0xb5) {
        int64_t imm = sign_extend(bits32(insn, 23, 5) << 2, 21);
        ggggg(gadget_a64_cbz, bits32(insn, 31, 31), bits32(insn, 24, 24),
                bits32(insn, 4, 0), (unsigned long) imm);
        end_block = true;
    } else if (bits32(insn, 31, 24) == 0xb6 || bits32(insn, 31, 24) == 0xb7) {
        int64_t imm = sign_extend(bits32(insn, 18, 5) << 2, 16);
        ggggg(gadget_a64_tbz, bits32(insn, 24, 24), bits32(insn, 4, 0),
                bits32(insn, 23, 19), (unsigned long) imm);
        end_block = true;
    } else if (bits32(insn, 31, 29) == 0) {
        int64_t immlo = bits32(insn, 30, 29);
        int64_t immhi = bits32(insn, 23, 5);
        int64_t imm = sign_extend((immhi << 2) | immlo, 21);
        unsigned op = bits32(insn, 31, 31);
        if (op)
            ggg(gadget_a64_adrp, bits32(insn, 4, 0), (unsigned long) imm);
        else
            ggg(gadget_a64_adr, bits32(insn, 4, 0), (unsigned long) imm);
    } else if ((insn & 0x1f800000u) == 0x12800000u) {
        ggggg(gadget_a64_mov_wide, bits32(insn, 30, 29), bits32(insn, 22, 21),
                bits32(insn, 4, 0), bits32(insn, 20, 5));
    } else if (insn == 0xd503201fu) {
        g(gadget_a64_nop);
    } else if ((insn & 0xffe00000u) == 0xd4200000u) {
        g(gadget_a64_brk);
        end_block = true;
    } else {
        gg(gadget_a64_insn, insn);
        if (aarch64_insn_ends_block(insn))
            end_block = true;
    }

    state->ip += 4;
    if (end_block)
        return 0;
    return 1;
}
