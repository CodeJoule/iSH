#include <stdint.h>
#include "emu/cpu-aarch64.h"

uint64_t helper_a64_decode_logical_imm(uint32_t insn) {
    unsigned n = (insn >> 22) & 1;
    unsigned immr = (insn >> 16) & 0x3f;
    unsigned imms = (insn >> 10) & 0x3f;
    unsigned size = 0;
    unsigned mask = (unsigned) ~0u;
    while (size < 6 && !((n >> size) & 1)) {
        size++;
        mask >>= 1;
    }
    if (size >= 6)
        return 0;
    unsigned len = 64 - size;
    unsigned levels = size - 1;
    unsigned S = imms & levels;
    unsigned R = immr & levels;
    unsigned diff = S - R;
    uint64_t welem = (1ull << (S + 1)) - 1;
    uint64_t tmask = (1ull << (S + 1)) - 1;
    uint64_t t = 0;
    for (unsigned i = 0; i < len; i++) {
        if ((diff & levels) == (i & levels))
            t |= 1ull << i;
    }
    uint64_t wmask = t & tmask;
    uint64_t res = 0;
    for (unsigned i = 0; i < 64; i += len)
        res |= wmask << i;
    return res >> R | res << (len - R);
}
