#ifndef CPU_AARCH64_H
#define CPU_AARCH64_H

#include "misc.h"
#include "emu/mmu.h"

#ifdef __KERNEL__
#include <linux/stddef.h>
#else
#include <stddef.h>
#endif

struct cpu_state;
struct tlb;
int cpu_run_to_interrupt(struct cpu_state *cpu, struct tlb *tlb);
void cpu_poke(struct cpu_state *cpu);

#define AARCH64_REG_COUNT 31

/* AArch64 PSTATE flag bits (NZCV in bits 31-28 of pstate). */
#define PSTATE_N (1u << 31)
#define PSTATE_Z (1u << 30)
#define PSTATE_C (1u << 29)
#define PSTATE_V (1u << 28)

union vreg {
    unsigned __int128 u128;
    qword_t qw[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t u8[16];
    double f64[2];
    float f32[4];
};
static_assert(sizeof(union vreg) == 16, "vreg size");

struct cpu_state {
    struct mmu *mmu;
    long cycle;

    qword_t x[AARCH64_REG_COUNT]; /* x0-x30; sp is x[31] alias via accessor */
    qword_t sp;
    qword_t pc;

    /* NZCV + exception level / mode bits we care about */
    dword_t pstate;

    /* FP/SIMD */
    union vreg v[32];
    dword_t fpcr;
    dword_t fpsr;

    /* TLS (TPIDR_EL0) */
    addr_t tls_ptr;

    /* page fault info */
    addr_t segfault_addr;
    bool segfault_was_write;

    int trapno;

    bool *poked_ptr;
    bool _poked;

    /* exclusive monitor for LDXR/STXR */
    addr_t exclusive_addr;
    bool exclusive_valid;
};

#define CPU_OFFSET(field) offsetof(struct cpu_state, field)

static inline qword_t *cpu_reg(struct cpu_state *cpu, unsigned reg) {
    if (reg == 31)
        return &cpu->sp;
    return &cpu->x[reg];
}

static inline bool cpu_flag_n(struct cpu_state *cpu) { return cpu->pstate & PSTATE_N; }
static inline bool cpu_flag_z(struct cpu_state *cpu) { return cpu->pstate & PSTATE_Z; }
static inline bool cpu_flag_c(struct cpu_state *cpu) { return cpu->pstate & PSTATE_C; }
static inline bool cpu_flag_v(struct cpu_state *cpu) { return cpu->pstate & PSTATE_V; }

static inline void cpu_set_nz(struct cpu_state *cpu, qword_t res) {
    cpu->pstate &= ~(PSTATE_N | PSTATE_Z);
    if (res == 0)
        cpu->pstate |= PSTATE_Z;
    if ((sqword_t) res < 0)
        cpu->pstate |= PSTATE_N;
}

static inline void cpu_set_nzc(struct cpu_state *cpu, qword_t res, bool carry) {
    cpu_set_nz(cpu, res);
    if (carry)
        cpu->pstate |= PSTATE_C;
    else
        cpu->pstate &= ~PSTATE_C;
}

static inline const char *aarch64_reg_name(unsigned reg) {
    if (reg == 31)
        return "sp";
    static char buf[4];
    buf[0] = 'x';
    if (reg < 10) {
        buf[1] = '0' + reg;
        buf[2] = '\0';
    } else {
        buf[1] = '0' + reg / 10;
        buf[2] = '0' + reg % 10;
        buf[3] = '\0';
    }
    return buf;
}

#endif
