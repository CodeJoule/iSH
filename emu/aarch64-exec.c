#include <stdint.h>
#include <string.h>
#include "emu/aarch64-exec.h"
#include "guest/interrupt.h"
#include "debug.h"

uint64_t helper_a64_decode_logical_imm(uint32_t insn);

#define DEFAULT_CHANNEL instr

static inline uint32_t bits32(uint32_t insn, int hi, int lo) {
    return (insn >> lo) & ((1u << (hi - lo + 1)) - 1);
}

static inline int64_t sign_extend(uint64_t val, int bits) {
    uint64_t shift = 64 - bits;
    return (int64_t) (val << shift) >> shift;
}

static bool mem_read(struct cpu_state *cpu, struct tlb *tlb, addr_t addr, void *buf, size_t size) {
    if (!tlb_read(tlb, addr, buf, size)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->segfault_was_write = false;
        return false;
    }
    return true;
}

static bool mem_write(struct cpu_state *cpu, struct tlb *tlb, addr_t addr, const void *buf, size_t size) {
    if (!tlb_write(tlb, addr, buf, size)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->segfault_was_write = true;
        return false;
    }
    return true;
}

static qword_t read_reg(struct cpu_state *cpu, unsigned reg) {
    if (reg == 31)
        return cpu->sp;
    return cpu->x[reg];
}

static void write_reg(struct cpu_state *cpu, unsigned reg, qword_t val) {
    if (reg == 31)
        cpu->sp = val;
    else
        cpu->x[reg] = val;
}

static void set_nzcv(struct cpu_state *cpu, bool n, bool z, bool c, bool v) {
    cpu->pstate &= ~(PSTATE_N | PSTATE_Z | PSTATE_C | PSTATE_V);
    if (n) cpu->pstate |= PSTATE_N;
    if (z) cpu->pstate |= PSTATE_Z;
    if (c) cpu->pstate |= PSTATE_C;
    if (v) cpu->pstate |= PSTATE_V;
}

static void add_with_carry(struct cpu_state *cpu, qword_t op1, qword_t op2, bool carry_in, qword_t *res_out) {
    uint64_t res = (uint64_t) op1 + (uint64_t) op2 + (carry_in ? 1 : 0);
    bool carry = (uint64_t) op1 + (uint64_t) op2 < (uint64_t) op1 ||
            (carry_in && res == (uint64_t) op1);
    bool overflow = ((~((uint64_t) op1 ^ (uint64_t) op2) & ((uint64_t) op1 ^ res)) >> 63) & 1;
    *res_out = res;
    set_nzcv(cpu, (int64_t) res < 0, res == 0, carry, overflow);
}

static void sub_with_carry(struct cpu_state *cpu, qword_t op1, qword_t op2, bool carry_in, qword_t *res_out) {
    add_with_carry(cpu, op1, ~op2, carry_in, res_out);
}

static bool cond_true(struct cpu_state *cpu, unsigned cond) {
    bool n = cpu_flag_n(cpu);
    bool z = cpu_flag_z(cpu);
    bool c = cpu_flag_c(cpu);
    bool v = cpu_flag_v(cpu);
    switch (cond) {
        case 0x0: return z;
        case 0x1: return !z;
        case 0x2: return c;
        case 0x3: return !c;
        case 0x4: return n;
        case 0x5: return !n;
        case 0x6: return v;
        case 0x7: return !v;
        case 0x8: return c && !z;
        case 0x9: return !c || z;
        case 0xa: return n == v;
        case 0xb: return n != v;
        case 0xc: return !z && (n == v);
        case 0xd: return z || (n != v);
        case 0xe: return true;
        case 0xf: return false;
        default: return false;
    }
}

static int handle_load_store(struct cpu_state *cpu, struct tlb *tlb, uint32_t insn) {
    unsigned size = bits32(insn, 31, 30);
    bool v = insn & (1u << 26);
    unsigned opc = bits32(insn, 23, 22);
    bool is_load = (opc & 1) == 1;
    unsigned rt = bits32(insn, 4, 0);
    unsigned rn = bits32(insn, 9, 5);
    int64_t offset = bits32(insn, 21, 10) << size;
    addr_t addr = read_reg(cpu, rn) + offset;
    unsigned width = 1u << size;

    if (v) {
        if (is_load) {
            union vreg zero = {0};
            cpu->v[rt] = zero;
        }
        return INT_NONE;
    }

    if (is_load) {
        qword_t val = 0;
        if (!mem_read(cpu, tlb, addr, &val, width))
            return INT_GPF;
        if (size == 0 && (opc >> 1))
            val = sign_extend(val, 8 << (opc >> 1));
        else if (size == 1 && opc == 3)
            val = sign_extend(val, 16);
        else if (size == 2 && opc == 3)
            val = sign_extend(val, 32);
        write_reg(cpu, rt, val);
    } else {
        qword_t val = read_reg(cpu, rt);
        if (width < 8)
            val &= ((1ull << (width * 8)) - 1);
        if (!mem_write(cpu, tlb, addr, &val, width))
            return INT_GPF;
    }
    return INT_NONE;
}

static int handle_load_store_reg(struct cpu_state *cpu, struct tlb *tlb, uint32_t insn) {
    unsigned size = bits32(insn, 31, 30);
    unsigned opc = bits32(insn, 23, 22);
    bool is_load = (opc & 1) == 1;
    unsigned rt = bits32(insn, 4, 0);
    unsigned rn = bits32(insn, 9, 5);
    unsigned rm = bits32(insn, 20, 16);
    unsigned extend = bits32(insn, 15, 13);
    bool shifted = insn & (1u << 12);
    qword_t offset = read_reg(cpu, rm);
    if (shifted)
        offset <<= size;
    if (extend == 2 || extend == 6)
        offset = sign_extend(offset, 32);
    else if (extend == 3 || extend == 7)
        offset = (uint32_t) offset;
    addr_t addr = read_reg(cpu, rn) + offset;
    unsigned width = 1u << size;

    if (insn & (1u << 26)) {
        if (is_load) {
            union vreg zero = {0};
            cpu->v[rt] = zero;
        }
        return INT_NONE;
    }

    if (is_load) {
        qword_t val = 0;
        if (!mem_read(cpu, tlb, addr, &val, width))
            return INT_GPF;
        if (size == 0 && opc >= 2)
            val = sign_extend(val, 8);
        else if (size == 1 && opc == 3)
            val = sign_extend(val, 16);
        else if (size == 2 && opc == 3)
            val = sign_extend(val, 32);
        write_reg(cpu, rt, val);
    } else {
        qword_t val = read_reg(cpu, rt);
        if (!mem_write(cpu, tlb, addr, &val, width))
            return INT_GPF;
    }
    return INT_NONE;
}

static int handle_pair(struct cpu_state *cpu, struct tlb *tlb, uint32_t insn) {
    bool pre = insn & (1u << 24);
    bool load = insn & (1u << 22);
    bool writeback = insn & (1u << 23);
    int64_t imm = sign_extend(bits32(insn, 21, 15), 7) * 8;
    unsigned rt = bits32(insn, 4, 0);
    unsigned rt2 = bits32(insn, 14, 10);
    unsigned rn = bits32(insn, 9, 5);
    addr_t base = read_reg(cpu, rn);
    addr_t addr = pre ? base + imm : base;
    qword_t v1 = 0, v2 = 0;

    if (load) {
        if (!mem_read(cpu, tlb, addr, &v1, 8) || !mem_read(cpu, tlb, addr + 8, &v2, 8))
            return INT_GPF;
        write_reg(cpu, rt, v1);
        write_reg(cpu, rt2, v2);
    } else {
        v1 = read_reg(cpu, rt);
        v2 = read_reg(cpu, rt2);
        if (!mem_write(cpu, tlb, addr, &v1, 8) || !mem_write(cpu, tlb, addr + 8, &v2, 8))
            return INT_GPF;
    }
    if (writeback)
        write_reg(cpu, rn, pre ? addr : base + imm);
    return INT_NONE;
}

static int handle_exclusive(struct cpu_state *cpu, struct tlb *tlb, uint32_t insn) {
    unsigned rt = bits32(insn, 4, 0);
    unsigned rn = bits32(insn, 9, 5);
    unsigned rs = bits32(insn, 20, 16);
    addr_t addr = read_reg(cpu, rn);
    unsigned size = bits32(insn, 31, 30);
    unsigned width = 1u << size;
    bool is_store = bits32(insn, 23, 21) == 0;

    if (!is_store) {
        qword_t val = 0;
        if (!mem_read(cpu, tlb, addr, &val, width))
            return INT_GPF;
        write_reg(cpu, rt, val);
        cpu->exclusive_valid = true;
        cpu->exclusive_addr = addr;
        return INT_NONE;
    }

    qword_t expected = read_reg(cpu, rs);
    qword_t newval = read_reg(cpu, rt);
    qword_t current = 0;
    if (!mem_read(cpu, tlb, addr, &current, width))
        return INT_GPF;
    if (cpu->exclusive_valid && cpu->exclusive_addr == addr && current == expected) {
        if (!mem_write(cpu, tlb, addr, &newval, width))
            return INT_GPF;
        write_reg(cpu, rs, 0);
    } else {
        write_reg(cpu, rs, 1);
    }
    cpu->exclusive_valid = false;
    return INT_NONE;
}

bool aarch64_insn_ends_block(uint32_t insn) {
    if ((insn & 0xffe0001fu) == 0xd4000001u)
        return true;
    if ((insn & 0xfffffc1fu) == 0xd61f0000u)
        return true;
    if (bits32(insn, 31, 26) == 0x25)
        return true;
    if ((insn & 0xff000010u) == 0x54000000u)
        return false;
    if (bits32(insn, 31, 24) == 0xb4 || bits32(insn, 31, 24) == 0xb5)
        return false;
    if (bits32(insn, 31, 24) == 0xb6 || bits32(insn, 31, 24) == 0xb7)
        return false;
    return false;
}

int aarch64_exec_insn(struct cpu_state *cpu, struct tlb *tlb, addr_t pc, uint32_t insn) {
    TRACE("aarch64 %016llx: %08x\n", (unsigned long long) pc, insn);

    if ((insn & 0xffe0001fu) == 0xd4000001u) {
        cpu->pc = pc + 4;
        return INT_SYSCALL;
    }

    if ((insn & 0xfffffc1fu) == 0xd61f0000u) {
        unsigned rn = bits32(insn, 9, 5);
        cpu->pc = read_reg(cpu, rn);
        return INT_NONE;
    }

    if (bits32(insn, 31, 26) == 0x25) {
        int64_t imm = sign_extend(bits32(insn, 25, 0) << 2, 28);
        if (insn & (1u << 31)) {
            write_reg(cpu, 30, pc + 4);
            cpu->pc = pc + imm;
        } else {
            cpu->pc = pc + imm;
        }
        return INT_NONE;
    }

    if ((insn & 0xff000010u) == 0x54000000u) {
        int64_t imm = sign_extend(bits32(insn, 23, 5) << 2, 21);
        unsigned cond = bits32(insn, 3, 0);
        if (cond_true(cpu, cond))
            cpu->pc = pc + imm;
        else
            cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 31, 24) == 0xb4 || bits32(insn, 31, 24) == 0xb5) {
        unsigned sf = bits32(insn, 31, 31);
        unsigned op = bits32(insn, 24, 24);
        int64_t imm = sign_extend(bits32(insn, 23, 5) << 2, 21);
        unsigned rt = bits32(insn, 4, 0);
        qword_t val = read_reg(cpu, rt);
        if (!sf)
            val = (uint32_t) val;
        bool is_zero = val == 0;
        if (is_zero == (op == 0))
            cpu->pc = pc + imm;
        else
            cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 31, 24) == 0xb6 || bits32(insn, 31, 24) == 0xb7) {
        unsigned op = bits32(insn, 24, 24);
        int64_t imm = sign_extend(bits32(insn, 18, 5) << 2, 16);
        unsigned bit = bits32(insn, 23, 19);
        unsigned rt = bits32(insn, 4, 0);
        bool bit_set = (read_reg(cpu, rt) >> bit) & 1;
        if (bit_set == op)
            cpu->pc = pc + imm;
        else
            cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 31, 29) == 0) {
        unsigned op = bits32(insn, 31, 31);
        int64_t immlo = bits32(insn, 30, 29);
        int64_t immhi = bits32(insn, 23, 5);
        int64_t imm = sign_extend((immhi << 2) | immlo, 21);
        unsigned rd = bits32(insn, 4, 0);
        if (op) {
            addr_t page = (pc & ~0xfffull) + (imm << 12);
            write_reg(cpu, rd, page);
        } else {
            write_reg(cpu, rd, pc + imm);
        }
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 22) == 0x39) {
        cpu->pc = pc + 4;
        return handle_load_store(cpu, tlb, insn);
    }

    if (bits32(insn, 28, 21) == 0xf1 || bits32(insn, 28, 21) == 0xf3) {
        cpu->pc = pc + 4;
        return handle_load_store_reg(cpu, tlb, insn);
    }

    if (bits32(insn, 28, 25) == 0xa) {
        cpu->pc = pc + 4;
        return handle_pair(cpu, tlb, insn);
    }

    if (bits32(insn, 28, 21) == 0x30) {
        cpu->pc = pc + 4;
        return handle_exclusive(cpu, tlb, insn);
    }

    if ((insn & 0x1f800000u) == 0x12800000u) {
        unsigned opc = bits32(insn, 30, 29);
        unsigned hw = bits32(insn, 22, 21);
        unsigned rd = bits32(insn, 4, 0);
        uint16_t imm = bits32(insn, 20, 5);
        qword_t val;
        qword_t shift = (qword_t) imm << (hw * 16);
        if (opc == 0)
            val = ~shift;
        else if (opc == 2)
            val = shift;
        else if (opc == 3)
            val = (read_reg(cpu, rd) & ~(0xffffull << (hw * 16))) | shift;
        else
            val = read_reg(cpu, rd);
        write_reg(cpu, rd, val);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if ((insn & 0x1f000000u) == 0x11000000u) {
        unsigned sf = bits32(insn, 31, 31);
        unsigned op = bits32(insn, 30, 30);
        unsigned sh = bits32(insn, 23, 22);
        uint32_t imm = bits32(insn, 21, 10);
        if (sh)
            imm <<= 12;
        unsigned rn = bits32(insn, 9, 5);
        unsigned rd = bits32(insn, 4, 0);
        bool setflags = bits32(insn, 29, 29);
        qword_t op1 = read_reg(cpu, rn);
        qword_t res;
        if (op)
            sub_with_carry(cpu, op1, imm, !setflags, &res);
        else
            add_with_carry(cpu, op1, imm, false, &res);
        if (!sf)
            res = (uint32_t) res;
        if (setflags && !sf)
            set_nzcv(cpu, (int32_t) res < 0, (uint32_t) res == 0, cpu_flag_c(cpu), cpu_flag_v(cpu));
        if (!setflags || rd != 31)
            write_reg(cpu, rd, res);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 23) == 0x24) {
        unsigned sf = bits32(insn, 31, 31);
        unsigned opc = bits32(insn, 30, 29);
        unsigned rd = bits32(insn, 4, 0);
        unsigned rn = bits32(insn, 9, 5);
        qword_t imm = helper_a64_decode_logical_imm(insn);
        qword_t val = read_reg(cpu, rn);
        qword_t res = 0;
        switch (opc) {
            case 0: res = val & imm; break;
            case 1: res = val | imm; break;
            case 2: res = val ^ imm; break;
            case 3: res = val & ~imm; break;
        }
        if (!sf)
            res = (uint32_t) res;
        cpu_set_nz(cpu, res);
        write_reg(cpu, rd, res);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 24) == 0x0b || bits32(insn, 28, 24) == 0x1b) {
        unsigned sf = bits32(insn, 31, 31);
        unsigned opc = bits32(insn, 30, 29);
        unsigned shift = bits32(insn, 23, 22);
        unsigned rm = bits32(insn, 20, 16);
        unsigned imm6 = bits32(insn, 15, 10);
        unsigned rn = bits32(insn, 9, 5);
        unsigned rd = bits32(insn, 4, 0);
        qword_t val1 = read_reg(cpu, rn);
        qword_t val2 = read_reg(cpu, rm);
        unsigned shamt = imm6 & (sf ? 63 : 31);
        if (shift == 0)
            val2 <<= shamt;
        else if (shift == 1)
            val2 = sf ? ((uint64_t) val2 >> shamt) : ((uint32_t) val2 >> shamt);
        else if (shift == 2)
            val2 = (sqword_t) (sf ? val2 : (int32_t) val2) >> shamt;
        qword_t res = 0;
        bool setflags = opc >= 2;
        switch (opc) {
            case 0: add_with_carry(cpu, val1, val2, false, &res); break;
            case 1: add_with_carry(cpu, val1, val2, true, &res); break;
            case 2: sub_with_carry(cpu, val1, val2, false, &res); break;
            case 3: sub_with_carry(cpu, val1, val2, true, &res); break;
        }
        if (!sf)
            res = (uint32_t) res;
        if (!setflags || rd != 31)
            write_reg(cpu, rd, res);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 24) == 0x0a) {
        unsigned sf = bits32(insn, 31, 31);
        unsigned opc = bits32(insn, 30, 29);
        unsigned shift = bits32(insn, 23, 22);
        unsigned rm = bits32(insn, 20, 16);
        unsigned imm6 = bits32(insn, 15, 10);
        unsigned rn = bits32(insn, 9, 5);
        unsigned rd = bits32(insn, 4, 0);
        qword_t val1 = read_reg(cpu, rn);
        qword_t val2 = read_reg(cpu, rm);
        unsigned shamt = imm6 & (sf ? 63 : 31);
        if (shift == 0)
            val2 <<= shamt;
        else if (shift == 1)
            val2 = sf ? ((uint64_t) val2 >> shamt) : ((uint32_t) val2 >> shamt);
        else if (shift == 2)
            val2 = (sqword_t) (sf ? val2 : (int32_t) val2) >> shamt;
        qword_t res = 0;
        switch (opc) {
            case 0: res = val1 & val2; break;
            case 1: res = val1 | val2; break;
            case 2: res = val1 ^ val2; break;
            case 3: res = val1 & ~val2; break;
        }
        if (!sf)
            res = (uint32_t) res;
        cpu_set_nz(cpu, res);
        write_reg(cpu, rd, res);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 23) == 0x25 && (insn & 0x1f800000u) != 0x12800000u) {
        unsigned opc = bits32(insn, 30, 29);
        unsigned hw = bits32(insn, 22, 21);
        unsigned rd = bits32(insn, 4, 0);
        uint16_t imm = bits32(insn, 20, 5);
        qword_t val = 0;
        if (opc == 0)
            val = 0;
        else
            val = read_reg(cpu, rd);
        if (opc == 0 || opc == 2)
            val |= (qword_t) imm << (hw * 16);
        else if (opc == 3)
            val = ~((qword_t) imm << (hw * 16));
        write_reg(cpu, rd, val);
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if (bits32(insn, 28, 21) == 0xd5) {
        unsigned op0 = bits32(insn, 20, 19);
        unsigned op1 = bits32(insn, 18, 16);
        unsigned crn = bits32(insn, 15, 12);
        unsigned crm = bits32(insn, 11, 8);
        unsigned op2 = bits32(insn, 7, 5);
        unsigned rt = bits32(insn, 4, 0);
        bool is_msr = insn & (1u << 21);
        if (op0 == 3 && op1 == 3 && crn == 13 && crm == 0 && op2 == 2) {
            if (is_msr)
                cpu->tls_ptr = read_reg(cpu, rt);
            else
                write_reg(cpu, rt, cpu->tls_ptr);
            cpu->pc = pc + 4;
            return INT_NONE;
        }
    }

    if (insn == 0xd503201fu) {
        cpu->pc = pc + 4;
        return INT_NONE;
    }

    if ((insn & 0xffe00000u) == 0xd4200000u) {
        cpu->pc = pc + 4;
        return INT_BREAKPOINT;
    }

    printk("unhandled aarch64 insn 0x%08x at 0x%llx\n", insn, (unsigned long long) pc);
    cpu->pc = pc + 4;
    return INT_UNDEFINED;
}
