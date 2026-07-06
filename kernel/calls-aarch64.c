#include <string.h>
#include "debug.h"
#include "kernel/calls.h"
#include "guest/interrupt.h"
#include "kernel/memory.h"
#include "kernel/signal.h"
#include "kernel/task.h"

typedef qword_t (*syscall_aarch64_t)(qword_t, qword_t, qword_t, qword_t, qword_t, qword_t);

#define SC(fn) (syscall_aarch64_t)(fn)

static qword_t sc_write(qword_t fd, qword_t buf, qword_t size, qword_t a4, qword_t a5, qword_t a6) {
    return sys_write((fd_t) fd, (addr_t) buf, (dword_t) size);
}
static qword_t sc_read(qword_t fd, qword_t buf, qword_t size, qword_t a4, qword_t a5, qword_t a6) {
    return sys_read((fd_t) fd, (addr_t) buf, (dword_t) size);
}
static qword_t sc_openat(qword_t dfd, qword_t path, qword_t flags, qword_t mode, qword_t a5, qword_t a6) {
    return sys_openat((fd_t) dfd, (addr_t) path, (dword_t) flags, (mode_t_) mode);
}
static qword_t sc_close(qword_t fd, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_close((fd_t) fd);
}
static qword_t sc_exit(qword_t status, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_exit((dword_t) status);
}
static qword_t sc_exit_group(qword_t status, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_exit_group((dword_t) status);
}
static qword_t sc_brk(qword_t addr, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_brk((addr_t) addr);
}
static qword_t sc_getpid(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_getpid();
}
static qword_t sc_gettid(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_gettid();
}
static qword_t sc_getuid(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_getuid32();
}
static qword_t sc_getgid(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_getgid32();
}
static qword_t sc_mmap(qword_t addr, qword_t len, qword_t prot, qword_t flags, qword_t fd, qword_t offset) {
    return sys_mmap2((addr_t) addr, (dword_t) len, (dword_t) prot, (dword_t) flags, (fd_t) fd, (dword_t) (offset >> 12));
}
static qword_t sc_munmap(qword_t addr, qword_t len, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_munmap((addr_t) addr, (uint_t) len);
}
static qword_t sc_mprotect(qword_t addr, qword_t len, qword_t prot, qword_t a4, qword_t a5, qword_t a6) {
    return sys_mprotect((addr_t) addr, (uint_t) len, (int_t) prot);
}
static qword_t sc_execve(qword_t file, qword_t argv, qword_t envp, qword_t a4, qword_t a5, qword_t a6) {
    return sys_execve((addr_t) file, (addr_t) argv, (addr_t) envp);
}
static qword_t sc_clone(qword_t flags, qword_t stack, qword_t ptid, qword_t tls, qword_t ctid, qword_t a6) {
    return sys_clone((dword_t) flags, (addr_t) stack, (addr_t) ptid, (addr_t) tls, (addr_t) ctid);
}
static qword_t sc_uname(qword_t buf, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_uname((addr_t) buf);
}
static qword_t sc_fcntl(qword_t fd, qword_t cmd, qword_t arg, qword_t a4, qword_t a5, qword_t a6) {
    return sys_fcntl32((fd_t) fd, (dword_t) cmd, (dword_t) arg);
}
static qword_t sc_ioctl(qword_t fd, qword_t cmd, qword_t arg, qword_t a4, qword_t a5, qword_t a6) {
    return sys_ioctl((fd_t) fd, (dword_t) cmd, (dword_t) arg);
}
static qword_t sc_futex(qword_t uaddr, qword_t op, qword_t val, qword_t timeout, qword_t uaddr2, qword_t val3) {
    return sys_futex((addr_t) uaddr, (dword_t) op, (dword_t) val, (addr_t) timeout, (addr_t) uaddr2, (dword_t) val3);
}
static qword_t sc_set_tid_address(qword_t tid, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_set_tid_address((addr_t) tid);
}
static qword_t sc_set_robust_list(qword_t head, qword_t len, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_set_robust_list((addr_t) head, (dword_t) len);
}
static qword_t sc_rt_sigaction(qword_t sig, qword_t act, qword_t oldact, qword_t sigsetsize, qword_t a5, qword_t a6) {
    return sys_rt_sigaction((int) sig, (addr_t) act, (addr_t) oldact, (dword_t) sigsetsize);
}
static qword_t sc_rt_sigprocmask(qword_t how, qword_t set, qword_t oldset, qword_t sigsetsize, qword_t a5, qword_t a6) {
    return sys_rt_sigprocmask((int) how, (addr_t) set, (addr_t) oldset, (dword_t) sigsetsize);
}
static qword_t sc_rt_sigreturn(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_rt_sigreturn();
}
static qword_t sc_clock_gettime(qword_t clk, qword_t tp, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_clock_gettime((clockid_t) clk, (addr_t) tp);
}
static qword_t sc_gettimeofday(qword_t tv, qword_t tz, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_gettimeofday((addr_t) tv, (addr_t) tz);
}
static qword_t sc_getrandom(qword_t buf, qword_t len, qword_t flags, qword_t a4, qword_t a5, qword_t a6) {
    return sys_getrandom((addr_t) buf, (dword_t) len, (dword_t) flags);
}
static qword_t sc_wait4(qword_t pid, qword_t status, qword_t options, qword_t rusage, qword_t a5, qword_t a6) {
    return sys_wait4((pid_t_) pid, (addr_t) status, (dword_t) options, (addr_t) rusage);
}
static qword_t sc_getcwd(qword_t buf, qword_t size, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_getcwd((addr_t) buf, (dword_t) size);
}
static qword_t sc_chdir(qword_t path, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_chdir((addr_t) path);
}
static qword_t sc_dup(qword_t fd, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_dup((fd_t) fd);
}
static qword_t sc_dup3(qword_t fd, qword_t newfd, qword_t flags, qword_t a4, qword_t a5, qword_t a6) {
    return sys_dup3((fd_t) fd, (fd_t) newfd, (int_t) flags);
}
static qword_t sc_pipe2(qword_t pipefd, qword_t flags, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_pipe2((addr_t) pipefd, (int_t) flags);
}
static qword_t sc_prlimit64(qword_t pid, qword_t resource, qword_t new_limit, qword_t old_limit, qword_t a5, qword_t a6) {
    return sys_prlimit64((pid_t_) pid, (dword_t) resource, (addr_t) new_limit, (addr_t) old_limit);
}
static qword_t sc_nanosleep(qword_t req, qword_t rem, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_nanosleep((addr_t) req, (addr_t) rem);
}
static qword_t sc_sched_yield(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return sys_sched_yield();
}
static qword_t sc_statx(qword_t dfd, qword_t path, qword_t flags, qword_t mask, qword_t buf, qword_t a6) {
    return sys_statx((fd_t) dfd, (addr_t) path, (int_t) flags, (uint_t) mask, (addr_t) buf);
}
static qword_t sc_enosys(qword_t a1, qword_t a2, qword_t a3, qword_t a4, qword_t a5, qword_t a6) {
    return _ENOSYS;
}

static syscall_aarch64_t syscall_table_aarch64[400];

static void init_syscall_table(void) {
    memset(syscall_table_aarch64, 0, sizeof(syscall_table_aarch64));
    syscall_table_aarch64[25] = sc_fcntl;
    syscall_table_aarch64[29] = sc_ioctl;
    syscall_table_aarch64[56] = sc_openat;
    syscall_table_aarch64[57] = sc_close;
    syscall_table_aarch64[63] = sc_read;
    syscall_table_aarch64[64] = sc_write;
    syscall_table_aarch64[93] = sc_exit;
    syscall_table_aarch64[94] = sc_exit_group;
    syscall_table_aarch64[96] = sc_set_tid_address;
    syscall_table_aarch64[98] = sc_futex;
    syscall_table_aarch64[99] = sc_set_robust_list;
    syscall_table_aarch64[113] = sc_clock_gettime;
    syscall_table_aarch64[134] = sc_rt_sigaction;
    syscall_table_aarch64[135] = sc_rt_sigprocmask;
    syscall_table_aarch64[139] = sc_rt_sigreturn;
    syscall_table_aarch64[160] = sc_uname;
    syscall_table_aarch64[169] = sc_gettimeofday;
    syscall_table_aarch64[172] = sc_getpid;
    syscall_table_aarch64[174] = sc_getuid;
    syscall_table_aarch64[176] = sc_getgid;
    syscall_table_aarch64[214] = sc_brk;
    syscall_table_aarch64[215] = sc_munmap;
    syscall_table_aarch64[220] = sc_clone;
    syscall_table_aarch64[221] = sc_execve;
    syscall_table_aarch64[222] = sc_mmap;
    syscall_table_aarch64[226] = sc_mprotect;
    syscall_table_aarch64[260] = sc_wait4;
    syscall_table_aarch64[261] = sc_prlimit64;
    syscall_table_aarch64[278] = sc_getrandom;
    syscall_table_aarch64[291] = sc_statx;
    syscall_table_aarch64[17] = sc_getcwd;
    syscall_table_aarch64[49] = sc_chdir;
    syscall_table_aarch64[23] = sc_dup;
    syscall_table_aarch64[24] = sc_dup3;
    syscall_table_aarch64[59] = sc_pipe2;
    syscall_table_aarch64[178] = sc_gettid;
    syscall_table_aarch64[124] = sc_sched_yield;
    syscall_table_aarch64[101] = sc_nanosleep;
}

void dump_stack(int lines);

void handle_interrupt(int interrupt) {
    static bool initialized;
    if (!initialized) {
        init_syscall_table();
        initialized = true;
    }

    struct cpu_state *cpu = &current->cpu;
    if (interrupt == INT_SYSCALL) {
        unsigned syscall_num = (unsigned) cpu->x[8];
        qword_t result;
        if (syscall_num >= array_size(syscall_table_aarch64) || syscall_table_aarch64[syscall_num] == NULL) {
            printk("%d(%s) missing aarch64 syscall %u\n", current->pid, current->comm, syscall_num);
            result = _ENOSYS;
        } else {
            STRACE("%d call %-3u ", current->pid, syscall_num);
            result = syscall_table_aarch64[syscall_num](
                    cpu->x[0], cpu->x[1], cpu->x[2], cpu->x[3], cpu->x[4], cpu->x[5]);
            STRACE(" = 0x%llx\n", (unsigned long long) result);
        }
        if ((sqword_t) result < 0) {
            cpu->x[0] = -result;
            cpu->pstate |= PSTATE_C;
        } else {
            cpu->x[0] = result;
            cpu->pstate &= ~PSTATE_C;
        }
    } else if (interrupt == INT_GPF) {
        read_wrlock(&current->mem->lock);
        void *ptr = mem_ptr(current->mem, cpu->segfault_addr, cpu->segfault_was_write ? MEM_WRITE : MEM_READ);
        read_wrunlock(&current->mem->lock);
        if (ptr == NULL) {
            printk("%d page fault on 0x%llx at 0x%llx\n", current->pid,
                    (unsigned long long) cpu->segfault_addr, (unsigned long long) cpu->pc);
            struct siginfo_ info = {
                .code = mem_segv_reason(current->mem, cpu->segfault_addr),
                .fault.addr = cpu->segfault_addr,
            };
            dump_stack(8);
            deliver_signal(current, SIGSEGV_, info);
        }
    } else if (interrupt == INT_UNDEFINED) {
        printk("%d illegal instruction at 0x%llx\n", current->pid, (unsigned long long) cpu->pc);
        dump_stack(8);
        deliver_signal(current, SIGILL_, (struct siginfo_) {
            .code = SI_KERNEL_,
            .fault.addr = cpu->pc,
        });
    } else if (interrupt == INT_BREAKPOINT) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = SI_KERNEL_,
        });
        unlock(&pids_lock);
    } else if (interrupt == INT_DEBUG) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .sig = SIGTRAP_,
            .code = TRAP_TRACE_,
        });
        unlock(&pids_lock);
    } else if (interrupt != INT_TIMER) {
        printk("%d unhandled interrupt %d\n", current->pid, interrupt);
        sys_exit(interrupt);
    }

    receive_signals();
    struct tgroup *group = current->group;
    lock(&group->lock);
    while (group->stopped)
        wait_for_ignore_signals(&group->stopped_cond, &group->lock, NULL);
    unlock(&group->lock);
}

void dump_stack(int lines) {
    printk("stack at %llx, pc at %llx\n", (unsigned long long) current->cpu.sp, (unsigned long long) current->cpu.pc);
}
