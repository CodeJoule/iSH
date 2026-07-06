#include <string.h>
#include "debug.h"
#include "kernel/calls.h"
#include "guest/guest-config.h"
#include "guest/interrupt.h"
#include "kernel/memory.h"
#include "kernel/signal.h"
#include "kernel/task.h"

#if GUEST_AARCH64

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

#else /* GUEST_I386 */

#include "emu/interrupt.h"

dword_t syscall_stub(void) {
    return _ENOSYS;
}
// While identical, this version of the stub doesn't log below. Use this for
// syscalls that are optional (i.e. fallback on something else) but called
// frequently.
dword_t syscall_silent_stub(void) {
    return _ENOSYS;
}
dword_t syscall_success_stub(void) {
    return 0;
}

#if is_gcc(8) || is_clang(21)
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
syscall_t syscall_table[] = {
    [1]   = (syscall_t) sys_exit,
    [2]   = (syscall_t) sys_fork,
    [3]   = (syscall_t) sys_read,
    [4]   = (syscall_t) sys_write,
    [5]   = (syscall_t) sys_open,
    [6]   = (syscall_t) sys_close,
    [7]   = (syscall_t) sys_waitpid,
    [9]   = (syscall_t) sys_link,
    [10]  = (syscall_t) sys_unlink,
    [11]  = (syscall_t) sys_execve,
    [12]  = (syscall_t) sys_chdir,
    [13]  = (syscall_t) sys_time,
    [14]  = (syscall_t) sys_mknod,
    [15]  = (syscall_t) sys_chmod,
    [19]  = (syscall_t) sys_lseek,
    [20]  = (syscall_t) sys_getpid,
    [21]  = (syscall_t) sys_mount,
    [23]  = (syscall_t) sys_setuid,
    [24]  = (syscall_t) sys_getuid,
    [25]  = (syscall_t) sys_stime,
    [26]  = (syscall_t) sys_ptrace,
    [27]  = (syscall_t) sys_alarm,
    [29]  = (syscall_t) sys_pause,
    [30]  = (syscall_t) sys_utime,
    [33]  = (syscall_t) sys_access,
    [36]  = (syscall_t) syscall_success_stub, // sync
    [37]  = (syscall_t) sys_kill,
    [38]  = (syscall_t) sys_rename,
    [39]  = (syscall_t) sys_mkdir,
    [40]  = (syscall_t) sys_rmdir,
    [41]  = (syscall_t) sys_dup,
    [42]  = (syscall_t) sys_pipe,
    [43]  = (syscall_t) sys_times,
    [45]  = (syscall_t) sys_brk,
    [46]  = (syscall_t) sys_setgid,
    [47]  = (syscall_t) sys_getgid,
    [49]  = (syscall_t) sys_geteuid,
    [50]  = (syscall_t) sys_getegid,
    [52]  = (syscall_t) sys_umount2,
    [54]  = (syscall_t) sys_ioctl,
    [55]  = (syscall_t) sys_fcntl32,
    [57]  = (syscall_t) sys_setpgid,
    [60]  = (syscall_t) sys_umask,
    [61]  = (syscall_t) sys_chroot,
    [63]  = (syscall_t) sys_dup2,
    [64]  = (syscall_t) sys_getppid,
    [65]  = (syscall_t) sys_getpgrp,
    [66]  = (syscall_t) sys_setsid,
    [74]  = (syscall_t) sys_sethostname,
    [75]  = (syscall_t) sys_setrlimit32,
    [76]  = (syscall_t) sys_old_getrlimit32,
    [77]  = (syscall_t) sys_getrusage,
    [78]  = (syscall_t) sys_gettimeofday,
    [79]  = (syscall_t) sys_settimeofday,
    [80]  = (syscall_t) sys_getgroups,
    [81]  = (syscall_t) sys_setgroups,
    [83]  = (syscall_t) sys_symlink,
    [85]  = (syscall_t) sys_readlink,
    [88]  = (syscall_t) sys_reboot,
    [90]  = (syscall_t) sys_mmap,
    [91]  = (syscall_t) sys_munmap,
    [94]  = (syscall_t) sys_fchmod,
    [96]  = (syscall_t) sys_getpriority,
    [97]  = (syscall_t) sys_setpriority,
    [99]  = (syscall_t) sys_statfs,
    [100] = (syscall_t) sys_fstatfs,
    [102] = (syscall_t) sys_socketcall,
    [103] = (syscall_t) sys_syslog,
    [104] = (syscall_t) sys_setitimer,
    [114] = (syscall_t) sys_wait4,
    [116] = (syscall_t) sys_sysinfo,
    [117] = (syscall_t) sys_ipc,
    [118] = (syscall_t) sys_fsync,
    [119] = (syscall_t) sys_sigreturn,
    [120] = (syscall_t) sys_clone,
    [122] = (syscall_t) sys_uname,
    [125] = (syscall_t) sys_mprotect,
    [132] = (syscall_t) sys_getpgid,
    [133] = (syscall_t) sys_fchdir,
    [136] = (syscall_t) sys_personality,
    [140] = (syscall_t) sys__llseek,
    [141] = (syscall_t) sys_getdents,
    [142] = (syscall_t) sys_select,
    [143] = (syscall_t) sys_flock,
    [144] = (syscall_t) sys_msync,
    [145] = (syscall_t) sys_readv,
    [146] = (syscall_t) sys_writev,
    [147] = (syscall_t) sys_getsid,
    [148] = (syscall_t) sys_fsync, // fdatasync
    [150] = (syscall_t) sys_mlock,
    [155] = (syscall_t) sys_sched_getparam,
    [156] = (syscall_t) sys_sched_setscheduler,
    [157] = (syscall_t) sys_sched_getscheduler,
    [158] = (syscall_t) sys_sched_yield,
    [159] = (syscall_t) sys_sched_get_priority_max,
    [162] = (syscall_t) sys_nanosleep,
    [163] = (syscall_t) sys_mremap,
    [168] = (syscall_t) sys_poll,
    [172] = (syscall_t) sys_prctl,
    [173] = (syscall_t) sys_rt_sigreturn,
    [174] = (syscall_t) sys_rt_sigaction,
    [175] = (syscall_t) sys_rt_sigprocmask,
    [176] = (syscall_t) sys_rt_sigpending,
    [177] = (syscall_t) sys_rt_sigtimedwait,
    [179] = (syscall_t) sys_rt_sigsuspend,
    [180] = (syscall_t) sys_pread,
    [181] = (syscall_t) sys_pwrite,
    [183] = (syscall_t) sys_getcwd,
    [184] = (syscall_t) sys_capget,
    [185] = (syscall_t) sys_capset,
    [186] = (syscall_t) sys_sigaltstack,
    [187] = (syscall_t) sys_sendfile,
    [190] = (syscall_t) sys_vfork,
    [191] = (syscall_t) sys_getrlimit32,
    [192] = (syscall_t) sys_mmap2,
    [193] = (syscall_t) sys_truncate64,
    [194] = (syscall_t) sys_ftruncate64,
    [195] = (syscall_t) sys_stat64,
    [196] = (syscall_t) sys_lstat64,
    [197] = (syscall_t) sys_fstat64,
    [198] = (syscall_t) sys_lchown,
    [199] = (syscall_t) sys_getuid32,
    [200] = (syscall_t) sys_getgid32,
    [201] = (syscall_t) sys_geteuid32,
    [202] = (syscall_t) sys_getegid32,
    [203] = (syscall_t) sys_setreuid,
    [204] = (syscall_t) sys_setregid,
    [205] = (syscall_t) sys_getgroups,
    [206] = (syscall_t) sys_setgroups,
    [207] = (syscall_t) sys_fchown32,
    [208] = (syscall_t) sys_setresuid,
    [209] = (syscall_t) sys_getresuid,
    [210] = (syscall_t) sys_setresgid,
    [211] = (syscall_t) sys_getresgid,
    [212] = (syscall_t) sys_chown32,
    [213] = (syscall_t) sys_setuid,
    [214] = (syscall_t) sys_setgid,
    [215] = (syscall_t) syscall_stub, // setfsuid
    [216] = (syscall_t) syscall_stub, // setfsgid
    [219] = (syscall_t) sys_madvise,
    [220] = (syscall_t) sys_getdents64,
    [221] = (syscall_t) sys_fcntl,
    [224] = (syscall_t) sys_gettid,
    [225] = (syscall_t) syscall_success_stub, // readahead
    [226 ... 237] = (syscall_t) sys_xattr_stub,
    [238] = (syscall_t) sys_tkill,
    [239] = (syscall_t) sys_sendfile64,
    [240] = (syscall_t) sys_futex,
    [241] = (syscall_t) sys_sched_setaffinity,
    [242] = (syscall_t) sys_sched_getaffinity,
    [243] = (syscall_t) sys_set_thread_area,
    [245] = (syscall_t) syscall_stub, // io_setup
    [252] = (syscall_t) sys_exit_group,
    [254] = (syscall_t) sys_epoll_create0,
    [255] = (syscall_t) sys_epoll_ctl,
    [256] = (syscall_t) sys_epoll_wait,
    [258] = (syscall_t) sys_set_tid_address,
    [259] = (syscall_t) sys_timer_create,
    [260] = (syscall_t) sys_timer_settime,
    [263] = (syscall_t) sys_timer_delete,
    [264] = (syscall_t) sys_clock_settime,
    [265] = (syscall_t) sys_clock_gettime,
    [266] = (syscall_t) sys_clock_getres,
    [268] = (syscall_t) sys_statfs64,
    [269] = (syscall_t) sys_fstatfs64,
    [270] = (syscall_t) sys_tgkill,
    [271] = (syscall_t) sys_utimes,
    [272] = (syscall_t) syscall_success_stub,
    [274] = (syscall_t) sys_mbind,
    [284] = (syscall_t) sys_waitid,
    [289] = (syscall_t) sys_ioprio_set,
    [290] = (syscall_t) sys_ioprio_get,
    [291] = (syscall_t) syscall_stub, // inotify_init
    [295] = (syscall_t) sys_openat,
    [296] = (syscall_t) sys_mkdirat,
    [297] = (syscall_t) sys_mknodat,
    [298] = (syscall_t) sys_fchownat,
    [300] = (syscall_t) sys_fstatat64,
    [301] = (syscall_t) sys_unlinkat,
    [302] = (syscall_t) sys_renameat,
    [303] = (syscall_t) sys_linkat,
    [304] = (syscall_t) sys_symlinkat,
    [305] = (syscall_t) sys_readlinkat,
    [306] = (syscall_t) sys_fchmodat,
    [307] = (syscall_t) sys_faccessat,
    [308] = (syscall_t) sys_pselect,
    [309] = (syscall_t) sys_ppoll,
    [311] = (syscall_t) sys_set_robust_list,
    [312] = (syscall_t) sys_get_robust_list,
    [313] = (syscall_t) sys_splice,
    [319] = (syscall_t) sys_epoll_pwait,
    [320] = (syscall_t) sys_utimensat,
    [322] = (syscall_t) sys_timerfd_create,
    [323] = (syscall_t) sys_eventfd,
    [324] = (syscall_t) sys_fallocate,
    [325] = (syscall_t) sys_timerfd_settime,
    [328] = (syscall_t) sys_eventfd2,
    [329] = (syscall_t) sys_epoll_create,
    [330] = (syscall_t) sys_dup3,
    [331] = (syscall_t) sys_pipe2,
    [332] = (syscall_t) syscall_stub, // inotify_init1
    [340] = (syscall_t) sys_prlimit64,
    [345] = (syscall_t) sys_sendmmsg,
    [352] = (syscall_t) syscall_stub, // sched_getattr
    [353] = (syscall_t) sys_renameat2,
    [355] = (syscall_t) sys_getrandom,
    [359] = (syscall_t) sys_socket,
    [360] = (syscall_t) sys_socketpair,
    [361] = (syscall_t) sys_bind,
    [362] = (syscall_t) sys_connect,
    [363] = (syscall_t) sys_listen,
    [364] = (syscall_t) syscall_stub, // accept4
    [365] = (syscall_t) sys_getsockopt,
    [366] = (syscall_t) sys_setsockopt,
    [367] = (syscall_t) sys_getsockname,
    [368] = (syscall_t) sys_getpeername,
    [369] = (syscall_t) sys_sendto,
    [370] = (syscall_t) sys_sendmsg,
    [371] = (syscall_t) sys_recvfrom,
    [372] = (syscall_t) sys_recvmsg,
    [373] = (syscall_t) sys_shutdown,
    [375] = (syscall_t) syscall_silent_stub, // membarrier
    [377] = (syscall_t) sys_copy_file_range,
    [383] = (syscall_t) sys_statx,
    [384] = (syscall_t) sys_arch_prctl,
    [422] = (syscall_t) syscall_silent_stub, // futex_time64
    [439] = (syscall_t) syscall_silent_stub, // faccessat2
};

#define NUM_SYSCALLS (sizeof(syscall_table) / sizeof(syscall_table[0]))

void dump_stack(int lines);

#if !GUEST_AARCH64
void handle_interrupt(int interrupt) {
    struct cpu_state *cpu = &current->cpu;
    if (interrupt == INT_SYSCALL) {
        unsigned syscall_num = cpu->eax;
        if (syscall_num >= NUM_SYSCALLS || syscall_table[syscall_num] == NULL) {
            printk("%d(%s) missing syscall %d\n", current->pid, current->comm, syscall_num);
            cpu->eax = _ENOSYS;
        } else {
            if (syscall_table[syscall_num] == (syscall_t) syscall_stub) {
                printk("%d(%s) stub syscall %d\n", current->pid, current->comm, syscall_num);
            }
            STRACE("%d call %-3d ", current->pid, syscall_num);
            int result = syscall_table[syscall_num](cpu->ebx, cpu->ecx, cpu->edx, cpu->esi, cpu->edi, cpu->ebp);
            STRACE(" = 0x%x\n", result);
            cpu->eax = result;
        }
    } else if (interrupt == INT_GPF) {
        // some page faults, such as stack growing or CoW clones, are handled by mem_ptr
        read_wrlock(&current->mem->lock);
        void *ptr = mem_ptr(current->mem, cpu->segfault_addr, cpu->segfault_was_write ? MEM_WRITE : MEM_READ);
        read_wrunlock(&current->mem->lock);
        if (ptr == NULL) {
            printk("%d page fault on 0x%x at 0x%x\n", current->pid, cpu->segfault_addr, cpu->eip);
            struct siginfo_ info = {
                .code = mem_segv_reason(current->mem, cpu->segfault_addr),
                .fault.addr = cpu->segfault_addr,
            };
            dump_stack(8);
            deliver_signal(current, SIGSEGV_, info);
        }
    } else if (interrupt == INT_UNDEFINED) {
        printk("%d illegal instruction at 0x%x: ", current->pid, cpu->eip);
        for (int i = 0; i < 8; i++) {
            uint8_t b;
            if (user_get(cpu->eip + i, b))
                break;
            printk("%02x ", b);
        }
        printk("\n");
        dump_stack(8);
        struct siginfo_ info = {
            .code = SI_KERNEL_,
            .fault.addr = cpu->eip,
        };
        deliver_signal(current, SIGILL_, info);
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
#endif

void dump_maps(void) {
    extern void proc_maps_dump(struct task *task, struct proc_data *buf);
    struct proc_data buf = {};
    proc_maps_dump(current, &buf);
    // go a line at a time because it can be fucking enormous
    char *orig_data = buf.data;
    while (buf.size > 0) {
        size_t chunk_size = buf.size;
        if (chunk_size > 1024)
            chunk_size = 1024;
        printk("%.*s", chunk_size, buf.data);
        buf.data += chunk_size;
        buf.size -= chunk_size;
    }
    free(orig_data);
}

void dump_mem(addr_t start, uint_t len) {
    const int width = 8;
    for (addr_t addr = start; addr < start + len; addr += sizeof(dword_t)) {
        unsigned from_left = (addr - start) / sizeof(dword_t) % width;
        if (from_left == 0)
            printk("%08x: ", addr);
        dword_t word;
        if (user_get(addr, word))
            break;
        printk("%08x ", word);
        if (from_left == width - 1)
            printk("\n");
    }
}

#if !GUEST_AARCH64
void dump_stack(int lines) {
    printk("stack at %x, base at %x, ip at %x\n", current->cpu.esp, current->cpu.ebp, current->cpu.eip);
    dump_mem(current->cpu.esp, lines * sizeof(dword_t) * 8);
}
#endif

#endif /* GUEST_AARCH64 */

// TODO find a home for this
#ifdef LOG_OVERRIDE
int log_override = 0;
#endif
