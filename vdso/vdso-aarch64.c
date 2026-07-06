#if !defined(__aarch64__) || !defined(__ELF__)
#error "VDSO must be built for aarch64 elf"
#endif

typedef long time_t;
typedef int clockid_t;

time_t __vdso_time(time_t *t) {
    time_t result;
    register long x0 __asm__("x0") = 201;
    register time_t *x1 __asm__("x1") = t;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1) : "memory", "x8");
    return x0;
}

int __vdso_gettimeofday(void *timeval, void *timezone) {
    register long x0 __asm__("x0") = 169;
    register void *x1 __asm__("x1") = timeval;
    register void *x2 __asm__("x2") = timezone;
    __asm__ volatile("mov x8, %1\n\t svc #0" : "+r"(x0) : "r"(x0), "r"(x1), "r"(x2) : "x8", "memory");
    return (int) x0;
}

int __vdso_clock_gettime(clockid_t clock, void *timespec) {
    register long x0 __asm__("x0") = 113;
    register clockid_t x1 __asm__("x1") = clock;
    register void *x2 __asm__("x2") = timespec;
    __asm__ volatile("mov x8, %1\n\t svc #0" : "+r"(x0) : "r"(x0), "r"(x1), "r"(x2) : "x8", "memory");
    return (int) x0;
}
