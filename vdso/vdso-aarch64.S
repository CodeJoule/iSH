    .text
    .global __kernel_rt_sigreturn
    .type __kernel_rt_sigreturn,@function
__kernel_rt_sigreturn:
    mov x8, #139
    svc #0
    nop

    .global __kernel_sigreturn
    .type __kernel_sigreturn,@function
__kernel_sigreturn:
    // aarch64 only has rt_sigreturn (NR 139); keep alias for ABI completeness
    mov x8, #139
    svc #0
    nop
