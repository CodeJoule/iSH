    .global _start
    .section .text
_start:
    movz x8, #64, lsl #0
    movz x0, #1, lsl #0
    adr x1, msg
    movz x2, #6, lsl #0
    svc #0
    movz x8, #93, lsl #0
    movz x0, #0, lsl #0
    svc #0
msg:
    .ascii "hello\n"
