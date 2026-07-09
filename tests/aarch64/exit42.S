    .global _start
    .section .text
_start:
    movz x8, #93, lsl #0
    movz x0, #42, lsl #0
    svc #0
