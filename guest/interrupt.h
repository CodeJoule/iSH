#ifndef GUEST_INTERRUPT_H
#define GUEST_INTERRUPT_H

#include "guest/guest-config.h"

#if GUEST_AARCH64

#define INT_NONE -1
#define INT_UNDEFINED 6
#define INT_BREAKPOINT 3
#define INT_DEBUG 1
#define INT_GPF 13
#define INT_TIMER 32
#define INT_SYSCALL 0x100

#else

#include "emu/interrupt.h"

#endif

#endif
