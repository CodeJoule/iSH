#ifndef GUEST_CONFIG_H
#define GUEST_CONFIG_H

/* Dual-arch build: select guest ISA at compile time via meson guest_arch option. */
#if defined(GUEST_ARCH_AARCH64)
#define GUEST_AARCH64 1
#define GUEST_I386 0
#elif defined(GUEST_ARCH_I386)
#define GUEST_AARCH64 0
#define GUEST_I386 1
#else
#define GUEST_I386 1
#define GUEST_AARCH64 0
#endif

#endif
