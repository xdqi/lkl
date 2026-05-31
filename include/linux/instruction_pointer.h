/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INSTRUCTION_POINTER_H
#define _LINUX_INSTRUCTION_POINTER_H

#include <asm/linkage.h>

#define _RET_IP_		(unsigned long)__builtin_return_address(0)

#ifndef _THIS_IP_
#ifdef __wasm__
/*
 * wasm has no computed-goto support and no meaningful PC concept exposed to
 * userland code (wasm functions are opaque indices, not addresses). The
 * address-of-label trick used here doesn't lower; use 0 instead - _THIS_IP_
 * is consumed by lockdep / tracing / WARN paths that only treat it as an
 * opaque token.
 */
#define _THIS_IP_  0UL
#else
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#endif
#endif

#endif /* _LINUX_INSTRUCTION_POINTER_H */
