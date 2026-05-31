#include <uapi/asm/unistd.h>

__SYSCALL(__NR_virtio_mmio_device_add, sys_virtio_mmio_device_add)
__SYSCALL(__NR_new_thread_group_leader, sys_new_thread_group_leader)

#define __SC_ASCII(t, a) #t "," #a

#define __ASCII_MAP0(m,...)
#define __ASCII_MAP1(m,t,a) m(t,a)
#define __ASCII_MAP2(m,t,a,...) m(t,a) "," __ASCII_MAP1(m,__VA_ARGS__)
#define __ASCII_MAP3(m,t,a,...) m(t,a) "," __ASCII_MAP2(m,__VA_ARGS__)
#define __ASCII_MAP4(m,t,a,...) m(t,a) "," __ASCII_MAP3(m,__VA_ARGS__)
#define __ASCII_MAP5(m,t,a,...) m(t,a) "," __ASCII_MAP4(m,__VA_ARGS__)
#define __ASCII_MAP6(m,t,a,...) m(t,a) "," __ASCII_MAP5(m,__VA_ARGS__)
#define __ASCII_MAP(n,...) __ASCII_MAP##n(__VA_ARGS__)

#ifdef __MINGW32__
#define SECTION_ATTRS "n0"
#else
#define SECTION_ATTRS "a"
#endif

#ifdef __wasm__
/*
 * wasm-as rejects the ELF .section flags ("a") the native path uses, but it
 * does support real WASM custom sections via the .custom_section.<name>
 * convention. So the wasm hook emits the same syscall-signature text into a
 * custom section named "syscall_defs" (see the asm() below); wasm-ld -r
 * concatenates them and llvm-objcopy --dump-section harvests syscall_defs.h
 * directly from the wasm vmlinux - no mingw32 preseed needed.
 *
 * In addition to the harvest, the wasm __SYSCALL_DEFINE_ARCH hook also
 * emits a per-syscall trampoline `lkl_w_sys<name>(long, long, long, long,
 * long, long)` alongside the regular `sys<name>`. The LKL syscall_table on
 * wasm holds the lkl_w_ wrappers so the dispatcher can call_indirect
 * against a single uniform signature — wasm enforces strict signature
 * matching on call_indirect, and the kernel's per-syscall arities (0..6
 * args, varying types) don't satisfy that.
 *
 * Body strategy: forward into __se_sys<name>(a0..a_{x-1}) — that's the
 * sign-extension wrapper synthesized by __SYSCALL_DEFINEx, which already
 * takes all-long (or `long long` for LL types) args. Calling it directly
 * (no function-pointer indirection) makes the compiler emit a plain
 * `call $__se_sys<name>` at the called signature, no call_indirect.
 *
 * For x=0 there is no __se_; SYSCALL_DEFINE0 only emits the (void)-arg
 * sys_<name>, so we call that instead.
 *
 * On 32-bit, LL-arg syscalls (truncate64, pread64, fallocate, ...) have
 * a `long long` slot in __se_sys_<name> that this 6-long fanout can't
 * pass correctly. unistd_32.h reroutes those entries to sys32_<name>
 * instead (arch/lkl/kernel/syscalls_32.c), so the auto-generated
 * lkl_w_sys_<name> for them is unreachable; we don't actually call it
 * with the wrong slot count. We still emit the symbol so the link
 * resolves, and DCE drops it.
 */
#define __LKL_W_CALL0(name) sys##name()
#define __LKL_W_CALL1(name) __se_sys##name(__a0)
#define __LKL_W_CALL2(name) __se_sys##name(__a0, __a1)
#define __LKL_W_CALL3(name) __se_sys##name(__a0, __a1, __a2)
#define __LKL_W_CALL4(name) __se_sys##name(__a0, __a1, __a2, __a3)
#define __LKL_W_CALL5(name) __se_sys##name(__a0, __a1, __a2, __a3, __a4)
#define __LKL_W_CALL6(name) __se_sys##name(__a0, __a1, __a2, __a3, __a4, __a5)

/*
 * Per-arity forward declarations of the kernel-side worker. We have to
 * match __SYSCALL_DEFINEx's later prototype exactly — K&R () triggers
 * -Wdeprecated-non-prototype + -Wstrict-prototypes under clang and the
 * kernel builds with -Werror. So mirror its __MAP+__SC_LONG construction
 * for x>=1, and use `(void)` for the x=0 path (matches SYSCALL_DEFINE0).
 */
#define __LKL_W_FWD0(name) \
	asmlinkage long sys##name(void);
#define __LKL_W_FWD1(name, ...) \
	asmlinkage long __se_sys##name(__MAP1(__SC_LONG, __VA_ARGS__));
#define __LKL_W_FWD2(name, ...) \
	asmlinkage long __se_sys##name(__MAP2(__SC_LONG, __VA_ARGS__));
#define __LKL_W_FWD3(name, ...) \
	asmlinkage long __se_sys##name(__MAP3(__SC_LONG, __VA_ARGS__));
#define __LKL_W_FWD4(name, ...) \
	asmlinkage long __se_sys##name(__MAP4(__SC_LONG, __VA_ARGS__));
#define __LKL_W_FWD5(name, ...) \
	asmlinkage long __se_sys##name(__MAP5(__SC_LONG, __VA_ARGS__));
#define __LKL_W_FWD6(name, ...) \
	asmlinkage long __se_sys##name(__MAP6(__SC_LONG, __VA_ARGS__));

#define __SYSCALL_DEFINE_ARCH(x, name, ...)				\
	__LKL_W_FWD##x(name, ##__VA_ARGS__)				\
	asmlinkage long lkl_w_sys##name(long, long, long, long, long, long); \
	asmlinkage long lkl_w_sys##name(long __a0, long __a1, long __a2, \
					long __a3, long __a4, long __a5) \
	{								\
		(void)__a0; (void)__a1; (void)__a2;			\
		(void)__a3; (void)__a4; (void)__a5;			\
		return __LKL_W_CALL##x(name);				\
	}								\
	/* Also harvest the syscall signature like the native path, but into a	\
	 * real WASM custom section (.custom_section.<name> -> custom section	\
	 * "syscall_defs"); wasm-ld -r concatenates these and			\
	 * `llvm-objcopy --dump-section syscall_defs` extracts them. This lets	\
	 * the wasm build self-produce syscall_defs.h with no mingw32 preseed. */ \
	asm(".section .custom_section.syscall_defs,\"\",@\n"		\
	    ".ascii \"#ifdef __NR" #name "\\n\"\n"			\
	    ".ascii \"SYSCALL_DEFINE" #x "(" #name ","			\
	    __ASCII_MAP(x, __SC_ASCII, __VA_ARGS__) ")\\n\"\n"		\
	    ".ascii \"#endif\\n\"\n"					\
	    ".text\n");
#else
#define __SYSCALL_DEFINE_ARCH(x, name, ...)				\
	asm(".section .syscall_defs,\"" SECTION_ATTRS "\"\n"		\
	    ".ascii \"#ifdef __NR" #name "\\n\"\n"			\
	    ".ascii \"SYSCALL_DEFINE" #x "(" #name ","			\
	    __ASCII_MAP(x, __SC_ASCII, __VA_ARGS__) ")\\n\"\n"		\
	    ".ascii \"#endif\\n\"\n"					\
	    ".section .text\n");
#endif
