/* SPDX-License-Identifier: GPL-2.0 */
// When building LKL with libFuzzer instrumentation (-fsanitize=fuzzer) provide
// an empty linker script to avoid section merging. For additional information
// refer to arch/lkl/Makefile.postlink.
#if !defined(CONFIG_LKL_FUZZING) || defined(LKL_FUZZING_POSTLINK)

#ifdef __wasm__
/*
 * wasm-ld's GNU-ld-style SECTIONS support (Joel Severin's linux-wasm patch +
 * our LKL-side extensions) is more restricted than full GNU ld:
 *   - SORT_BY_ALIGNMENT() is unsupported; turn it into a no-op.
 *   - Script-defined symbols can't be re-read inside a dot expression, so the
 *     generic INIT_TASK_DATA pattern `. = __start_init_stack + THREAD_SIZE`
 *     fails. Override with a literal ALIGN(THREAD_SIZE) instead.
 *   - STABS_DEBUG / DWARF_DEBUG sections use `.foo 0 : {...}` which wasm-ld
 *     rejects ("setting address for .stab to 0"). Drop them - we keep
 *     symbols/relocs in the wasm `linking` section, not DWARF.
 */
#define SORT_BY_ALIGNMENT(files) files
#endif /* __wasm__ */

#include <asm/vmlinux.lds.h>
#include <asm/thread_info.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <linux/export.h>

#ifdef __wasm__
/*
 * Drop the script-defined symbols (init_stack, __start_init_stack,
 * __end_init_stack, init_thread_union). Script-defined data symbols are
 * emitted with WASM_SYMBOL_ABSOLUTE in the wasm linking section; emcc's
 * stock wasm-ld doesn't resolve those against a real segment in the final
 * link, so relocations referencing them get baked to 0 (we observed
 * init_task.stack == NULL after final link). Instead arch/lkl/kernel/setup.c
 * provides them as C-level aliases of init_thread_info, which IS a real
 * DATA symbol bound to the section.
 */
#undef INIT_TASK_DATA
#define INIT_TASK_DATA(align)						\
	. = ALIGN(align);						\
	KEEP(*(.data..init_thread_info))

#undef STABS_DEBUG
#define STABS_DEBUG
#undef DWARF_DEBUG
#define DWARF_DEBUG
#else
OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT)
#endif /* __wasm__ */

jiffies = jiffies_64;

/* FIXME: symbols defined here outside individual sections don't have a final
 * address assigned because vmlinux is linked incrementally. In the final
 * linking step (when linked against an application) they can be rearranged away
 * from the other adjacent symbols or sections in this file which makes them
 * bogus.
 *
 * Fortunatelly, in most cases their are used for informational purposes only,
 * e.g. printing the init/code/data size early during boot.
 */
SECTIONS
{
	/*
	 * Keep all text symbols in the same section, including init, to keep
	 * kallsyms partially working - at least for functions. This
	 * allows us to get non-bogus stack traces.
	 */
	.text :
	{
		_stext = .;
		_text = . ;
		text = . ;

		. = ALIGN(PAGE_SIZE);
		_sinittext = .;
		INIT_TEXT
		_einittext = .;

		TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT

		_etext = .;
	}

	__init_begin = .;
	INIT_DATA_SECTION(16)
	PERCPU_SECTION(L1_CACHE_BYTES)
	__init_end = .;

	_sdata = .;
	RO_DATA(PAGE_SIZE)
	RW_DATA(L1_CACHE_BYTES, PAGE_SIZE, THREAD_SIZE)
	_edata = .;

	__start_ro_after_init = .;
	.data..ro_after_init : { *(.data..ro_after_init)}
	EXCEPTION_TABLE(16)
	__end_ro_after_init = .;
	NOTES

	BSS_SECTION(0, 0, 0)
	_end = .;

	STABS_DEBUG
	DWARF_DEBUG

	/DISCARD/ : {
		*(.modinfo)
	}

	// Don't include DISCARDS section to build the target with code coverage.
#if !defined(CONFIG_LKL_FUZZING)
	DISCARDS
#endif // !defined(CONFIG_LKL_FUZZING)
}

#endif // !defined(CONFIG_LKL_FUZZING) || defined(LKL_FUZZING_POSTLINK)
