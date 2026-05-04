#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Print the C compiler output file format, as determined by objdump.
# Use a temp file in cwd (not /tmp) to avoid Wine/Cygwin path mapping issues.
t=".tmp_cc_fmt_$$"
echo 'void foo(void) {}' | $CC -x c - -c -o "$t" \
	&& LC_ALL=C $OBJDUMP -p "$t" | awk '/file format/ {print $4}'
rm -f "$t"
