# SPDX-License-Identifier: GPL-2.0
CFLAGS_REMOVE_empty.o += $(CC_FLAGS_LTO)

hostprogs-always-y	+= modpost mk_elfconfig
always-y		+= empty.o

modpost-objs	:= modpost.o file2alias.o sumversion.o symsearch.o

devicetable-offsets-file := devicetable-offsets.h

$(obj)/$(devicetable-offsets-file): $(obj)/devicetable-offsets.s FORCE
	$(call filechk,offsets,__DEVICETABLE_OFFSETS_H__)

targets += $(devicetable-offsets-file) devicetable-offsets.s

# dependencies on generated files need to be listed explicitly

$(obj)/modpost.o $(obj)/file2alias.o $(obj)/sumversion.o $(obj)/symsearch.o: $(obj)/elfconfig.h
$(obj)/file2alias.o: $(obj)/$(devicetable-offsets-file)

quiet_cmd_elfconfig = MKELF   $@
      cmd_elfconfig = $(obj)/mk_elfconfig < $< > $@

# For PE/COFF targets (LKL on Windows), empty.o is not ELF so mk_elfconfig
# fails. Generate a static elfconfig.h instead.
ifneq ($(filter pe-%,$(CONFIG_OUTPUT_FORMAT)),)
$(obj)/elfconfig.h: FORCE
	$(Q)echo '#define KERNEL_ELFCLASS ELFCLASS64' > $@
	$(Q)echo '#define KERNEL_ELFDATA ELFDATA2LSB' >> $@
else
$(obj)/elfconfig.h: $(obj)/empty.o $(obj)/mk_elfconfig FORCE
	$(call if_changed,elfconfig)
endif
