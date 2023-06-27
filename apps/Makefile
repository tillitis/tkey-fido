OBJCOPY ?= llvm-objcopy
CC = clang

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../../tkey-libs

INCLUDE=$(LIBDIR)/include

# If you want libcommon's qemu_puts() et cetera to output something on our QEMU
# debug port, recompile tkey-libs and remove -DNODEBUG
CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration \
   -I $(INCLUDE) -I $(LIBDIR) -I . \
   -DNODEBUG

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS=-T $(LIBDIR)/app.lds -L $(LIBDIR)/libcommon/ -lcommon -L $(LIBDIR)/libcrt0/ -lcrt0 -L $(LIBDIR)/monocypher -lmonocypher

.PHONY: all
all: fido/app.bin

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-%-hash: %/app.bin
	cd $$(dirname $^) && sha512sum app.bin

check-fido-hash: fido/app.bin
	cd fido && { printf "got:\n"; sha512sum app.bin; printf "expected:\n"; cat app.bin.sha512; sha512sum -c app.bin.sha512; }

FIDOOBJS=fido/main.o fido/app_proto.o fido/rng.o fido/p256-m.o fido/sha-256.o fido/u2f.o
fido/app.elf: $(FIDOOBJS)
	$(CC) $(CFLAGS) $(FIDOOBJS) $(LDFLAGS) -L monocypher -lmonocypher -I monocypher -o $@
$(FIDOOBJS): $(INCLUDE)/tk1_mem.h fido/app_proto.h

.PHONY: clean
clean:
	$(RM) -f fido/app.bin fido/app.elf $(FIDOOBJS)

# Uses ../.clang-format
FMTFILES=fido/main.c fido/u2f.[ch] fido/rng.[ch]
.PHONY: fmt
fmt:
	clang-format --dry-run --ferror-limit=0 $(FMTFILES)
	clang-format --verbose -i $(FMTFILES)
.PHONY: checkfmt
checkfmt:
	clang-format --dry-run --ferror-limit=0 --Werror $(FMTFILES)

.PHONY: update-mem-include
update-mem-include:
	cp -af ../../tillitis-key1/hw/application_fpga/fw/tk1_mem.h include/tk1_mem.h
