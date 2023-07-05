.PHONY: all
all: device-fido/app.bin tkey-fido

DESTDIR=/
PREFIX=/usr/local
SYSTEMDDIR=/etc/systemd
UDEVDIR=/etc/udev
destbin=$(DESTDIR)/$(PREFIX)/bin
destman1=$(DESTDIR)/$(PREFIX)/share/man/man1
destunit=$(DESTDIR)/$(SYSTEMDDIR)/user
destrules=$(DESTDIR)/$(UDEVDIR)/rules.d

OBJCOPY ?= llvm-objcopy
CC = clang

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../tkey-libs

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

.PHONY: install
install:
	install -Dm755 tkey-fido $(destbin)/tkey-fido
	strip $(destbin)/tkey-fido
	install -Dm644 system/60-tkey.rules $(destrules)/60-tkey.rules
.PHONY: uninstall
uninstall:
	rm -f \
	$(destbin)/tkey-fido \
	$(destrules)/60-tkey.rules
.PHONY: reload-rules
reload-rules:
	udevadm control --reload
	udevadm trigger

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-%-hash: %/app.bin
	cd $$(dirname $^) && sha512sum app.bin

check-fido-hash: device-fido/app.bin
	cd device-fido && { printf "got:\n"; sha512sum app.bin; printf "expected:\n"; cat app.bin.sha512; sha512sum -c app.bin.sha512; }

FIDOOBJS=device-fido/main.o device-fido/app_proto.o device-fido/rng.o device-fido/p256/p256-m.o device-fido/sha-256/sha-256.o device-fido/u2f.o
device-fido/app.elf: $(FIDOOBJS)
	$(CC) $(CFLAGS) $(FIDOOBJS) $(LDFLAGS) -L monocypher -lmonocypher -I monocypher -o $@
$(FIDOOBJS): $(INCLUDE)/tk1_mem.h device-fido/app_proto.h

# Uses ../.clang-format
FMTFILES=device-fido/main.c device-fido/u2f.[ch] device-fido/rng.[ch]
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

TKEY_FIDO_VERSION ?=
# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-fido
tkey-fido: device-fido/app.bin
	cp -af device-fido/app.bin cmd/tkey-fido/app.bin
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(TKEY_FIDO_VERSION)" -trimpath ./cmd/tkey-fido

.PHONY: clean
clean:
	rm -f tkey-fido \
	device-fido/app.bin device-fido/app.elf $(FIDOOBJS)

.PHONY: lint
lint:
	$(MAKE) -C gotools
	GOOS=linux   ./gotools/golangci-lint run
	GOOS=windows ./gotools/golangci-lint run
