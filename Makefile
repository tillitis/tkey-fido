.PHONY: all
all: apps tkey-fido

DESTDIR=/
PREFIX=/usr/local
SYSTEMDDIR=/etc/systemd
UDEVDIR=/etc/udev
destbin=$(DESTDIR)/$(PREFIX)/bin
destman1=$(DESTDIR)/$(PREFIX)/share/man/man1
destunit=$(DESTDIR)/$(SYSTEMDDIR)/user
destrules=$(DESTDIR)/$(UDEVDIR)/rules.d
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

.PHONY: apps
apps:
	$(MAKE) -C apps

.PHONY: apps/fido/app.bin
apps/fido/app.bin:
	make -C apps fido/app.bin

TKEY_FIDO_VERSION ?=
# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-fido
tkey-fido: apps/fido/app.bin
	cp -af apps/fido/app.bin cmd/tkey-fido/app.bin
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(TKEY_FIDO_VERSION)" -trimpath ./cmd/tkey-fido

.PHONY: clean
clean:
	rm -f tkey-fido
	$(MAKE) -C apps clean

.PHONY: lint
lint:
	$(MAKE) -C gotools
	GOOS=linux   ./gotools/golangci-lint run
	GOOS=windows ./gotools/golangci-lint run
