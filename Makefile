CC ?= cc
PKG_CONFIG ?= pkg-config
LIBUSB_MIN_VERSION := 1.0.30

ifeq ($(shell $(PKG_CONFIG) --atleast-version=$(LIBUSB_MIN_VERSION) libusb-1.0 2>/dev/null && echo yes),)
$(error libusb >= $(LIBUSB_MIN_VERSION) is required)
endif

CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic $(shell $(PKG_CONFIG) --cflags libusb-1.0)
LDLIBS += $(shell $(PKG_CONFIG) --libs libusb-1.0)

BUILD_DIR := build
TARGET := $(BUILD_DIR)/smk37-fw
MACOS_WL82_TARGET := $(BUILD_DIR)/smk37-wl82-macos
MACOS_WL82_BOT_TARGET := $(BUILD_DIR)/smk37-wl82-macos-bot
MACOS_WL82_IOKIT_BOT_TARGET := $(BUILD_DIR)/smk37-wl82-macos-iokit-bot
MACOS_WL82_RECOVERY_TARGET := $(BUILD_DIR)/smk37-wl82-macos-iokit-recovery
SOURCES := src/device_info.c src/flash_read.c src/fwsc.c src/main.c src/ota.c src/protocol.c src/sha256.c src/usb_probe.c

# Device-side SMK OTA transport mirror (ac79/app/) differentially tested against
# the host-side reference src/protocol.c. Builds host-native; needs no libusb.
OTA_COMPAT_TARGET := $(BUILD_DIR)/host-compat-test
OTA_COMPAT_SOURCES := ac79/test/host_compat_test.c ac79/app/smk_ota_transport.c src/protocol.c
# Real captured request triples for the optional replay stage. logs/ is gitignored,
# so the test falls back to its self-contained differential suite when absent.
OTA_COMPAT_TRANSCRIPT ?= logs/v15/ota-v15-s1c6-reset-sig-20260814.log

# B1 device-side USB descriptor evidence set (ac79/app/). Its 18-byte device
# descriptor and its recovered product-name text are checked byte for byte
# against a live flash dump when one is given; its MIDIStreaming interface
# fragment is evidence-pinned, and the test re-derives every pinned field from
# docs/research-notes.md and baselines/v15/device-info/probe.txt on every run.
# The test FAILS CLOSED if either document is absent (SMK_REPO_ROOT selects the
# document root), so a PASS always means the evidence was actually read.
USB_DESC_TARGET := $(BUILD_DIR)/usb-descriptor-test
USB_DESC_SOURCES := ac79/test/usb_descriptor_test.c ac79/app/smk_usb_descriptors.c src/sha256.c
# One or more whole-flash dump paths (space separated) to check the descriptor
# set against. Every dump given is searched and, when it carries the identity,
# compared byte for byte with what the app would serve.
SMK_LIVE_DUMP ?= $(HOME)/Documents/SMK37ProMod/build/M10-baseline-before-flash-20260801-a.bin

.PHONY: all clean test test-ota-transport test-usb-descriptors test-safe-repack macos-wl82 macos-wl82-bot macos-wl82-iokit-bot macos-wl82-recovery

all: $(TARGET)

$(TARGET): $(SOURCES) src/device_info.h src/flash_read.h src/fwsc.h src/ota.h src/protocol.h src/sha256.h src/usb_probe.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDLIBS)

macos-wl82: $(MACOS_WL82_TARGET)

macos-wl82-bot: $(MACOS_WL82_BOT_TARGET)

macos-wl82-iokit-bot: $(MACOS_WL82_IOKIT_BOT_TARGET)

macos-wl82-recovery: $(MACOS_WL82_RECOVERY_TARGET)

$(MACOS_WL82_TARGET): tools/smk37_wl82_macos.c | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic $< -o $@ -framework IOKit -framework CoreFoundation

$(MACOS_WL82_BOT_TARGET): tools/smk37_wl82_macos_bot.c | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic $< -o $@ $(shell $(PKG_CONFIG) --cflags --libs libusb-1.0)

$(MACOS_WL82_IOKIT_BOT_TARGET): tools/smk37_wl82_macos_iokit_bot.c | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic $< -o $@ -framework IOKit -framework CoreFoundation

$(MACOS_WL82_RECOVERY_TARGET): tools/smk37_wl82_macos_iokit_recovery.c | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc $< src/sha256.c -o $@ -framework IOKit -framework CoreFoundation

$(BUILD_DIR):
	mkdir -p $@

$(OTA_COMPAT_TARGET): $(OTA_COMPAT_SOURCES) ac79/app/smk_ota_transport.h src/protocol.h | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Isrc -Iac79/app $(OTA_COMPAT_SOURCES) -o $@

test-ota-transport: $(OTA_COMPAT_TARGET)
	@if [ -f "$(OTA_COMPAT_TRANSCRIPT)" ]; then \
		$(OTA_COMPAT_TARGET) "$(OTA_COMPAT_TRANSCRIPT)"; \
	else \
		echo "note: transcript $(OTA_COMPAT_TRANSCRIPT) absent (gitignored); running self-contained differential test only"; \
		$(OTA_COMPAT_TARGET); \
	fi

$(USB_DESC_TARGET): $(USB_DESC_SOURCES) ac79/app/smk_usb_descriptors.h src/sha256.h | $(BUILD_DIR)
	$(CC) -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Isrc -Iac79/app $(USB_DESC_SOURCES) -o $@

test-usb-descriptors: $(USB_DESC_TARGET)
	@if [ -f "$(firstword $(SMK_LIVE_DUMP))" ]; then \
		SMK_REPO_ROOT=$(CURDIR) $(USB_DESC_TARGET) $(SMK_LIVE_DUMP); \
	else \
		echo "note: live dump $(firstword $(SMK_LIVE_DUMP)) absent; the recovered bytes are then only ""checked against the test's transcription, but the evidence ledger is still re-derived from the record"; \
		SMK_REPO_ROOT=$(CURDIR) $(USB_DESC_TARGET); \
	fi

test: $(TARGET)
	$(TARGET) self-test
	$(MAKE) test-ota-transport
	$(MAKE) test-usb-descriptors
	python3 tools/smk37_app_patch.py self-test
	python3 tools/check_sdk_app_layout.py --self-test
	python3 tools/check_sdk_app_layout.py --check-target
	@if [ "$$(uname -s)" = Darwin ]; then \
		$(MAKE) macos-wl82 >/dev/null && $(MACOS_WL82_TARGET) self-test; \
		$(MAKE) macos-wl82-recovery >/dev/null && $(MACOS_WL82_RECOVERY_TARGET) self-test; \
	fi
	python3 -m py_compile tools/prepare_macos_restore_plan.py

test-safe-repack:
	@test -n "$(FWSC)" || (echo "usage: make test-safe-repack FWSC=path/to/SMK-37_Pro_012.fwsc" >&2; exit 2)
	python3 tools/smk37_app_patch.py roundtrip "$(FWSC)" build/v12-roundtrip.fwsc \
		--manifest build/v12-roundtrip-manifest.json
	@cmp -s "$(FWSC)" build/v12-roundtrip.fwsc
	@echo "official v12 no-op roundtrip: byte-identical PASS"

clean:
	rm -f $(TARGET) $(OTA_COMPAT_TARGET) $(USB_DESC_TARGET) $(MACOS_WL82_TARGET) $(MACOS_WL82_BOT_TARGET) $(MACOS_WL82_IOKIT_BOT_TARGET) $(MACOS_WL82_RECOVERY_TARGET)
