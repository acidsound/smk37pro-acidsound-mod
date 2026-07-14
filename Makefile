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
SOURCES := src/device_info.c src/flash_read.c src/fwsc.c src/main.c src/ota.c src/protocol.c src/sha256.c src/usb_probe.c

.PHONY: all clean test test-safe-repack

all: $(TARGET)

$(TARGET): $(SOURCES) src/device_info.h src/flash_read.h src/fwsc.h src/ota.h src/protocol.h src/sha256.h src/usb_probe.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

test: $(TARGET)
	$(TARGET) self-test
	python3 tools/smk37_app_patch.py self-test

test-safe-repack:
	@test -n "$(FWSC)" || (echo "usage: make test-safe-repack FWSC=path/to/SMK-37_Pro_012.fwsc" >&2; exit 2)
	python3 tools/smk37_app_patch.py roundtrip "$(FWSC)" build/v12-roundtrip.fwsc \
		--manifest build/v12-roundtrip-manifest.json
	@cmp -s "$(FWSC)" build/v12-roundtrip.fwsc
	@echo "official v12 no-op roundtrip: byte-identical PASS"

clean:
	rm -f $(TARGET)
