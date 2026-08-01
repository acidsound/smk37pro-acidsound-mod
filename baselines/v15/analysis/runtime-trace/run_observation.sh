#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
source_file="$root/baselines/v15/analysis/runtime-trace/v15_usb_midi_observer.c"
binary="$root/build/runtime-trace/v15-usb-midi-observer"
serial=${V15_SERIAL:-1120041B00020312}
mode=${1:---dry-run}
group=${2:-all}

mkdir -p "$root/build/runtime-trace"
cc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror \
  $(pkg-config --cflags libusb-1.0) \
  "$source_file" -o "$binary" \
  $(pkg-config --libs libusb-1.0)

case "$mode" in
  --dry-run)
    exec "$binary" --dry-run "$group"
    ;;
  --enumerate)
    exec "$binary" --enumerate --expect-serial "$serial"
    ;;
  --execute)
    if [ "${EXECUTE_V15_USB_MIDI:-}" != YES ]; then
      echo "refusing live OUT traffic: set EXECUTE_V15_USB_MIDI=YES" >&2
      exit 2
    fi
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    log="$root/baselines/v15/analysis/runtime-trace/runtime-$stamp.tsv"
    echo "logging to $log" >&2
    exec "$binary" --execute "$group" --expect-serial "$serial" --log "$log"
    ;;
  *)
    echo "usage: $0 [--dry-run|--enumerate|--execute] [all|cables|channels|cin|program|cc|pitch|sysex|malformed]" >&2
    exit 2
    ;;
esac
