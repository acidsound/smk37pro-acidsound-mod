# SDK signature tooling

This directory is self-contained evidence for the pinned public AC79 SDK versus
the exact official SMK37 v15 application. The conclusion and interpretation are
in [evidence.md](evidence.md).

## Files

- `scan_sdk.py`: hash-guarded archive inventory, exact `sdk.elf` function
  matcher, and exact-v15 string/constant/pointer/region fingerprints.
- `reproduce_objects.sh`: extracts selected LLVM bitcode members and rebuilds
  relocation-bearing pi32v2 objects with the official compiler.
- `match_relocated_objects.py`: masks pi32v2 relocations and applies the
  calibrated fixed-island/window criterion.
- `report.json`: deterministic exact scan output.
- `midi-object-matches.json`: seven MIDI objects, 57 functions, no accepted
  matches; retains the one rejected isolated window.
- `calibration-object-matches.json`: positive controls from `gpio.c.o` and
  `sdfile_new.c.o`, with twenty-one accepted v15 functions.
- `SHA256SUMS`: hashes of this evidence set.

## Inputs

```text
SDK URL:    https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK
SDK branch: release/AC79NN_SDK_V1.2.0
SDK commit: e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d
v15 SHA256: 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055
```

The scripts refuse a different SDK checkout or app hash.

## Exact scan

```sh
git clone --filter=blob:none \
  https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK.git ac79-sdk
git -C ac79-sdk checkout --detach \
  e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d

python3 scan_sdk.py /absolute/path/ac79-sdk \
  /absolute/path/v15-official-app.bin --output report.reproduced.json
cmp report.json report.reproduced.json
```

## Official-toolchain object rebuild

The official Linux toolchain URL used for this run resolved from Jieli's public
`https://pkgman.jieliapp.com/s/linux-toolchain` link to:

```text
https://jl-update.oss-cn-shenzhen.aliyuncs.com/jieli-linux-toolchains-20250805.1.tar.xz
SHA256 f686586bcfb45e0f0bb27fd2b39c7a7f313cb4f0e88a66a14da621ffa8225958
```

The executable is x86-64 Linux. Run it on x86-64 Linux or under a compatible
runtime. The compiler reports clang 4.0.1. Given its `pi32v2/bin/clang`:

```sh
./reproduce_objects.sh /absolute/path/ac79-sdk \
  /absolute/path/toolchain/pi32v2/bin/clang /absolute/path/generated
```

The matcher canonicalizes function bytes and relocations, excluding
debug-path-sensitive ELF metadata. Expected canonical signatures are:

```text
7d8c6f195cb0cb30a85aa0fdc895596121216f3c17aac2a69ceee4ffa8bb5edf  midi_ctrl_decoder.pi32.o (6 functions)
8ebd9baf882a06fcfe34e601d3e6d49cc2849e9debd0faf32ffcb86999369bc3  midi_dec.pi32.o (18 functions)
0fd4d05bb32392b6eb35466267c0fa53fa798d585c9353d02342da333d12ccb3  midi_event.pi32.o (9 functions)
5e941d8e85ef0da83eb4ea2b62c61850de50bbbf38a51fb4f53e42c85a533285  midi_fread_tone.pi32.o (3 functions)
2fc512abc158eff6b45c7b7434efb150be3876ddb991c562450bc06b11b580b2  midi_play.pi32.o (12 functions)
542ad95c5f8c9a93b56a64f784a24171f92de97ea301fb2f230f3c61e6c0a846  midi_synth.pi32.o (9 functions)
4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945  midi_tabs.pi32.o (0 functions; data tables only)
```

Then run the matcher:

```sh
python3 match_relocated_objects.py /absolute/path/v15-official-app.bin \
  /absolute/path/generated/midi_ctrl_decoder.pi32.o \
  /absolute/path/generated/midi_dec.pi32.o \
  /absolute/path/generated/midi_event.pi32.o \
  /absolute/path/generated/midi_fread_tone.pi32.o \
  /absolute/path/generated/midi_play.pi32.o \
  /absolute/path/generated/midi_synth.pi32.o \
  /absolute/path/generated/midi_tabs.pi32.o \
  --output midi-object-matches.reproduced.json
```

Paths are intentionally omitted from semantic comparison because the saved
JSON records object basenames and canonical code signatures. No command here
patches or flashes a device.
