# v15 PI32 and USB MIDI static analysis

## Scope and result

This analysis used only:

- `build/v15-official-app.bin`
- `baselines/v15/official/package-manifest.json`
- internal bytes and pointers from that image
- public PI32 tooling documentation

Input SHA-256:

```text
36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055
```

**Defensible result:** the image contains a coherent USB MIDI 1.0 descriptor set, MIDI endpoint descriptors, a canonical Code Index Number payload-length table, and MIDI-related strings. The runtime image base is strongly supported as `0x02000000`. No USB MIDI receive or dispatch function entry point was identified defensibly. No patching or flashing was performed.

## Address model

These are different address spaces and must not be combined:

| Address kind | Formula | Evidence | Confidence |
|---|---:|---|---|
| File offset | offset in `v15-official-app.bin` | direct byte position | High |
| Package/flash storage offset | file offset + `0x4120` | v15 package manifest `layout.app_data_start = 16672` | High |
| Runtime virtual address | file offset + `0x02000000` | repeated internal absolute pointers to exact long-string offsets | High |

The package value `0x4120` is a storage offset, not a runtime base. Adding it to the runtime base produces `0x02004120`, which has zero exact references to long strings in the test below.

### Runtime-base evidence

`analyze_v15.py` derives 64-KiB-aligned base candidates from this image by subtracting each long ASCII string's file offset from plausible internal absolute pointer values. `0x02000000` ranks first with 7 references to 5 distinct targets. The next candidate has only 2 references to 1 target.

| Pointer location in file | Pointer value | Exact target file offset | Target text |
|---:|---:|---:|---|
| `0x004a62` | `0x02057954` | `0x57954` | `app_area_head` |
| `0x01e044` | `0x02057b20` | `0x57b20` | `Enable SEQ first` |
| `0x057a80` | `0x0205da41` | `0x5da41` | `sdfile_fat` |
| `0x057a90` | `0x0205da41` | `0x5da41` | `sdfile_fat` |
| `0x058174` | `0x0205da41` | `0x5da41` | `sdfile_fat` |
| `0x058304` | `0x0205d9c5` | `0x5d9c5` | `Pad Bank-` |
| `0x058314` | `0x0205d9e9` | `0x5d9e9` | `Keys Channel-` |

The script also directly scores both interpretations:

| Candidate | Distinct exact long-string targets | Exact pointer references | Interpretation |
|---:|---:|---:|---|
| `0x02000000` | 5 | 7 | selected runtime base |
| `0x02004120` | 0 | 0 | rejected storage-offset category error |

## PI32 tooling

| Tool | Availability/result | Limit |
|---|---|---|
| Apple LLVM `objdump` 21.0.0 | Installed | No PI32 target was available |
| radare2 6.1.8 | Installed | `rasm2 -L` contains no `pi32`, `jieli`, or `q32` plugin |
| Rizin, `llvm-objdump`, SDCC | Not found in `PATH` | Not evaluated further |
| Ghidra 12.1.2 + [`kagaimiq/ghidra-jieli`](https://github.com/kagaimiq/ghidra-jieli) with the repository's `ghidra-jieli-pi32v2-smk37.patch` | Usable for a limited pi32v2 headless probe | Upstream calls pi32v2 “very early stage”; the local patch adds only the specific call, branch, move, immediate, and stack-load forms listed in that patch. Many instructions, loops, parallel execution, stack semantics, and flag effects remain incomplete |

The run pinned `ghidra-jieli` commit:

```text
b5e60122b6cd3e6b615387035994b8bed0ea1a26
```

It then applied the tracked, reviewable decoder supplement:

```text
patches/ghidra-jieli-pi32v2-smk37.patch
```

The public PI32 notes describe a little-endian 32-bit architecture using 16-bit instruction words and an ELF machine ID of `0xF0`: <https://github.com/kagaimiq/jielie/blob/main/cpu/pi32.md>.

Validated environment: Ghidra 12.1.2 and OpenJDK 21.0.11 on macOS arm64.
The project language was asserted as `pi32v2:LE:32:default`. Results remain
heuristic because both the upstream model and the narrow local supplement are
incomplete. Constant propagation also emitted p-code/construction failures.

## USB MIDI evidence

Every listed byte pattern occurs exactly once.

| Evidence | File offset | Runtime VA | Flash offset | Interpretation | Confidence |
|---|---:|---:|---:|---|---|
| ASCII `midi_route\0` | `0x5773b` | `0x0205773b` | `0x5b85b` | MIDI routing component name | Medium |
| MIDIStreaming interface `09 04 00 00 02 01 03 00 00` | `0x579ae` | `0x020579ae` | `0x5bace` | Audio class, MIDIStreaming subclass, two endpoints | High |
| MIDIStreaming class header `07 24 01 00 01 81 00` | `0x579b7` | `0x020579b7` | `0x5bad7` | USB MIDI 1.0 class-specific header | High |
| CIN payload lengths `00 00 02 03 03 01 02 03 03 03 03 03 02 02 03 01` | `0x57ab0` | `0x02057ab0` | `0x5bbd0` | Canonical USB MIDI CIN 0x0 through 0xf payload-byte counts | High |
| USB device descriptor | `0x57b53` | `0x02057b53` | `0x5bc73` | USB 2.0, EP0 64 bytes, VID `0x4353`, PID `0x4b4d`, one configuration | High |
| UTF-16LE `SMK-37 Pro Midi` | `0x57fa8` | `0x02057fa8` | `0x5c0c8` | USB product string | High |
| MIDI IN endpoint `09 05 84 02 40 00 00 00 00` | `0x57fc6` | `0x02057fc6` | `0x5c0e6` | Device-to-host bulk endpoint `0x84`, max packet 64 | High |
| IN class endpoint `07 25 01 03 08 0a 0c` | `0x57fcf` | `0x02057fcf` | `0x5c0ef` | Three associated embedded MIDI jacks | High |
| MIDI OUT endpoint `09 05 04 02 40 00 00 00 00` | `0x57fd6` | `0x02057fd6` | `0x5c0f6` | Host-to-device bulk endpoint `0x04`, max packet 64 | High |
| OUT class endpoint `07 25 01 03 01 03 05` | `0x57fdf` | `0x02057fdf` | `0x5c0ff` | Three associated embedded MIDI jacks | High |
| Coherent 12-descriptor MIDI jack graph | `0x58274` | `0x02058274` | `0x5c394` | Embedded/external IN and OUT jack topology | High |

Descriptor presence proves that the bytes encode a coherent USB MIDI configuration template. It does not by itself prove that the firmware activates that configuration at runtime.

## Receive/dispatch search and unresolved result

`V15Pi32Xrefs.java` imports the exact image at `0x02000000`, requires
`pi32v2:LE:32:default`, and heuristically seeds disassembly only from even
internal pointers below the descriptor/string area. A seed is not asserted to
be a function entry. Ghidra then runs analysis and checks:

1. all decoded PI32 call instructions and direct call references,
2. direct references to each MIDI string, descriptor, endpoint, jack graph, and CIN table,
3. every decoded instruction reference into runtime region `0x02057000..0x020584ff`.

Clean-run result:

| Measurement | Result |
|---|---:|
| Pointer-derived seeds | 663 |
| Seeds accepted by disassembler | 663 |
| Decoded instructions | 2,079 |
| Decoded call instructions | 217 |
| Direct call references | 202 |
| Xrefs to each named USB/MIDI target | 0 |
| Instruction references into the complete evidence region | 0 |

Ghidra also emitted p-code and constant-propagation failures, consistent with
the processor model's documented incompleteness. Consequently, zero xrefs is
not proof that the runtime code has no receive path. It means this incomplete
pi32v2 toolchain and these defensible seeds did not recover one.

**No address is reported as a USB MIDI receive or dispatch entry point.** Descriptor-adjacent pointer groups and partially decoded blocks were rejected as candidates because linker adjacency is not a call/data xref, several targets did not decode cleanly, and no caller chain connected them to endpoint `0x04`, the CIN table, or `midi_route`.

Evidence that could upgrade this result includes a more complete PI32 processor model, a trustworthy vendor disassembler, symbols or a link map for this exact image, or runtime tracing of host-to-device endpoint `0x04`. None was available here.

## Reproduction

From the repository root:

```bash
python3 baselines/v15/analysis/analyze_v15.py
python3 baselines/v15/analysis/analyze_v15.py --json
```

The script refuses any image whose SHA-256 differs from the value at the top of this report and verifies the v15 manifest hash and size.

Prepare the pinned Ghidra module in scratch space. The runner applies the
tracked decoder supplement itself:

```bash
git clone https://github.com/kagaimiq/ghidra-jieli.git /path/to/ghidra-jieli
git -C /path/to/ghidra-jieli checkout b5e60122b6cd3e6b615387035994b8bed0ea1a26
```

With an extracted Ghidra 12.1.2 directory and JDK 21:

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC \
GHIDRA_JIELI_DIR=/path/to/ghidra-jieli \
JCODE_JAVA_HOME=/path/to/jdk-21/Contents/Home \
WORK_DIR="$HOME/jcode-v15-analysis-work" \
  bash baselines/v15/analysis/run_ghidra_upstream.sh
```

The runner verifies the image SHA-256 and plugin commit before importing. Its Ghidra log is written only to `WORK_DIR`, not to the repository.
