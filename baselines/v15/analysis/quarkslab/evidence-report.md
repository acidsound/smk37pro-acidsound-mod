# v15 Quarkslab PI32v2 and USB MIDI evidence report

## Conclusion

The pinned Quarkslab `pi32v2` decoder is a material improvement over the
repository's current pinned `kagaimiq/ghidra-jieli` plus local patch. On the
same exact v15 app, base, seeds, Ghidra version, and analysis script, the
recursive phase increased decoded instruction bytes from 4,618 to 149,332 and
recovered 4,214 direct call references instead of 184.

It is not complete enough to identify a USB MIDI receive or dispatch entry
point defensibly. The Quarkslab run still left 103,510 aligned slots undecoded
in the recursive phase and 15,671 after an aggressive sweep. Its log also
contains unresolved constructors, delay-slot context errors, and other p-code
errors. The strongest descriptor and CIN candidates do not form a caller chain
from endpoint `0x04` or the CIN table to a receive and message-dispatch path.

**Final classification:** receive and dispatch were **not identified because
analysis remains decoder/tool limited**. This is not evidence that the code is
absent from v15.

No firmware bytes were changed. Nothing was flashed. No commit was created.
No older-firmware function address, structure, listing, or conclusion was used.

## Scope and evidence policy

Inputs were restricted to:

1. the official v15 package and exact extracted app recorded by the v15
   manifest;
2. bytes and relationships internal to that exact app;
3. public processor modules and public architecture information;
4. the public USB MIDI 1.0 specification.

The analysis did not derive an address or function identity from another
firmware version.

Public sources:

- Quarkslab improved processor module at
  [`e1bd0707874b77b759401555d24839ad43af1267`](https://github.com/quarkslab/ghidra-jieli/tree/e1bd0707874b77b759401555d24839ad43af1267)
- Kagaimiq processor module at
  [`b5e60122b6cd3e6b615387035994b8bed0ea1a26`](https://github.com/kagaimiq/ghidra-jieli/tree/b5e60122b6cd3e6b615387035994b8bed0ea1a26)
- [USB Device Class Definition for MIDI Devices 1.0](https://www.usb.org/sites/default/files/midi10.pdf)
- Public AC79/WL82 architecture and toolchain sources catalogued in
  [`../public-research.md`](../public-research.md)

## Exact input and import

| Item | Value |
|---|---|
| Official package | `build/SMK-37_Pro_015.fwsc` |
| Package SHA-256 | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| Exact app | `build/v15-official-app.bin` |
| App size | 617,012 bytes |
| App SHA-256 | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| Manifest | `baselines/v15/official/package-manifest.json` |
| Ghidra | 12.1.2 |
| Java | OpenJDK 21.0.11 |
| Language | `pi32v2:LE:32:default` |
| BinaryLoader mapped base | `0x02000000` |

`results/v15-byte-evidence.json` independently verifies the app hash, size,
single occurrences of every named USB MIDI byte pattern, and the internal
pointer/string derivation of `0x02000000`.

Ghidra's raw `BinaryLoader` maps the memory block at `0x02000000` while leaving
the program image-base metadata field at zero. `V15DecoderAnalysis.java`
asserts the mapped minimum memory address and hashes all 617,012 mapped bytes.
The logs record both values to avoid conflating loader metadata with the
runtime mapping.

## Pinned decoder artifacts

| Variant | Public revision | Source constructors | Source lines | Ghidra 12.1.2 compiled `.sla` SHA-256 |
|---|---|---:|---:|---|
| Quarkslab | `e1bd0707874b77b759401555d24839ad43af1267` | 326 | 4,630 | `6d774eacaa7f5769ebb536699c6c13500dbb806a265740094464c64951a906d4` |
| Kagaimiq plus repository patch | `b5e60122b6cd3e6b615387035994b8bed0ea1a26` plus patch SHA-256 `298aa34ba5e0c75e94b28f7288825fa9c2c48bb3abe0f6e19551d6bbf46b683d` | 109 | 1,422 | `8499de8322988e0e762c4f4fda72ed36715327c8edd1945e4eba867a3d750fba` |

The Quarkslab source adds broad arithmetic, logic, load/store, stack,
conditional-block, repeat, branch, and parallel-execution coverage. The source
claim is “covers most instructions, some remain unknown.” The Ghidra build log
is consistent with both parts of that claim:

- Quarkslab compiles successfully but reports 50 pi32v2 NOP-semantics
  constructors, two delay-slot warnings, and one converted
  extension/truncation.
- Kagaimiq plus the local patch compiles successfully but has only 109 source
  constructors and two pi32v2 NOP-semantics constructors.

The NOP count does not mean Kagaimiq is more complete. It means Quarkslab
recognizes many more encodings, while some of the newly recognized forms lack
full semantic p-code.

Exact source and file hashes are in
`results/decoder-source-metrics.json`. Build diagnostics are in
`results/*-sleigh-build.log`.

## Analysis method

`V15DecoderAnalysis.java` runs two separately labelled phases over
`0x02000000..0x02056fff`.

### Recursive phase

- seed the mapped base;
- scan the exact app for even internal 32-bit pointers into the pre-evidence
  region and use the 663 unique values as heuristic disassembly seeds;
- follow decoded flow;
- run Ghidra analysis;
- record instructions, bytes, functions, calls, branches, p-code, references,
  scalars, and named-target xrefs.

A pointer-derived seed is not asserted to be a function entry.

### Exhaustive phase

- visit every still-undecoded even address below `0x02057000`;
- attempt flow-following disassembly from it;
- rerun Ghidra analysis;
- export a full TSV listing.

The exhaustive phase is a coverage experiment. It can decode embedded data and
must not establish a function identity by itself.

## Decoder comparison

### Recursive phase

| Metric | Quarkslab | Kagaimiq plus patch |
|---|---:|---:|
| Decoded instructions | 51,089 | 1,893 |
| Decoded instruction bytes | 149,332 | 4,618 |
| Byte coverage of tested region | 41.906% | 1.296% |
| Undecoded aligned slots | 103,510 | 175,867 |
| Functions created | 1,055 | 133 |
| Call instructions | 4,430 | 198 |
| Direct call references | 4,214 | 184 |
| Branch instructions | 6,713 | 204 |
| Computed flows | 271 | 0 |
| References into `0x02057000..0x020584ff` | 479 | 0 |

### Exhaustive phase

| Metric | Quarkslab | Kagaimiq plus patch |
|---|---:|---:|
| Decoded instructions | 112,211 | 91,248 |
| Decoded instruction bytes | 325,010 | 213,736 |
| Byte coverage of tested region | 91.205% | 59.979% |
| Undecoded aligned slots | 15,671 | 71,308 |
| Functions created | 1,668 | 1,375 |
| Direct call references | 7,831 | 6,720 |
| References into evidence region | 759 | 6 |

The Quarkslab improvement is decisive for instruction and control-flow
coverage. The exhaustive result is not “full disassembly” because 31,342 bytes
at aligned starts remain undecoded, some decoded bytes can be data, and p-code
errors persist.

The mechanical comparison is in `results/comparison.md` and
`results/comparison.json`. Complete listings are stored as compressed TSV
files under `results/`.

## USB MIDI evidence anchors

All anchors occur once in the exact app.

| Anchor | Runtime address | Role |
|---|---:|---|
| `midi_route\0` | `0x0205773b` | component-like string |
| MIDIStreaming interface | `0x020579ae` | class `0x01`, subclass `0x03`, two endpoints |
| MIDIStreaming class header | `0x020579b7` | USB MIDI 1.0 class header |
| CIN payload lengths | `0x02057ab0` | canonical 16-entry payload-byte table |
| USB device descriptor | `0x02057b53` | VID `0x4353`, PID `0x4b4d` |
| MIDI IN endpoint | `0x02057fc6` | bulk endpoint `0x84`, 64 bytes |
| MIDI OUT endpoint | `0x02057fd6` | bulk endpoint `0x04`, 64 bytes |
| MIDI jack graph | `0x02058274` | coherent 12-descriptor topology |

The bytes prove that the templates are present. They do not by themselves
prove runtime registration or callback identity.

## Xref and path results

### Narrow evidence-backed absences

A byte-by-byte little-endian scan found zero literal 32-bit pointers to the
start or interior of every named anchor above. This is evidence-backed absence
of those **literal pointer encodings** only.

The recursive Quarkslab result also found no exact xref to:

- `midi_route` start;
- MIDIStreaming interface start;
- CIN table start;
- USB device descriptor start;
- MIDI endpoint starts;
- product string start.

Those zero counts are not evidence that runtime users are absent. PI32v2 can
form addresses from a base plus an immediate, and decoder/p-code failures are
present.

### MIDIStreaming header candidate

Quarkslab produced two recursive parameter xrefs from `FUN_02024d4c` to the
class header at `0x020579b7`:

```text
02024da2  add r1,r4,#0x741
02024dd2  add r1,r4,#0x741
```

The same function sets `r4` to `0x02057276`, selects branches for input values
0, 1, and 2, and passes several derived `r1` values through
`FUN_0201a67c`. Three direct callers were recovered at `0x02027e08`,
`0x02028414`, and `0x02028966`.

This is not a defensible descriptor-registration path:

1. `FUN_0201a67c` calls `FUN_02048eca`, a byte loop that returns the length to
   a zero byte.
2. It allocates or reuses a buffer and calls `FUN_02048e5c`, a zero-terminated
   byte-copy loop.
3. Several decoded source addresses point to plausible short strings such as
   `"sbc"` and `"linein"`.
4. The claimed header target begins `07 24 01 00`, so the same helper would
   treat it as a three-byte zero-terminated value.
5. Other values in the same switch point to an empty value, a one-byte value,
   or the middle of mixed tables.

The xref is therefore retained as a contradictory candidate. It may reflect
an incorrectly decoded immediate or a semantically unrelated short binary
value. It does not identify USB descriptor registration, receive, or dispatch.
This is a decoder/semantic limitation, not evidence of absence.

### `midi_route` candidate

No recursive or literal pointer reference to the string start was recovered.
The exhaustive sweep produced three interior references from
`FUN_02004f06`. The relevant code reads halfwords from a contiguous rodata
range beginning before the string and copies them into RAM in repeat loops.
The recovered operation overlaps `midi_route`, but it never loads
`0x0205773b` as a semantic string pointer.

This is consistent with bulk rodata initialization or relocation. It is not a
route lookup and does not lead to receive or dispatch code.

### CIN-table candidate

The exhaustive sweep recovered a coherent prologue-to-epilogue block at
`0x02000f8e..0x0200104e`. One instruction computes `0x02057abe`, CIN index
14, from base `0x02057250` plus immediate `0x86e`.

Reasons not to promote it to a USB MIDI parser:

- the reference is to a fixed interior byte, not the table start;
- the function was not recovered by the recursive phase;
- there are zero decoded direct callers;
- there are zero raw little-endian function pointers to `0x02000f8e`;
- the function uses a table branch and several unrelated fixed-size copy
  cases, but no chain connects it to endpoint `0x04`, a 4-byte USB MIDI event
  packet loop, MIDI status dispatch, or the descriptor-registration candidate.

This remains an **ambiguous, decoder-limited candidate**. It is not evidence
that a CIN consumer is absent.

### Endpoint and jack interiors

Recursive analysis produced interior references to `0x02057fc8`,
`0x02058278`, and `0x02058280`, but not to the descriptor starts. Two sources
have no recovered enclosing function. One source is in the data region itself.
The decoded operations are lookup, arithmetic, or halfword stores rather than
an endpoint callback registration sequence. Exhaustive-only additions include
an implausible branch into descriptor bytes.

These references were rejected as receive/dispatch evidence.

## Decoder failure versus absence

| Observation | Classification |
|---|---|
| Quarkslab recognizes 326 constructors and recovers much more code | Decoder improvement |
| Quarkslab SLEIGH build reports 50 NOP-semantics pi32v2 constructors | Known semantic decoder gap |
| Headless log contains unresolved constructors, delay-slot context failures, cross-build errors, and other p-code errors | Decoder/tool failure present |
| Recursive phase covers only 41.906% of the tested region | Incomplete recovery |
| Exhaustive phase covers 91.205% but may decode data and still has 15,671 undecoded aligned slots | Incomplete and heuristic recovery |
| Zero literal 32-bit pointers to named anchors | Narrow evidence-backed absence of literal pointers |
| No defensible caller chain from descriptor, CIN, or `midi_route` evidence to endpoint receive and MIDI status dispatch | Not identified |
| No receive/dispatch entry point reported | Tool-limited result, not code absence |

A claim that v15 lacks USB MIDI receive code would require evidence not present
here, such as complete validated PI32v2 decoding, exact symbols or a link map,
or runtime tracing of host-to-device endpoint `0x04`.

## Reproduction

The runner clones both public repositories, pins exact commits, applies the
tracked comparison patch only to a scratch copy, rebuilds both SLEIGH modules,
creates isolated Ghidra copies, verifies app and package hashes, imports at
`0x02000000`, runs both phases, exports listings, extracts candidate traces,
and generates the comparison files.

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC \
JDK_HOME=/path/to/jdk-21/Contents/Home \
WORK_DIR=/large/scratch/smk37-v15-quarkslab \
PROJECT_ROOT="$HOME/jcode-v15-quarkslab-work" \
  bash baselines/v15/analysis/quarkslab/run_analysis.sh
```

`PROJECT_ROOT` must not contain a path component beginning with `.` because
Ghidra rejects hidden project paths. It can be a non-hidden symlink into a
larger scratch filesystem.

## Validation

A clean end-to-end invocation of `run_analysis.sh` completed with exit status
zero in a separate scratch tree. Its generated app metadata, base, language,
phase metrics, anchor summary, and exact/interior target-xref counts matched the
retained `results/comparison.json` exactly.

Additional checks passed:

- every entry in `results/SHA256SUMS` verifies;
- all compressed listings pass `gzip -t`;
- the runner passes `bash -n`, and all Python helpers pass `py_compile`;
- the exact app and package still have the SHA-256 values listed above;
- both clean clones are at their recorded commits with no source changes;
- repository `HEAD` remained unchanged, and Git reports this analysis directory
  only as untracked output;
- no firmware patching, flashing, or commit command was performed.

## Output index

| File | Purpose |
|---|---|
| `run_analysis.sh` | end-to-end pinned reproduction |
| `V15DecoderAnalysis.java` | hash assertion, recursive and exhaustive disassembly, xref metrics, listing export |
| `decoder_source_metrics.py` | source constructor and hash comparison |
| `summarize_results.py` | paired log to JSON/Markdown comparison |
| `extract_candidate_traces.py` | exact descriptor, CIN, and `midi_route` trace extraction |
| `results/provenance.txt` | exact hashes, commits, trees, tools, and base |
| `results/v15-byte-evidence.*` | exact app hash, base derivation, USB MIDI byte anchors |
| `results/comparison.*` | decoder metrics and target xref counts |
| `results/candidate-traces.md` | preserved candidate code and data evidence |
| `results/*-headless.log` | complete Ghidra analysis logs and tool failures |
| `results/*-listing.tsv.gz` | complete exported tested-region listings |
| `results/*-sleigh-build.log` | SLEIGH compiler diagnostics |
| `results/decoder-source-metrics.json` | constructor, source-line, file, and `.sla` hashes |
