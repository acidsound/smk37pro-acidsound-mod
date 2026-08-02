# v15 UI reverse-engineering requirements for Drum Set UI preflash review

Status: requirements and evidence policy only. This review did not patch, flash, or commit firmware.

## Scope

This document defines the minimum evidence standard and minimum function, ABI, RAM, and persistence contracts required before claiming that a Drum Set UI change is implementable on the official v15 firmware.

Inputs reviewed independently:

- `baselines/v15/analysis/subsystem-feasibility/ui.md`
- `baselines/v15/analysis/quarkslab/evidence-report.md`
- `baselines/v15/analysis/quarkslab/results/comparison.md`
- `baselines/v15/analysis/quarkslab/results/*listing.tsv.gz` spot queries for known UI anchors
- `baselines/v15/analysis/sdk-signatures/evidence.md`

Canonical v15 address model from the reviewed documents:

- official app: `build/v15-official-app.bin`, 617,012 bytes, SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- runtime VA: `0x02000000 + file_offset`
- package/flash storage offset: `file_offset + 0x4120`

## Evidence classes and promotion rules

| Class | May support | Must not support by itself |
|---|---|---|
| Direct v15 byte evidence | Exact string/color/table presence, exact pointer value, exact region hash | Function identity, mutability, safety, renderer ABI |
| Direct v15 xref/call evidence | Candidate renderer, dispatcher, state user, persistence user | Semantic identity unless control/data flow and arguments are explained |
| Quarkslab recursive listing | Stronger decoded control-flow evidence than the older decoder | Completeness claims or absence claims outside exact decoded/literal facts |
| Quarkslab exhaustive listing | Coverage experiment and candidate discovery | Function identity by itself, because it may decode embedded data |
| Public SDK signature evidence | Lineage, ABI search models, possible AC79 idioms | v15 addresses unless matched by direct byte/relocation-aware evidence |
| Product documentation | Physical UI existence and user-visible behavior expectations | Firmware addresses, RAM layout, persistence layout, pin mapping |
| Prior hands-on observations | Regression hypotheses for same-length labels only | R01/v15 renderer ABI, generalized patch safety, or flashing approval |

A v15 UI claim may be promoted from candidate to requirement-satisfying only when it has at least two independent supports, one of which is direct v15 evidence. Public SDK similarity and product documentation together are not enough.

## Minimum Drum Set UI contract requirements

### REQ-01: Immutable input and address provenance

Every Drum Set UI analysis artifact must state the exact app hash, file offset, runtime VA, and package/flash offset for each byte range or symbol it uses.

Acceptance test:

- For every claimed address, recompute `VA == 0x02000000 + file_offset` and `flash == file_offset + 0x4120`.
- Verify the app SHA-256 equals `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` before accepting offsets.

Anti-overclaim rule:

- Do not import addresses, structures, function names, or patch conclusions from v11-v14 or any other firmware version.

### REQ-02: Renderer entry function contract

Before implementing a Drum Set UI screen, identify the v15 function or function chain that renders app-resident text or menu fields.

Minimum evidence:

- At least one direct v15 xref or data-flow path from a known UI string pointer such as `Pad Bank-` at file `0x5d9c5`/VA `0x0205d9c5` or `Keys Channel-` at file `0x5d9e9`/VA `0x0205d9e9` into executable code.
- A decoded call boundary showing argument registers or stack usage for text pointer, x/y or layout object, color/style, and invalidation/refresh behavior, or a documented reason that a different ABI model fits better.

Acceptance test:

- Produce a read-only xref report listing caller addresses, call instructions, and the register values or RAM fields carrying the text pointer.
- Confirm the renderer path is recovered in the recursive Quarkslab phase or is independently supported if first found only in exhaustive output.

Anti-overclaim rule:

- A raw string occurrence, color string occurrence, or pointer table entry proves that bytes are present and referenced. It does not prove that arbitrary new UI pages, longer labels, new glyphs, or layout changes are safe.

### REQ-03: Same-length text and color edit contract

The only currently high-confidence UI edit class is same-length ASCII label replacement and same-length `#RRGGBB` color replacement inside `app.bin`.

Minimum evidence:

- Known direct v15 offsets include `SAVE` at `0x57298`, `#D9D9D9` at `0x57730`, `#F5BC27` at `0x57ce4`, parameter labels at `0x5d852..0x5d88b`, `Firmware` at `0x5d8f5`, `SAVED` at `0x5d990`, `Pad Bank-` at `0x5d9c5`, and `Keys Channel-` at `0x5d9e9`.
- Replacement bytes must not change field length, terminator placement, adjacent bytes, pointer values, or package layout.

Acceptance test:

- Generate a dry-run binary diff that shows only the intended byte ranges changed.
- Recompute package checksums or CRCs in dry-run only if packaging is tested.
- Do not flash as part of this requirement.

Anti-overclaim rule:

- Prior marker-only success may justify a regression test idea, but it does not establish renderer bounds behavior, font coverage, or safe general UI editing.

### REQ-04: Drum Set menu state contract

Before adding or modifying a Drum Set UI state, identify the v15 RAM location or object field that represents the current UI page, selected drum set, selected pad/key, and edited parameter.

Minimum evidence:

- A state-machine or dispatcher caller chain from button/input events to UI redraw.
- RAM base or global pointer derivation for each state field.
- Read and write sites for each field, with width and value range.

Acceptance test:

- For each proposed RAM field, list writer functions, reader functions, access width, reset/default path, and at least one UI render use.
- Demonstrate that changing the field's interpretation will not alias the MIDI ingress routing arrays, USB descriptors, or unrelated global blocks documented in SDK/Quarkslab evidence.

Anti-overclaim rule:

- The SDK's public UI framework and public MIDI structs are search models only. They must not be assigned to v15 RAM without direct v15 matches.

### REQ-05: Button/input ABI contract

Before binding Drum Set UI actions to buttons, identify the v15 button or key event ABI.

Minimum evidence:

- Key scan or event dispatcher function address.
- Event record layout or scalar arguments, including press/release/repeat/long-press distinction if used.
- Caller chain into the UI state machine.

Acceptance test:

- Produce a table of button event codes with evidence source, dispatch function, and observed or inferred action.
- If using the rejected `0x58248` eleven-pointer run as a lead, re-establish it with disassembly and callers. It was rejected as public MIDI ABI because the operation sizes match product UI/button-state callbacks, not `MIDI_CTRL_CONTEXT`.

Anti-overclaim rule:

- Do not describe button remapping as feasible from physical product photos or SDK GPIO examples alone. Recovery, boot, and safety combinations must be treated as unknown until traced.

### REQ-06: LCD/framebuffer/display update contract

Before relying on custom Drum Set graphics, identify the v15 display controller path and update ABI.

Minimum evidence:

- Exact v15 LCD init table file offset and caller.
- LCD command/data write function addresses.
- Pixel format, coordinate range, and buffer ownership model.
- Evidence whether drawing is immediate, buffered, DMA-driven, dirty-rect based, or resource-renderer based.

Acceptance test:

- Compare the v15 init table byte-for-byte with the pinned SDK `lcd_st7789v.c` command family and record differences.
- Show a read-only trace from renderer/update function to LCD write or framebuffer flush.

Anti-overclaim rule:

- The ST7789V-like command set supports a controller-family hypothesis only. It does not prove bus mode, rotation safety, resolution changes, framebuffer size, or custom bitmap support.

### REQ-07: RAM allocation and scratch-space contract

No Drum Set UI code or data expansion may claim safety until RAM ownership and scratch-space lifetime are known.

Minimum evidence:

- Stack frame sizes for any hooked or reused function.
- Global/static buffers used by renderer, button dispatcher, LCD update, and persistence path.
- Interrupt or callback context for UI calls.

Acceptance test:

- For each candidate hook or reused routine, document clobbered registers, stack use, reentrancy assumptions, and maximum buffer length.
- Verify that any proposed scratch RAM is not touched by decoded readers/writers in normal UI, MIDI ingress, USB, or storage paths.

Anti-overclaim rule:

- Unreferenced-looking RAM in an incomplete listing is not free RAM. Decoder/tool limitations and computed addressing prevent broad absence claims.

### REQ-08: Persistence contract

Before a Drum Set UI edit persists settings, identify the v15 storage API, record format, commit timing, and failure behavior.

Minimum evidence:

- Read and write function addresses for the relevant preset/settings store.
- Record key or table offset, field widths, checksum/CRC if any, and bounds checks.
- UI save path coupling, especially around `SAVE` at `0x57298` and `SAVED` at `0x5d990`.

Acceptance test:

- Produce a read-only data-flow report from the save UI action to VM/flash/storage calls and back to the rendered confirmation state.
- Verify that a default-load path and failed-write path are identified before proposing persistent Drum Set changes.

Anti-overclaim rule:

- A visible `SAVE`/`SAVED` string does not prove which settings are saved, where they are saved, or that new fields can be added.

### REQ-09: Function ABI and hook safety contract

Any claimed callable v15 function must include a pi32v2 ABI description sufficient for a reviewer to reproduce the call safely.

Minimum evidence:

- Entry address, return convention, argument registers/stack slots, preserved/clobbered registers, and preconditions.
- At least two independent evidence sources when assigning semantic names.

Acceptance test:

- Provide a small call-site audit showing existing callers set the same arguments in the same order.
- Check for tail calls, table calls, interrupt context, and computed branches that could change calling assumptions.

Anti-overclaim rule:

- The public SDK confirms general pi32v2 scalar argument behavior, but public SDK function prototypes do not name v15 functions unless relocation-aware or direct v15 matching supports them.

### REQ-10: Quarkslab listing use contract

Quarkslab decoder output may guide reverse engineering, but every Drum Set UI requirement must record whether evidence came from recursive analysis, exhaustive analysis, raw byte scanning, or SDK matching.

Acceptance test:

- Each promoted function or xref includes phase provenance and a note about decoder errors if the path crosses uncertain code.
- Claims first discovered in exhaustive listing receive an independent confirmation such as raw bytes, recursive recovery, a literal pointer, a caller chain, or runtime read-only trace.

Anti-overclaim rule:

- Do not treat the 91.205% exhaustive coverage as complete disassembly. The reviewed report explicitly notes undecoded aligned slots, possible decoded data, p-code errors, and unresolved constructors.

## Minimum evidence package before any future patch proposal

A future Drum Set UI patch proposal should include, at minimum:

1. `addresses.md`: exact offsets, VAs, flash offsets, hashes, and source provenance.
2. `renderer-xrefs.md`: text/color/string xrefs to render/update functions.
3. `state-contract.md`: page, selection, edited parameter, and redraw state fields.
4. `button-contract.md`: event ABI and dispatcher mapping.
5. `display-contract.md`: LCD init, write, framebuffer/update behavior.
6. `ram-contract.md`: stack/global/scratch-space ownership and clobber list.
7. `persistence-contract.md`: save/load field layout and failure behavior.
8. `dry-run-diff.md`: byte-level diff and package checksum plan, with no flashing.

Until those artifacts exist, the defensible Drum Set UI scope is limited to read-only analysis and same-length app-resident label/color dry-runs. Flashing, longer strings, new glyphs, new pages, persistent new settings, button remaps, and custom graphics should remain out of scope.
