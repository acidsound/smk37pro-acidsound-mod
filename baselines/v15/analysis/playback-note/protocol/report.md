# S1-C3 r3 Playback Note protocol audit

Status: **PROTOCOL DESIGN PASS; FIRMWARE CANDIDATE BLOCKED**.

Scope: offline only. This audit did not access a device, open MIDI/USB, flash, OTA, reset, build a live firmware package, or send traffic. It writes only this evidence directory.

## Decision

A compact per-pad Playback Note map can be defined safely as a **future** one-shot control frame after the existing 16 S1-C3 r3 patch packets. RAM boundary expansion is **not required** because the proven S1-C3 boundary already reserves `0x01c46f20..0x01c46fb0` for header/map data.

No firmware package is safe to build now. The installed r3 producer has only **4 reported spare bytes** in `0x0201e1a2..0x0201e254`, and the installed selector is a 96-byte hard-coded `note 36..51 -> slot note-36` selector. A map-aware producer/parser plus a map-aware selector need new byte-exact PI32 bodies and independent decode before packaging.

## Exact current basis

| item | value |
|---|---|
| S1-C3 r3 app | `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b` |
| S1-C3 r3 FWSC | `0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9` |
| r3 producer | `48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607` |
| selector | `ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915` |
| boundary parent app | `c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14` |

Current r3 behavior is note-ordered: slot `0..15` corresponds to MIDI notes `36..51`; physical Pad permutation is a browser/UI concern, not firmware proof of immutable hardware order.

## RAM boundary and layout

| range/address | size | current ownership | Playback Note use |
|---|---:|---|---|
| `0x01c099d4..0x01c46fb0` | `0x3d5dc` | boot-zeroed BSS after S1-C3 boundary | unchanged |
| `0x01c46fb0` | 0 | current heap begin | unchanged |
| `0x01c46520..0x01c46f20` | `0x0a00` | 16 resident slots at stride `0xa0` | unchanged |
| `0x01c465bd` | 1 | global nonblocking producer lock | reused by future map producer |
| `0x01c465bf` | 1 | slot-set state, `2 == ARMED` | require ARMED before map |
| `0x01c46f20..0x01c46fb0` | `0x90` | reserved header/map area | enough for header plus 128-byte `note_to_slot` |

Conclusion: **no RAM boundary expansion required** for the proposed map.

## Executable placement and budgets

| region | bytes | current use | decision |
|---|---:|---|---|
| `0x0201e13e..0x0201e19e` | 96 | selector, 72 live bytes plus 24 padding | BLOCK pending map-aware bytecode |
| `0x0201e19e..0x0201e1a2` | 4 | gap bytes `02005904` | insufficient |
| `0x0201e1a2..0x0201e250` | 174 | compact r3 producer | full |
| `0x0201e250..0x0201e254` | 4 | reported spare/tail bytes `22805604` | insufficient |

A safe map producer must check magic/version/flags/count, validate 16 entries, verify CRC, reject duplicates, use the lock, clear/fill a 128-entry map, and publish `map_state=ARMED` last. That cannot be justified from 4 bytes of producer spare.

## Existing direct-product SysEx gates

The minimal transport reuses only the direct complete product gate already proven by r3:

```text
F0 43 00 00 01 1B + 0x9c staged bytes + F7
```

The official handler copies bytes after the six-byte header to `0x01c37fd0`, checks terminal `F7`, then calls the r3 producer at `0x0201e468 -> 0x0201e226`; the reload call at `0x0201e46c` remains intact. The segmented final path remains **not used** for the map protocol because r3 intentionally makes it a no-mutation stub.

## Proposed compact Playback Note frame

The future control message is exactly 163 bytes:

```text
F0 43 00 00 01 1B
53 4D 4B 50 4E 31  01 10 00 10  MASK0 MASK1 MASK2
NOTE0 ... NOTE15  CRC0 CRC1 CRC2  124 zero padding bytes
F7
```

Fields:

- `53 4D 4B 50 4E 31`: ASCII `SMKPN1`.
- version `1`, command `0x10`, flags `0`, entry count `16`.
- `MASK0..2`: 16-bit Original mask encoded in three seven-bit chunks. Bit `i == 1` means slot `i` uses Original.
- `NOTE0..NOTE15`: custom MIDI notes `0..127` where the Original bit is clear; must be `0` where Original is set.
- `CRC0..2`: CRC-16/CCITT-FALSE over payload bytes `0..28`, encoded as three seven-bit chunks.
- all padding bytes must be zero.

Default Original behavior: if no map is accepted, current r3 behavior remains unchanged: note `36+i` selects slot `i`. If a map entry is Original, effective note is also `36+i`. All 16 effective notes must be distinct.

## Publication semantics

A future handler must validate the entire frame before mutation. Then it must:

1. require slot-set state `0x01c465bf == 2` and all 16 slot valid bytes are `1`;
2. reject if map state is already ARMED; v1 is one-shot until reboot;
3. acquire `0x01c465bd` with the existing nonblocking lock policy;
4. set map state LOADING, clear `note_to_slot[128]` to `0xff`, fill the 16 effective-note entries, and `csync`;
5. write metadata, `csync`, then publish `map_state = ARMED` last;
6. release the lock.

Consumers should use the current note-ordered selector while map state is not ARMED. Once map state is ARMED, they should read `note_to_slot[note]`, fall back for `0xff` or `>=16`, check slot `valid == 1`, and copy exactly `0x9c` bytes. No map or slot mutation is allowed after publication.

## Browser editor send plan

The browser editor can support this only as a capability-gated future package feature:

1. send the existing 16 patch packets in r3 resident slot order;
2. translate physical Pad UI order to resident slot order locally;
3. encode Original bits or custom `0..127` playback notes;
4. append the single `SMKPN1` control frame after patches **only** when the selected firmware manifest advertises map support.

Against current r3, the editor must treat Playback Note maps as unsupported/no-op and must not imply live support.

## Blockers

- Current r3 has no SMKPN1 handler.
- Producer byte budget is blocked by only 4 reported spare bytes.
- Selector byte budget is blocked until a map-aware replacement is encoded and independently decoded.
- No app/FWSC/live package was built, by design.

## Validation

Run:

```sh
python3 baselines/v15/analysis/playback-note/protocol/validate.py
(cd baselines/v15/analysis/playback-note/protocol && shasum -a 256 -c SHA256SUMS)
```
