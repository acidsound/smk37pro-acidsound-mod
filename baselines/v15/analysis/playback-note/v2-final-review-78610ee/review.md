# S1-C4 Playback Note v2 fail-closed review for commit 78610ee

Decision: PASS

Scope was offline only. I reviewed only:

- baselines/v15/analysis/flash-candidates/S1C4-playback-note-v2-failclosed
- baselines/v15/analysis/playback-note/candidate-v2-failclosed

The working tree target directories match exact commit 78610ee by git diff returning no paths for the two reviewed directories. No device, USB, MIDI, OTA, or flash operation was used.

## Independent artifact checks

Validated checksums from the binary files themselves:

| Artifact | Size | SHA-256 |
|---|---:|---|
| app.bin | 617012 | 66ac465cc058682ee015e0f1b980da6593b09ac345f4f7d5abd6396077b46b25 |
| SMK37Pro-v15-S1C4-playback-note-v2-failclosed.fwsc | package | f10683dc3ae5a15a7a0dfd3675297d07527af4bab5be6d72d932af15364238c7 |
| selector.bin | 88 | 900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f |
| producer.bin | 188 | a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438 |
| combined.bin | 278 | 4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1 |

selector.bin, producer.bin, and combined.bin exactly match their owned slices in app.bin:

- selector: 0x0201e13e..0x0201e196
- producer: 0x0201e196..0x0201e252
- owned window including inert tail: 0x0201e13e..0x0201e254

## Selector review

Decoded selector bytes independently from independent-decode.tsv and the raw slice:

- Default metadata note is set before any gate: 0x0201e148 3516 is mov r5,r3, so fallback default is Trigger Note.
- Non-Ch10 fallback reaches copy before map load: 0x0201e14c 86f81b12 branches to 0x0201e186.
- Below-range fallback reaches copy before map load: 0x0201e150 83fd1948 branches to 0x0201e186.
- Above-range fallback reaches copy before map load: 0x0201e154 03fd1768 branches to 0x0201e186.
- Not-ARMED fallback reaches copy before map load: state load at 0x0201e164, gate at 0x0201e166 80f80e04 branches to 0x0201e186.
- Invalid selected slot fallback reaches copy before map load: valid load at 0x0201e176, gate at 0x0201e178 80f80502 branches to 0x0201e186.
- Playback Note map is not referenced until after ARMED and selected-slot valid gates: map base at 0x0201e17c, map slot add at 0x0201e180, map load at 0x0201e182.
- Selected source remains trigger slot: trigger is normalized to slot by add r3,#-36 at 0x0201e158, slot offset is derived from r3, and source copy uses mov r1,r6 at 0x0201e184. The mapped Playback Note loads only into r5 for metadata.
- Copy path is shared and reached by all fallbacks before map load: 0x0201e186 restores destination, 0x0201e188 calls memcpy target 0x02048cce, and 0x0201e192 stores metadata note.

This satisfies fail-closed fallback behavior and source-slot invariance.

## Note On/Off symmetry and velocity

- Note Off hook remains 80fffa1a0000 at 0x0201c63e, targeting selector Note Off adapter 0x0201e13e.
- Note On hook remains 80ffc01a0000 at 0x0201c67c, targeting selector Note On adapter 0x0201e142.
- Stock metadata stores after both hooks are neutralized symmetrically with 001600160016 at 0x0201c644 and 0x0201c682.
- Note On velocity store is preserved at 0x0201c68c, observed bytes begin 8d42.
- Selector push/pop preserve r9..r4, so r5 metadata changes are local to the wrapper return while trigger and velocity state are restored for caller continuation.

## Producer review

Producer path independently confirms:

- Wire byte 161 is captured as staging payload offset 0x9b: 0x0201e1e8 builds stage + 0x9b, 0x0201e1ec loads from it, and 0x0201e1ee stores it into 0x01c46f20 + slot.
- 0x9b restore before copy: 0x0201e1f0 loads 0x3f, 0x0201e1f2 stores it back into staging byte 0x9b, then copy call occurs at 0x0201e1fa.
- Slot 0x9b restore before valid publication: 0x0201e200 loads 0x3f, 0x0201e202 stores to [valid_pointer-1], then 0x0201e208 publishes valid.
- ARMED is last: count is reloaded/incremented/stored at 0x0201e20a..0x0201e20e; only when count reaches 16 does 0x0201e216 load ARMED value 2 and 0x0201e218 store state.
- Reset hides stale map and control state: reset entry 0x0201e228 checks reset signature, clears lock/count/state at 0x0201e240..0x0201e244, performs csync, then calls producer at 0x0201e24a.

## Branch and call targets

Raw callsite bytes and decoded targets:

- Direct product callsite 0x0201e468: bfeadefe -> 0x0201e228 reset entry.
- Direct reload callsite 0x0201e46c: bfeaf838, preserved.
- Segmented product callsite 0x0201e49c: bfeac2fe -> 0x0201e224 segmented no-mutation stub.
- Segmented reload callsite 0x0201e4a0: bfeade38, preserved.

Owned window is exact: 0x0201e13e..0x0201e254. There is one inert tail word 0016 at 0x0201e252.

## Rebuild, rollback, and OTA checks

Commands run offline:

- python3 validate.py passed.
- python3 build_s1c4_playback_note_v2.py followed by python3 validate.py passed and left the reviewed candidate directories clean, confirming deterministic rebuild for reviewed outputs.
- SHA256SUMS inventory was checked by validate.py.
- Rollback sector manifest and sector hashes were checked by validate.py, which asserts rollback reconstructs official flash.
- Exact OTA checker compiled locally and produced:
  - candidate accepted: exact v15 S1-C4 Playback Note package: PASS (701120-byte OTA payload), rc 0.
  - S1-C3 parent rejected: offline check rejected: not exact S1-C4 Playback Note package, rc 1.
  - official v15 rejected: offline check rejected: not exact S1-C4 Playback Note package, rc 1.

## Final verdict

PASS. The candidate satisfies the requested fail-closed selector behavior, source-slot invariant, Note On/Off symmetry, velocity preservation, producer wire-byte capture and 0x9b restoration, ARMED-last/reset behavior, exact call targets and owned window, deterministic rebuild, rollback reconstruction, and exact OTA accept/reject constraints.
