# S1C8 manifest-gated persistence successor: BLOCK/design package

## Decision

**BLOCK.** No `app.bin`, FWSC, exact OTA wrapper, rollback flasher, or device writer is emitted.

S1C5 remains the only live-validated baseline. Because S1C7 failed silent, the next persistence successor must reject unseeded or corrupt data by positive manifest validation before touching runtime RAM. That stronger gate does not fit any owned/exact placement while preserving S1C5 selector, producer, WebMIDI/CoreMIDI behavior, and rollback expectations.

## Requirements outcome

| Requirement | Outcome |
|---|---|
| Preserve exact S1C5 selector/producer and Web/CoreMIDI behavior | PASS for this package by emitting no firmware; pinned combined SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` and producer SHA-256 `53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4`. |
| Unseeded device behaves exactly S1C5 | PASS only because no firmware is emitted. Future firmware must fail closed to the exact S1C5 path on missing/invalid manifest. |
| Persistent data gated by manifest/magic/CRC | Data-format PASS, firmware BLOCK. Manifest magic `SMK37S8P`, payload CRC `0x520c42bf`, header CRC `0x7bb63606`. |
| Dynamic SysEx overrides persistent restore | Design rule recorded: ARMED+valid S1C5 RAM wins; persistent restore is only a not-ARMED fallback. |
| Playback notes may duplicate | PASS. Proposed record image carries notes `60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60` and does not collapse source identity. |
| Forced-seeded tail records | Data package only. Payload record tails `0x9c..0xa2` are forced from exact clean-v15 twin dumps. |
| Separate manifest record | PASS in data format: record `112`. |
| Lazy boot load | Design only. The least risky future lifecycle is first accepted Ch10 note after storage init, not a pre-USB boot hook. |

## Offline data package, not a firmware candidate

The generated data package is under `data-package/`:

- `candidate-records-096-112.bin`: SHA-256 `6b34954243eec925ba3fc0de228c72a294285f194696ff5589427b6513bd44c9`.
- `manifest-record-112.bin`: SHA-256 `02317088f480229e506fb36c69b4f7ec20b303c3887c025d975b51fd07969465`.
- `package-manifest.json`: records 96..111 plus manifest record 112.

Payload encoding for each slot is:

```text
raw[0x00..0x9a] = exact S1C5 packet voice bytes 0x00..0x9a
raw[0x9b]       = Playback Note byte, 0..127
raw[0x9c..0xa2] = forced clean-v15 tail bytes from identical twin dumps
```

Manifest prefix fields include magic, version, committed flag, layout, record base, manifest record, lengths, generation, payload CRC32, note CRC32, per-record CRC32 values, the 16 Playback Notes, and a header CRC32 with its own field zeroed.

## Fit and ABI blockers

| Gate | Result |
|---|---|
| S1C5 owned window | `278` bytes total, exact selector `88`, producer `188`, inert tail `2`, no free bytes. |
| Disabled SAVE helper window | `84` bytes. The S1C7 no-manifest helper already consumed `84` bytes. |
| Positive manifest gate | BLOCK. Manifest read setup floor `20` bytes and magic-only compare floor `48` bytes already exceed the filled helper before version/count/commit/CRC. |
| CRC ABI | BLOCK. no exact callable runtime CRC routine or compact PI32 implementation is proven |
| Writer | BLOCK. A writer still needs `0x02004b02` full-length checks, `0x02004870` readback, CRC, commit-last manifest, and non-silent failure reporting. |
| Boot/lazy hook | BLOCK for code. `0x02005f9c` is revoked; `0x02005fa4` lacks proof; first-note lazy load has no placement. |

## Safe successor contract if future evidence unblocks placement

1. Start from exact S1C5 and keep ARMED+valid volatile RAM behavior byte-for-byte.
2. Validate manifest magic/version/layout/count/record base/lengths/committed flag/header CRC/payload CRC/per-record CRC before any restore.
3. On unseeded, corrupt, short-read, ambiguous generation, or CRC mismatch, do nothing and return through exact S1C5 behavior.
4. Let dynamic SysEx producer override persistent restore for the session.
5. For future writes, write payloads first, verify by readback, then write/verify manifest last. Never silently claim SAVED.
6. Preserve duplicate Playback Notes as note data, not source-slot identity.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block && shasum -a 256 -c SHA256SUMS)
```
