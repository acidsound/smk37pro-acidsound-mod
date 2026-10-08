# S1C7 live pad-silence root cause and safe successor blocker

## Decision

**ROOT_CAUSE_CONFIRMED; SAFE FIRMWARE SUCCESSOR BLOCKED OFFLINE.** No `app.bin`, FWSC, exact OTA, rollback flasher, or device writer is emitted from this package. The safe successor needs positive magic/CRC-gated restore, but current exact S1C5/S1C7 placement cannot prove that implementation while preserving S1C5 behavior.

## Exact binaries used

| Artifact | SHA-256 |
|---|---|
| S1C5 app | `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189` |
| S1C5 FWSC | `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91` |
| S1C5 selector+producer window | `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` |
| S1C5 producer window | `53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4` |
| S1C7 app | `71cfc1fcbeecd1a9277f88272be6b122a96f33fbd741d7486c670ffab6e58646` |
| S1C7 FWSC | `3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593` |
| S1C7 selector window | `b77f2787874ad37d724e1c6305e74f97c8a6eb9fe6b51627c8fce35dd257daeb` |
| S1C7 producer window | `53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4` |
| S1C7 helper window | `e9ea13c277736c000e5b7f275f97d319b725b2376e9ac15aac97209a8b0f4396` |

S1C7 preserved the S1C5 producer byte-for-byte, but it did **not** preserve the S1C5 selector state policy. The app diff from S1C5 to S1C7 is `104` bytes in ranges `0x1e168..0x1e169, 0x1e17a..0x1e17b, 0x1e186..0x1e196, 0x26d7a..0x26dbb, 0x26dbd..0x26dc5, 0x26dc6..0x26dca, 0x26dcb..0x26dd4`.

## Exact call, ABI, and state root cause

S1C5 not-ARMED or invalid-slot behavior falls through to the stock copy path at `0x0201e186`. S1C7 changed those branches:

- `0x0201e166`: `jne r0,#2 -> 0x0201e18c`, so not-ARMED state calls the persistent helper.
- `0x0201e178`: `jne r0,#1 -> 0x0201e18c`, so invalid resident slot calls the persistent helper.
- `0x0201e18c`: `call32 -> 0x02026d80`.
- `0x02026d92`: helper calls `0x02004870` with `r0=dest`, `r1=0x7d20 + slot*0xa3`, `r2=0x9c`.
- `0x02026d98`: helper treats any nonzero return as valid data, then loads Playback Note from copied byte `dest+0x9b`.

The ABI mistake is that `0x02004870` is only a full-length read wrapper. It can prove that `0x9c` bytes were read, but not that the bytes are seeded, committed, or valid. S1C7 therefore trusted empty storage as if it were a valid patch record.

## Live evidence

Dual preseed dumps are byte-identical 1 MiB images:

- `baselines/v15/device-dumps/s1c7-preseed-20260804/pre-a-live.bin`
- `baselines/v15/device-dumps/s1c7-preseed-20260804/pre-b-live.bin`
- SHA-256 `078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946`

For records 96..111 at `0x0fbd20..0x0fc748`, every 156-byte prefix is all zero with SHA-256 `59bf9091f4cbbd2a8796bfe086a501c57226c42739dcf8ad323e7493ad51e38f` and tail `64000000000000`. That is an unseeded state, but S1C7 had no magic or CRC gate, so the full-length read could still be accepted. The helper then copied zero patch bytes into the live note payload destination, forced byte `0x9b` to `0x3f`, and returned metadata note 0. This explains pad silence.

Current live observations align with this: after S1C7 OTA the user reported no pad sound and no change after Patch Set Editor SysEx; after restoring exact S1C5 and retransmitting the Patch Set, the user reported pad operation normal. Producer preservation alone was insufficient because the S1C7 selector gave unvalidated persistent fallback priority in not-ARMED or invalid states instead of retaining S1C5's stock fallback.

## Minimal safe successor design

The next safe successor must guarantee:

1. **No-seed stock fallback:** unseeded, all-zero, short-read, corrupt, wrong-version, uncommitted, or CRC-failing storage does nothing and returns through exact S1C5 behavior.
2. **S1C5 SysEx ARMED priority:** if exact S1C5 resident RAM is `ARMED` and the selected slot is valid, use it before any persistent lookup.
3. **Seeded restore only with positive magic/CRC:** restore requires manifest magic `SMK37S8P`, layout/count checks, committed flag, header CRC, payload CRC, and per-record CRCs before any resident RAM publication.
4. **Publish last:** materialize all 16 resident slots and Playback Note map first, then set valid flags, count, and ARMED state last.
5. **Future write safety:** write payload records first, readback verify, write/readback verify manifest last. Never silently claim saved state.

A deterministic manifest template was generated for the design: SHA-256 `58f177ef040a8a8ffdc324a0243f904efb0d79de7520e73a3e24cef53333f36f`, header CRC `0xc4f6c192`.

## Why no FWSC/rollback candidate is emitted

- The exact S1C5 selector/producer window has no free bytes if Web/CoreMIDI producer behavior is preserved.
- The exact S1C7 helper window is only 84 bytes and already filled by the unsafe no-manifest helper.
- A positive magic/CRC gate plus stock fallback and ARMED priority does not fit in the proven owned space.
- No exact callable runtime CRC ABI or larger safe lazy-load hook is proven.

Therefore the safe action is blocker evidence, not another flashable candidate.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804 && shasum -a 256 -c SHA256SUMS)
```
