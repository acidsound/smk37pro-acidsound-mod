# Independent S1-C1 boundary-only candidate review

Date: 2026-08-02 UTC

## Verdict

**PASS** for the exact offline S1-C1 boundary-only candidate and its exact rollback bundle.

No device was accessed. Nothing was flashed. This verdict is an artifact-integrity and scope verdict. It does not claim live allocator headroom or live workload success, which are intentionally outside this no-device review.

## Exact identity

| Artifact | SHA-256 |
|---|---|
| official v15 app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| official v15 FWSC | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| H2 parent app | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| H2 parent FWSC | `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011` |
| boundary-only app | `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e` |
| boundary-only FWSC | `ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d` |
| rollback ZIP | `9cf3a7ec8a24e09d2d2bef9d55d73363c01f8461a3800ad37ba30abb72d332f1` |

The H2 app rebuilt byte-for-byte from the exact official app before comparison. The boundary-only app and package then rebuilt byte-for-byte in scratch space, including both manifests and `SHA256SUMS`.

## H2-relative boundary-only proof

The exact H2-relative app delta is four bytes:

- offsets `0x20`, `0x21` in the BSS-size immediate at runtime instruction `0x0200001e`;
- offsets `0x5e9fa`, `0x5e9fb` in the `HEAP_BEGIN` immediate at runtime instruction `0x0205e9f8`.

The complete instruction pairs are:

| Field | H2 | Boundary-only |
|---|---|---|
| BSS size | `c2ffeccb0300` = `0x0003cbec` | `c2ff8ccc0300` = `0x0003cc8c` |
| `HEAP_BEGIN` | `c5ffc065c401` = `0x01c465c0` | `c5ff6066c401` = `0x01c46660` |

Both values advance by exactly `0xa0`. Both independently derive the same BSS base, `0x01c099d4`. The candidate's remaining boundary span to unchanged `HEAP_END = 0x01c7fd30` is `0x396d0`.

There are no other H2-relative app changes. In particular:

- the entire H2 code-cave producer/consumer implementation is byte-identical;
- no new second-slot read or write exists;
- no note selector exists;
- no persistence behavior was added;
- only the two boundary instruction operands changed. This is not a claim that the app has zero executable-byte changes, since the immediate operands reside in instructions.

## Package and protected regions

Independent FWSC unpacking found the expected official-relative changed sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, and `0x62000`. The package safety gate is `PASS`.

The following protected hashes were recomputed independently from both official and candidate unpacked flash and are identical:

| Region | SHA-256 |
|---|---|
| boot/layout `0x0000..0x3fff` | `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67` |
| U-Boot raw `0x00a0..0x38cf` | `b5a0715940db344f951595e2d5a66050631c7721703cb06d33d8dc94eca3c861` |
| ISD config raw `0x38d0..0x3b8a` | `0952afd96f533dd0fba72a8fab9cb4a4336f55424a1a89eecb13ff8a51a0eff0` |
| post-app resources/reserved | `53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7` |

## Exact OTA check

The scoped OTA source compiled from scratch with warnings enabled. Its embedded package hash equals the exact candidate FWSC hash, and its confirmation token is:

`INSTALL-SMK37PRO-V15-S1C1-BOUNDARY-AE8C44A4`

Offline `check` results:

| Input | Exit | Result |
|---|---:|---|
| exact boundary-only FWSC | `0` | accepted |
| exact official v15 FWSC | `1` | rejected |
| exact H2 parent FWSC | `1` | rejected |
| malformed non-FWSC | `1` | rejected during format validation |

No `upload` command was invoked.

## Rollback bundle

The exact rollback bundle was independently rebuilt from the official package, exact candidate package, and locked H2 rollback template. The rebuilt 13-file directory was byte-identical, and the rebuilt ZIP was byte-identical with SHA-256 `9cf3a7ec8a24e09d2d2bef9d55d73363c01f8461a3800ad37ba30abb72d332f1`.

The unpacked-flash difference and manifest both identify exactly five 4 KiB sectors:

| Sector | Stock SHA-256 | Expected candidate SHA-256 | Changed bytes |
|---|---|---|---:|
| `0x04000` | `f0dbdd1756fdb0fbf31def403c74c4f4c69ec30bfc6a405f88d9bd540a9cf8e9` | `a4b8f46cf49e3fad9aa281ce0f45fcde803cf0e821e30454acf89d8bd9473143` | 10 |
| `0x20000` | `1dc90a318976cead8c55bb071b4096b242c354329eaf0cba74204866c0011f64` | `aae02584dd183936956c478a472e6e21d66c9ebd853af8bdf540259a61a4f26e` | 6 |
| `0x22000` | `dd533edf9d53f120d66c54b0e40769b5a8774b4de9e114c1f1865f7d470f1dcc` | `5d0b47eb018d90ebb90864890e121cd79eb38d765f45a73a688d48a43ad71e64` | 175 |
| `0x2a000` | `630e50034f661f0a2d1d94e56f25b056ae99c8d1d379d6e7b082bd868d619409` | `a58c41f00acf8dab7c326c49ae7d24c97f900b0efabc7a25905886f702b56fc2` | 8 |
| `0x62000` | `7fbd04123b6ffecd937f5b9896e385c62a12a1ef16a316888dd071fa43649f6d` | `6b16fe66773d7c5d6bf8dfa692813d55bf67e5e70b2765ba56601a9c40054790` | 2 |

The manifest, Python guard, and elevated wrapper carry the exact three S1C1B confirmations. No stale `H2`/`h2` token remains in bundle text. Every `SHA256SUMS.txt` member passes, ZIP CRC and member-byte checks pass, fixed ZIP timestamps pass, and the guard's fake-transport self-test passes its erase/write/readback, CRC, CDB allow-list, and failure cases.

## Reproduction

From the repository root:

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c1/boundary-review/validate.py
```

The captured output is in `validation.txt`; structured locked evidence is in `evidence.json`.
