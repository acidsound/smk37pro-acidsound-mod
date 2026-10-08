# S1-C2 executable placement unblock audit

Date: 2026-08-02 UTC
Status: **BLOCK**

## Scope

Read-only static audit of exact official v15, live-PASS H2, and live-PASS S1-C1 boundary-only images. No firmware candidate, app, FWSC, rollback, device access, flash, OTA, or reset was created or performed.

## Exact inputs

| id | path | sha256 |
|---|---|---|
| `official_app` | `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `official_fwsc` | `build/SMK-37_Pro_015.fwsc` | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| `h2_app` | `build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin` | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| `h2_fwsc` | `build/SMK37Pro-v15-H2-owned-source-corrected-fallback/SMK37Pro-v15-H2-owned-source-corrected-fallback.fwsc` | `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011` |
| `s1c1_app` | `build/SMK37Pro-v15-S1C1-boundary-only/app.bin` | `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e` |
| `s1c1_fwsc` | `build/SMK37Pro-v15-S1C1-boundary-only/SMK37Pro-v15-S1C1-boundary-only.fwsc` | `ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d` |
| `h2_manifest` | `baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json` | `dc6fba4ddb887424d6bd76b6d1477f66f97096e2d6656f203eec423680572cf3` |
| `s1c1_manifest` | `baselines/v15/analysis/flash-candidates/S1C1-boundary-only/app-manifest.json` | `51f20f38d5c73eef34f2b45834dd428819725249395f5317786443fd9290b40b` |
| `prior_s1c2_evidence` | `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/evidence.json` | `b0e60b37e05ffa8075aaa9b39acf0149f1cd5b822579d2e3535e6f217da1af60` |
| `prior_s1c2_report` | `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/report.md` | `e06dc98dc0495b154ec50ec25b848b6a00a6a1e314117562ba8577e5d6997481` |
| `s1c1_code_evidence` | `baselines/v15/analysis/patch-set-ui/s1c1/code/evidence.json` | `44b2cb1d7d758c8b85ae19461a05aaa78f9a7579b90f1fddf4575b09079b672c` |
| `s1c1_code_report` | `baselines/v15/analysis/patch-set-ui/s1c1/code/report.md` | `a326c3ec72273530239b7c87963141f89ddde2879fba9eddeca4689c63786aa3` |
| `s1c1_ingress_evidence` | `baselines/v15/analysis/patch-set-ui/s1c1/ingress/evidence.json` | `3b30cdb6904fd81156f4be1b919eda9b44259873055f9e1aad2b029c156bcf34` |
| `s1c1_ingress_report` | `baselines/v15/analysis/patch-set-ui/s1c1/ingress/report.md` | `c6b5e86fc1a0e66912c54aa361f8309ba6e918914ac5ed254b094935ed64b76c` |
| `app_tail_evidence` | `baselines/v15/analysis/r03-owned-ram/app-tail-placement/evidence.json` | `19633d28c7060f578ee78dbb809ed31e74e0baec9b1b8af608a56c2c85ba1846` |
| `app_tail_report` | `baselines/v15/analysis/r03-owned-ram/app-tail-placement/report.md` | `036eca79c6258a9ffff9f493874058a1876cbbe92f2cd76c27d06efe2f2c105c` |
| `quarkslab_recursive_listing` | `baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz` | `c1d2f3f1369720c3d934acb468d6ddb79b4f0d9c65af5b9583225df610c253a9` |
| `quarkslab_exhaustive_listing` | `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz` | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| `kagaimiq_exhaustive_listing` | `baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz` | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |
| `quarkslab_comparison` | `baselines/v15/analysis/quarkslab/results/comparison.md` | `6196755c9448edb3600f1663574b33bcb651b99ee00b08af503ca975a38cf21f` |

## Decision

**BLOCK.** No concrete executable range is proven for the S1-C2 private atomic parser/selector that can be overwritten without removing exact S1-C1/H2 reachable behavior.

- No concrete executable range is proven to hold the S1-C2 private atomic parser/selector without removing exact S1-C1/H2 reachable behavior.
- The only residual executable tail with any ownership argument is 0x0201e1ec..0x0201e254, 104 contiguous bytes, and there is no exact assembled PI32 parser proving the required prefix/length/CRC/state/copy/reject/delegation logic fits there.
- The unchanged H2 producer at 0x0201e1a2..0x0201e1ec has positive callsite reach and cannot be overwritten.
- The completed-message handler and callsite neighborhood are reachable stock/H2 behavior, not free placement.
- The app-area tail is cfg_tool.bin per JLFS evidence, not executable padding ownership.
- Uniform zero/0xff runs in app.bin are generic data-cave candidates only and are expressly not ownership proof.

## Candidate placement matrix

| candidate | range | bytes | decision | critical evidence |
|---|---:|---:|---|---|
| `residual_h2_packer_tail` | `0x0201e1ec..0x0201e254` | 104 | **BLOCK_AS_S1C2_PARSER_PLACEMENT** | only 104 contiguous bytes are available here |
| `selector_internal_gap` | `0x0201e19e..0x0201e1a2` | 4 | **BLOCK** | only 4 bytes |
| `unchanged_h2_producer` | `0x0201e1a2..0x0201e1ec` | 74 | **BLOCK** | exact H2/S1-C1 reachable behavior uses this producer from accepted Yamaha product packet callsites |
| `official_completed_handler_entry` | `0x0201e254..0x0201e4a4` | 592 | **BLOCK** | this is the official/H2 completed-message handler entry and body |
| `completed_message_callsite_neighborhood` | `0x0202d1d0..0x0202d220` | 80 | **BLOCK** | 0x0202d202 is only a 4-byte call slot inside reachable function FUN_0202d15a |
| `app_area_tail_if_contiguous_runtime` | `0x02096a34..0x02096bb3` | 383 | **BLOCK** | not inside logical app.bin, so current application-only patcher cannot own it |

## Positive reachability and ownership facts

- Official v15 decoders show direct stock calls to `0x0201e13e` at `0x0201e468`, `0x0201e49c`, and in Quarkslab exhaustive output at `0x02026dac`. H2/S1-C1 deliberately replace that packer body and block SAVE.
- H2/S1-C1 reachable producer bytes occupy `0x0201e1a2..0x0201e1ec`. The product callsites are redirected to that producer, so overwriting it removes live-PASS H2 behavior.
- The only residual executable tail with a plausible ownership argument is `0x0201e1ec..0x0201e254`, exactly 104 contiguous bytes after the H2 producer return and before official handler entry.
- The `0x0202d202` completed-message callsite can short-call this tail (`bfeaf387`), but reach alone is not parser placement proof.
- `0x0201e254` is the official/H2 completed-message handler entry used by callers at `0x0202d1fa` and `0x0202d202`; it must be preserved for non-private traffic.
- The apparent app-area tail maps to `cfg_tool.bin` and remains BLOCKED. Uniform zero/0xff runs are reported as generic data-cave candidates only and are not promoted.

## Why the residual tail does not unblock S1-C2

S1-C2 needs a private parser that performs prefix discrimination, exact length/F7 gates, byte-range gates, TX/FLAGS/LEN gates, packet CRC, full-set CRC, nonblocking lock/state publication, two 156-byte copies, rejection cleanup, mutation-after-ARMED rejection, and unchanged H2 delegation. The residual tail provides only 104 contiguous bytes and no exact assembled PI32 implementation proves those requirements fit. A PASS would require exact bytes, exact overwritten range, exact branch/call encodings, and positive non-removal proof. That evidence does not exist in the current artifacts.

## Smallest next runtime evidence, if later authorized

- Only after an exact static parser is assembled and fits a proven range: authorize a no-mutation ingress smoke build that changes only the 0x0202d202 call target and the candidate range, delegates every non-private packet to H2 0x0201e254, and proves the live H2 Yamaha packet plus Ch1/Ch10 fallback still work with no reboot.
- If using residual tail 0x0201e1ec..0x0201e254, the smoke must prove execution enters that tail and returns/delegates correctly while the H2 producer at 0x0201e1a2..0x0201e1ec remains byte-for-byte unchanged.
- Only after the no-mutation ingress smoke passes should a mutating two-message parser be considered for live evidence.

## Reproduce

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/analyze_executable_placement.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/SHA256SUMS
```
