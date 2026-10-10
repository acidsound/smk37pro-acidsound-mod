# Official v16 → official v15 recovery readiness

**Status: offline package comparison prepared; not ready to flash.** No firmware
was sent to the instrument during this preparation. Current read-only
`device-info` returned `SMK-37 Pro_015` on 2026-10-11. The desired downgrade
scenario (`016` installed, then return to official `015`) is not the current
hardware state.

## Fixed artifacts

- v16 input: `firmware/SMK-37 Pro_016.fwsc`, 705,252 bytes, SHA-256
  `2d98ce72530e71d617384963423820536f094501299e2cfec0a8d3c3fb6bcfb0`.
- exact official v15 input: `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/SMK-37_Pro_015.fwsc`, 701,140 bytes, SHA-256
  `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`.
- offline inspector: [`tools/prepare_v16_to_v15_package_diff.py`](../tools/prepare_v16_to_v15_package_diff.py).
- generated local report: `build/v16-to-v15-recovery/package-diff-manifest.json` (ignored build output; regenerate with the command below).

The inspector verifies the distinct 20-slot v15 and 36-slot v16 FWSC metadata,
exact package and flash hashes, UFW entry CRCs/layout, JLFS application records,
application sizes/hashes, and decoded app CRCs. It reports **152 differing
4-KiB sectors in the common FWSC-unpacked `flash.bin` range**, plus a v16-only
4-KiB package range at `0x9C000`. These are package-representation differences,
not a physical target write list.

Reproduce the offline check:

```sh
python3 tools/prepare_v16_to_v15_package_diff.py --self-test
python3 tools/prepare_v16_to_v15_package_diff.py
```

The manifest deliberately records `restore_authorized: false`,
`flash_writer_included: false`, and `physical_restore_ready: false`.

## Why there is no flashable restore bundle yet

1. Jieli/SMK documentation checked so far does not confirm downgrade support
   for this exact product, the approved Windows command, or the semantics of
   `isd_download.exe -todisk FILE ADDRESS`. Treat `-todisk` as prohibited until
   the matching tool's documentation/help or vendor confirms it. Do not pass an
   `.fwsc` package to the forced loader by assumption.
2. The stored 1-MiB dump pair
   `backups/smk37-pro-live-before-sloop-20261011-{a,b}.bin` is byte-identical
   (SHA-256 `79862188d7977443d2888ac055bfe0f8fea2026403cc538e63f68807ed8076f4`)
   and contains the `015` identity. It is **not** a forced-loader dump from a
   device running v16, so it cannot validate the v16 downgrade sector hashes.
3. v16's app-area layout and size differ from v15. The extra package range at
   `0x9C000..0x9CFFF` also intersects the region treated as device/user data
   beyond the v15 package. Its on-device ownership and preservation behavior
   must be established before any write plan may include or exclude it.
4. Package-side `flash.bin` bytes are not automatically the same bytes returned
   by the target's download/read path. The known physical mapping includes
   device-specific boot/JLFS/tail handling; the actual v16 target representation
   must be established sector by sector from fresh read-only acquisition.
5. The existing Windows writer bundles are pinned to other v15 candidates
   (e.g. H0/H1/H2), not official v16. Do not run them against a v16 target or
   retarget their expected hashes. The general Windows tool
   [`windows-readonly/smk37_wl82_readonly.py`](../windows-readonly/smk37_wl82_readonly.py)
   intentionally has no Flash erase/write commands.

## Gated Windows sequence (no write command authorized here)

1. Before any v16 install, obtain written SMK/Jieli confirmation of the
   supported v15↔v16 transition, exact accepted package/tool versions, Windows
   procedure, and impact on calibration/user preset data. Stage and self-test
   the recovery tools first. The current v15 device does not prove a recovery
   path from v16.
2. If a separately authorized v16 installation is later performed and the
   device stops booting normally, enter WL82 forced mode. On Windows, identify
   the actual `PHYSICALDRIVE` from fresh system enumeration; never reuse a
   hard-coded drive number. First use `probe`, then the exact official RAM
   loader through `loader-probe`, then the read-only double-dump workflow. Do
   not start with `isd_download`, erase, or a writer.
3. Save two full 1-MiB dumps, verify byte identity, archive the report and
   hashes, and confirm WL82/UBOOT1.00, device type, device ID, and flash ID.
   Keep the package-diff manifest separate: its hashes are not forced-loader
   expectations.
4. Independently decode/compare v16 package and forced-loader representations
   at every proposed target sector, including `0x9C000..0x9CFFF`; decide
   explicitly how to preserve all user/configuration data and the target's
   device-specific prefix/JLFS header/tail.
5. Only after gates 1–4 pass, derive a new v16-specific recovery manifest from
   the exact failed target dump and reviewed official v15 package, implement a
   separate allow-listed writer, and test its scope/readback/failure handling
   using fake transport. Require exact target-sector pre-hashes, immediate
   readback, and whole-chip outside-range invariance.
6. Conduct a human safety review and obtain a separate explicit authorization
   before any physical write. After a successful restore, verify normal USB
   identity `SMK-37 Pro_015`, then display, MIDI/audio, keys/pads, and user
   presets. A successful sector readback alone is not proof of normal boot.

Never use a chip erase, full-chip image write, key burn, package-side sector
bytes directly on the target, or an unrelated old rollback bundle. The
previously tested 015 dumps are helpful provenance but do not satisfy the
fresh-v16-target acquisition gate.
