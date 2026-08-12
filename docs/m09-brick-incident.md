# M09 boot-failure incident report

Date: 2026-07-15 (KST)

Status: `BOOT-FAILED / NO-USB`; root cause narrowed but not proven

## Executive conclusion

M09 was transferred and accepted by the normal OTA protocol, but the resulting
application produced neither visible UI content nor USB initialization. The
latest owner observation on 2026-07-16 is that the instrument powers on and
the LCD backlight illuminates, but the LCD has no visible pixels/UI and USB
does not enumerate. There is no observed battery fault.

Immediately after the failure, one true-power-cycle observation had the LCD
and pad LEDs dark. That remains a valid timeline observation, but it is not the
current electrical symptom. The stable recovery-relevant symptom is the lack
of application UI and both known USB identities.

The strongest established failure boundary is therefore the M09 application
package/change set, not a demonstrated OTA protocol error. The exact
instruction or data byte that stopped boot is not yet known because there is
no crash log, post-write Flash dump, or working forced-loader connection.

The two leading technical hypotheses are:

1. The zero-filled application-tail range used for drum templates was not safe
   persistent storage, despite having no statically visible direct reference.
2. The new M09 wrapper was reached during early initialization and faulted due
   to an invalid runtime, ABI, address, or instruction assumption.

M09 changed both of these dimensions at once, so the current evidence cannot
distinguish them. Reinstalling M09 is forbidden.

The effective brick was made possible by a separate recovery-design failure:
the only recovery route proven on the real unit was application-resident OTA.
When the application stopped before USB initialization, that route disappeared.
The independent mask-ROM/forced-upgrade path had been researched but had not
been physically demonstrated before M09 was installed.

“Bricked” here means that no currently demonstrated USB recovery path is
reachable. It does not prove permanent silicon, boot-ROM, Flash, or USB-PHY
damage.

## Observed timeline

1. M08 installed and booted through the same normal OTA toolchain.
2. The owner verified M08 Ch1/Ch10 isolation and Patch UI independence.
3. M09 OTA stage 1 acknowledged `0xe0000000`.
4. M09 OTA stage 2 reached request 1241 and acknowledged `0xf0000000`.
5. The normal USB identity did not return after the updater completed.
6. The display was black. Previously illuminated pad LEDs initially remained
   lit because the internal battery kept the old powered state alive.
7. Unplugging and reconnecting USB-C did not change the state.
8. After a real power-off and power-on, the display remained black and the pad
   LEDs remained off.
9. A fresh descriptor scan found neither normal nor updater USB identity.
10. On 2026-07-16 the owner clarified the current steady state: instrument
    power and LCD backlight are on, LCD content is absent, and USB still does
    not enumerate.
11. The battery and USB were both disconnected for five minutes, with the
    power switch used only while unpowered to discharge residual rails. After
    reconnecting the battery and booting without USB, the symptom was
    unchanged: instrument power, panel LEDs, and LCD backlight are present,
    but the LCD contains no pixels/UI. A latched PMU or residual-power state
    is therefore no longer a useful leading hypothesis.
12. During a direct Mac connection, macOS detected USB-C CC attachment and
    powered the host port, but no `IOUSBHostDevice` was created. This confirms
    cable attachment at the Type-C layer but does not prove D+/D- continuity;
    no normal, updater, or forced-loader USB identity was observed. Reversing
    the USB-C plug reproduced the same result: a clean detach/attach event and
    USB2 host-port power-on, but no USB device node.
13. The instrument was reassembled after the photo inspection. Its behavior
    remained unchanged: instrument power and LCD backlight are present, the
    LCD has no pixels/UI, and normal USB enumeration is absent. No new
    functional symptom was introduced by reassembly.

The OTA transcript is `backups/ota-M09-install-20260715.log`.

## Confirmed facts, inferences, and unknowns

| Class | Statement |
| --- | --- |
| Confirmed | The host completed both OTA protocol stages and received both completion acknowledgements. |
| Confirmed | M08 booted through the same packaging and upload path; M09 did not. |
| Confirmed | M09 remained non-booting after a true power cycle. |
| Confirmed | Neither known USB identity was present after the failure. |
| Confirmed | macOS detects USB-C physical attachment and activates the host port, but the SMK does not reach USB device enumeration. |
| Confirmed | Both USB-C plug orientations produce the same no-enumeration result. |
| Confirmed | Reassembly did not change the established failure signature. |
| Confirmed | The intended stock-to-M09 Flash delta is confined to six audited 4 KiB application sectors. |
| Inferred | The application failed before display and USB initialization, or reset repeatedly before reaching them. |
| Inferred | The boot ROM and USB hardware probably remain intact because no boot-prefix sector was intentionally modified. |
| Unknown | Whether the bytes actually written to Flash exactly match the M09 package. OTA acknowledgement is not Flash readback. |
| Unknown | Whether the first fault is caused by the template-data range or the new wrapper. |
| Unknown | Whether the application faults once, loops in reset, or stalls. |
| Unknown | Whether forced `USB_KEY` entry can still expose `WL82 UBOOT1.00` on this unit. |

## M08-to-M09 change boundary

An offline byte comparison of the built application images gives 954 changed
bytes:

| Change | M08-to-M09 changed bytes | Live status before M09 |
| --- | ---: | --- |
| Drum-template/map range at `0x020959EE..0x02095EDE` | 789 | Never written on the unit |
| Wrapper and relocated pad bridge in the existing code cave | 162 | M08 proved the cave and hook concept, not the new M09 instructions |
| Local-pad hook branch-target adjustment | 2 | Target changed only because the bridge moved |
| Display marker `M08` to `M09` | 1 | Earlier display markers were proven |
| **Total** | **954** | |

The template allocation is 1,264 bytes: eight 156-byte runtime templates
(1,248 bytes) plus a 16-byte note map. Only 789 of those bytes differ from the
former all-zero range. “1,264 nonzero bytes” is incorrect.

The M09 app manifest reports application SHA-256
`8c63f6f44877810b7f23ba88a91870aa758add099cb02d3de9721b6f636ecdbe`.
The FWSC package SHA-256 is
`5ac1264eba85ce5f1747458a90203bc144d21f87dc66f189ca055b74700ab5c8`.

## Ranked technical hypotheses

### H1: the zero-filled tail was not a safe data cave

Confidence: moderate; currently the leading hypothesis.

Supporting evidence:

- This is the largest new M09-only change and was never live-tested in
  isolation.
- M08 booted without modifying this range.
- Direct and destination-reference scans found no references, but that only
  rules out references recognizable by the current static analysis. It does
  not rule out an indirect base pointer, a loader/linker convention, a
  boot-time integrity rule, or required-zero state.
- The range was selected from zero padding near the application tail. Zero
  contents and lack of direct references do not establish ownership or a
  writable persistent-data contract.

Counter-evidence and limits:

- The range lies inside the packaged application and the normal repacker
  regenerated the known enclosing CRC fields.
- Merely storing bytes should not execute them. A failure requires an
  unidentified loader/runtime invariant or an early read through an indirect
  path.
- No dump from the failed device proves that this range was written exactly as
  intended.

### H2: the new wrapper faults when reached during startup

Confidence: moderate.

Supporting evidence:

- M09 replaced M08's factory-patch-loader path with new indexed map access,
  multiplication by 156, address addition, and a direct 156-byte copy.
- The 162 changed code-cave bytes were disassembled statically but never
  exercised on hardware before the full M09 install.
- Note initialization, all-notes-off, pad initialization, or another startup
  path may call a hooked Note On/Off-related function before user input.
- A wrong register, ABI, address-space, alignment, or instruction-encoding
  assumption could fault only when the Ch10 branch is reached.

Counter-evidence and limits:

- M08 already proved the same hook sites, channel-register assumptions,
  destination snapshot size, code-cave execution, and pad bridge pattern in
  normal use.
- Static Pi32v2 disassembly of the M09 wrappers and bridge is internally
  consistent.
- It is not established that a Ch10 event occurs before display/USB startup.

### H3: written Flash differs from the built M09 image

Confidence: low, not eliminated.

Supporting evidence:

- The OTA protocol acknowledges transfer completion; it does not provide an
  independent full-Flash readback.
- A transport, target write, or power-state fault could theoretically leave an
  invalid application while still acknowledging the final command.

Counter-evidence:

- The deterministic package and dry-run checks passed.
- Both OTA stages completed without a reported packet error.
- The same uploader and package pipeline had worked repeatedly through M08.

### H4: known common patches caused the failure

Confidence: low.

The Note On/Off hook locations, disabled SysEx calls, and general pad-bridge
mechanism were already present in the booting M08 image. M09 changed the pad
hook target by two bytes because its bridge moved, so a relocation error is
not mathematically impossible, but the bridge disassembly is valid.

### H5: display marker, unrelated hardware damage, or boot-ROM overwrite

Confidence: very low.

Earlier version-marker changes booted. The failure occurred immediately after
M09, and the intended package delta does not touch the boot prefix. There is no
evidence of an electrical event or a write to the mask ROM, which is immutable.

## Why loss of USB made this an effective brick

The successful M04-to-M08 restores established only this recovery loop:

```text
running application -> application OTA mode -> upload official v12 -> reboot
```

M09 broke the first dependency. If the application does not initialize USB,
neither its normal identity nor its updater identity is available, so a known
good package cannot be sent through the proven route.

The independent recovery loop should have been established first:

```text
mask ROM USB_KEY entry -> forced loader -> read/verify Flash -> restore exact sectors
```

That loop was not demonstrated on SMK-37 Pro. The missing safety property was
therefore not “a stock firmware file exists”; it was “stock firmware can be
written without executing the installed application.”

## Process causes

1. Successful application OTA rollback was treated as a sufficient recovery
   floor even though it depended on the application continuing to boot.
2. M09 combined two unproven dimensions: a new persistent-data location and a
   new direct-copy wrapper.
3. Static disassembly and no-reference scans were treated as stronger evidence
   than they are. They prove encoding and visible references, not runtime
   ownership or boot safety.
4. OTA completion was correctly recorded, but it could be mistaken for
   successful installation unless boot verification is kept as a separate
   gate.
5. The independent forced-upgrade entry and readback path was not physically
   proven before accepting a change capable of failing before USB init.

## Recovery scope already prepared

The intended M09 Flash image differs from official v12 in exactly six 4 KiB
sectors:

| Physical sector | Intended changed bytes | Contents |
| --- | ---: | --- |
| `0x04000` | 8 | Application header/CRC |
| `0x20000` | 6 | Note Off hook |
| `0x21000` | 126 | Note On hook and wrapper |
| `0x27000` | 6 | Local-pad bridge hook |
| `0x5A000` | 4 | Display marker |
| `0x99000` | 789 | Drum templates/map and enclosing ciphertext |

These are planned-image differences, not a readback of the failed unit. The
sector hashes and restore gate are in `build/m09-forced-recovery/manifest.json`
and `docs/forced-recovery-plan.md`.

## Required controls before any future custom firmware

1. Demonstrate forced `USB_KEY` entry on the real instrument without writing.
2. Upload a loader and archive a full read-only Flash dump.
3. Prove an exact stock-sector restore and readback through a recovery path
   that does not depend on the application.
4. Change only one unproven dimension per build.
5. Never classify zero padding as a data cave from a reference scan alone.
   Require loader/section ownership evidence or a disposable-device runtime
   proof.
6. Keep “OTA transfer complete”, “application booted”, “USB returned”, and
   “audio behavior passed” as separate ledger states.
7. Do not write boot-prefix, key, calibration, user, or non-target sectors.
8. Never use chip erase or a full-Flash write as an exploratory recovery step.
9. Revoke M09 permanently; any future derivative must receive a new build ID.

No new live firmware experiment is allowed until controls 1 through 3 are
complete.

## Evidence needed to identify the exact root cause after recovery

After forced recovery is independently working, archive the failed unit's full
Flash dump before restoring it. First compare that dump with the intended M09
image. If it differs, H3 becomes primary.

If the dump exactly matches M09, isolate H1 and H2 only on a recoverable unit:

- data-only probe: populate the proposed range but leave all execution paths
  identical to M08;
- code-only probe: run the new wrapper against a storage range with proven
  ownership, without changing the proposed tail range;
- early-boot instrumentation: expose a minimal persistent or hardware-visible
  checkpoint before display and USB initialization.

These probes are diagnostic designs, not authorization to install them on the
currently inaccessible unit.

## Evidence artifacts

- `backups/ota-M09-install-20260715.log`
- `build/SMK37ProMod-M08-app-manifest.json`
- `build/SMK37ProMod-M09-app-manifest.json`
- `build/m09-forced-recovery/manifest.json`
- `analysis/m09-wrapper-listing.txt`
- `analysis/m09-wrapper-on-listing.txt`
- `analysis/m09-pad-bridge-listing.txt`
- `analysis/m09-primary-data-cave-references.txt`
- `analysis/m09-primary-cave-prefix-references.txt`
- `analysis/m09-primary-cave-suffix-references.txt`
- `analysis/m09-secondary-data-cave-references.txt`
- `analysis/m09-tail-cave-references.txt`
