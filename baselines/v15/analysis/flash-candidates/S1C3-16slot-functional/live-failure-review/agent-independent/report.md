# S1-C3 16-slot functional live failure independent review

Date: 2026-08-03 UTC  
Scope: exact currently installed reset-aware S1-C3 functional candidate, static/offline only. I did not access the device, flash, OTA, reset, or open MIDI/USB transport.

## Finding

The live symptom, “all Ch10 pads sound stock Ch1 after a successful 16-packet host send,” is the selector fallback symptom. In the installed selector, `r1` remains the original stock/H2 fallback source unless both predicates pass:

1. publication state byte `0x01c465bf == 2` (`ARMED`), checked at `0x0201e162..0x0201e164`;
2. selected slot valid byte `0x01c46520 + (note - 36) * 0xa0 + 0x9c == 1`, checked at `0x0201e170..0x0201e176`.

I do not see static evidence for a wrong hook, call target, staging ABI, r9 gate, reset signature, metadata overlap, or push/call return defect. The most defensible root-cause class is that producer publication did not reach selector-consumable `ARMED`, or the selector observed it as not `ARMED`. The most likely live mechanism is fewer than all 16 exact direct products being accepted by firmware after slot0 reset, leaving state `LOADING` instead of `ARMED`; host-side “16 bulk sends succeeded” does not prove producer count/state advancement.

## Exact installed bytes checked

- App SHA-256: `a6f99cf6672ae3bd5b00312876a77ce1ed0e8a909ef56df7af0db34a2f726e05`.
- FWSC SHA-256: `974c1675426e5d43f6b48e7ac7a1142f40062fca945dc6ba1b3ace8b0d144496`.
- Producer SHA-256: `5c0ec6675c29b8f20d055938425ceb12c356513c29b79b761f1a469eaa068a75`.
- Note Off hook `0x0201c63e`: `80fffa1a0000`, targets selector note-off entry `0x0201e13e`.
- Note On hook `0x0201c67c`: `80ffc01a0000`, targets selector note-on entry `0x0201e142`.
- Direct product call `0x0201e468`: `bfeadcfe`, targets reset wrapper `0x0201e224`.
- Segmented product call `0x0201e49c`: `bfeac0fe`, targets no-mutation stub `0x0201e220`.

## Producer publication review

The reset-aware producer bytes match the intended 172-byte PI32 stream.

- Direct route enters reset wrapper `0x0201e224`, then calls original sequential producer `0x0201e1a2`.
- The original producer gates `r9 == 0xa3` at `0x0201e1a6..0x0201e1ac`, before lock/testset/state/count/slot mutation.
- Reset wrapper checks accepted staging bytes `[0..1] == 62 63`, clears lock/count/state at `0x01c465bd..0x01c465bf`, then calls `0x0201e1a2`.
- Actual slot00 runtime begins `62 63 62 00 63 42 62 00`, so the reset signature matches the exact first packet.
- No later packet has first two runtime bytes `62 63`, so the reset should not accidentally fire mid-sequence.
- Publication order is valid-clear, 0x9c memcpy, csync, valid=1, loaded_count=i+1, and only slot15 stores `state=2` last.

## RAM metadata overlap review

The overlap is intentional and internally consistent:

| Address | Purpose |
|---|---|
| `0x01c46520..0x01c465bb` | slot0 0x9c-byte voice payload |
| `0x01c465bc` | slot0 valid |
| `0x01c465bd` | producer lock |
| `0x01c465be` | loaded_count |
| `0x01c465bf` | publication state |
| `0x01c465c0` | slot1 voice start |

The producer copies exactly `0x9c` bytes, so it does not overwrite valid/lock/count/state while writing slot0.

## Minimal diagnostic checkpoint

Use a one-discriminator firmware checkpoint, only with future explicit authorization:

**S1C3-PUB1:** temporarily change the selector state predicate from `state == 2` to `state == 1`, leaving the producer and selected-slot valid gate unchanged. The relevant installed branch is at `0x0201e164` (`80f80a04`, decoded as `jne r0,#2,copy`). Then send only exact slot00/note36 once and press the physical pad that emits Ch10 note36.

Interpretation:

- If note36 changes from stock, slot0 publication and selector source selection are live. The current failure is completion/final `ARMED` publication, for example dropped/rejected later packets or count progression.
- If note36 remains stock, the failure is before or at slot0 publication/selector reach, such as producer not invoked, r9 gate not passing, live staging signature mismatch, lock/testset issue, or hook/channel gate not selecting.

This is a single selector-predicate discriminator between “producer published at least slot0 but never reached `ARMED`” and “no selector-consumable publication at all.”

## Validation

Commands run offline only:

```text
python3 validate.py
shasum -a 256 app.bin SMK37Pro-v15-S1C3-16slot-functional.fwsc inputs/producer/producer.bin inputs/producer/evidence.json exact_16_packet_sender.c exact_ota.c validate.py
python3 packet/runtime prefix inspection script
python3 app hook/callsite byte extraction script
```

Key outputs are captured in `evidence.json`. No existing shared files were modified.
