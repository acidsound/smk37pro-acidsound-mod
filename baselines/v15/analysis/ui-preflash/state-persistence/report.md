# v15 current Patch state and SAVE/SAVED persistence static RE

Scope: official v15 app/full package only. No v12 structure was used, and no patch/flash/commit action is performed by the script.

## SHA gates

- app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` (PASS)
- package: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` (PASS)
- package `flash.bin` slice: `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a` (PASS)
- quarkslab exhaustive listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` (PASS)

## 한국어 결론

- 확정: current Patch 선택값은 `0x01c33260+0x3a4` bank와 `0x01c33260+0x3a0+bank` preset이며, `0x02005660` factory loader가 `(bank*32+preset)*0xa3` 레코드를 `*(+0x164)+0x4000`에서 `+0x1a14` current snapshot으로 복사한다.
- 확정: `+0x129c + bank*32+preset` 플래그가 loader의 SAVE/SAVED 표시 상태 분기와 가장 강하게 연결된 v15 내부 근거다.
- 확정: seed `0x01c34c74`는 `0x0201c5ec`에서 0x9c-byte voice/note slot 복사 소스로 쓰이며, loader 자체의 current snapshot 주소는 `0x01c33260+0x1a14`다.
- 후보: `0x02026d6c`는 동일 record 계산 후 `+0x1a14`, `*(+0x160)+0x4000+record*0xa3`, `0xa3`를 storage wrapper `0x02004b02`에 넘기고 `+0x129c`/`+0x9180`을 갱신하므로 SAVE writer 후보다. 다만 `0x02063260` primitive 방향은 이 listing만으로 확정하지 않았다.
- 미확정: SAVE/SAVED styled label의 UI widget xref와 cfg_tool 실행/호출 체인은 direct pointer로 확정되지 않았다.

## 확정

- `sha-gates`: Official v15 app/package/listing SHA gates match expected values. flash.bin gate is package payload offset 20 + UFW offset 1024.
- `factory-loader-current-selection`: 0x02005660 reads RAM object base 0x01c33260, selected bank at +0x3a4 (0..3), selected preset at +0x3a0+bank (0..31).
- `factory-loader-record-copy`: 0x02005660 computes record index (bank*32+preset)*0xa3 from pointer *(0x01c33260+0x164), adds 0x4000, and memcpy()s 0xa3 bytes to current snapshot 0x01c33260+0x1a14.
- `factory-loader-expanded-ui-fields`: After the raw 0xa3 copy, 0x02005660 expands/normalizes packed fields into +0x1a14, +0x1a90, +0x1aa0 and invokes four update helpers 0x0200552e/0x0200558e/0x020055f8/0x0200562c.
- `dirty-saved-flag-table`: 0x02005660 indexes +0x129c + bank*32+preset and branches on flag 0/1 before copying display bytes. This is the strongest static link between selected patch and SAVE/SAVED state.
- `current-patch-buffer-consumer`: 0x01c34c74 is referenced directly only in 0x0201c5ec. That function copies 0x9c bytes from 0x01c34c74 into per-note/voice slots, so it is a runtime current-patch consumer rather than the factory loader itself.
- `official-ui-strings`: Official app contains #D9D9D9 SAVE#, #f5bc27 SAVED#, Please select a bank to save, usrflash, cfg_tool.bin, VM/app_dir_head/flash.bin/flash2.bin strings at the reported addresses.

## 후보

- `save-writer-candidate-02026d6c`: 0x02026d6c gates on +0x1ec and non-0xff state, recomputes current bank/preset record, passes current snapshot +0x1a14, storage address *(+0x160)+0x4000+record*0xa3, and length 0xa3 to 0x02004b02, then marks +0x129c entry and flushes/updates *(+0x160)+0x9180 length 0x80. Direction and primitive semantics are candidate because the storage wrapper is only partially decoded.
- `bank-load-save-cluster-0202553c`: 0x0202553c handles bank selection, calls 0x02004a54 with mode 2 and bank*0x1000 storage base, transfers 0x1000 bytes via 0x02004b02, clears 32 dirty/saved flags at +0x129c, flushes +0x9180, writes +0x3a4/+0x3a0, and calls factory loader. This is likely bank-level load/commit preparation.
- `storage-wrapper-candidate`: 0x02004b02 wraps 0x02004a7a, which bounds checks against a storage size field and calls 0x02063260 through a request object at +0xd1c. It behaves like a USRFLASH/VM storage transfer primitive, but exact read/write direction remains unconfirmed in this static pass.
- `usrflash-low-level-candidate`: 0x0201e846 toggles registers 0x50040/0x11d00 and commands 0x2a/0x2b/0x2c around buffers, near the usrflash string table. It is likely low-level flash/USRFLASH service code, but no direct caller chain from SAVE was confirmed.

## 미확정

- `ui-widget-xref-to-save-strings`: The SAVE/SAVED styled labels are present in the app data, but no direct absolute pointer xref was emitted by the v15 listing. UI resource tables appear to use packed/resource indexing or data tables not resolved by this listing.
- `exact-storage-primitive-direction`: 0x02004b02 and 0x02004a7a are tied to the save candidate but the downstream 0x02063260 primitive is not decoded in the available listing, so read vs write direction is not asserted as confirmed.
- `old-v12-structure`: No v12-derived offsets or names were used. All addresses and offsets in this report come from v15 app/package/listing only.

## 핵심 데이터 흐름

```mermaid
flowchart TD
    S[0x01c33260 + 0x3a4 selected bank] --> I[(bank*32 + preset)]
    P[0x01c33260 + 0x3a0 + bank selected preset] --> I
    I --> R[record * 0xa3]
    B[*(0x01c33260 + 0x164)] --> L[factory loader 0x02005660]
    R --> L
    L --> C[copy from B + 0x4000 + record*0xa3 to 0x01c33260 + 0x1a14]
    C --> E[expanded UI/current fields +0x1a90/+0x1aa0]
    I --> F[flag table 0x01c33260 + 0x129c + index]
    F --> V[SAVE/SAVED display state candidate]
    C --> W[save candidate 0x02026d6c]
    W --> T[0x02004b02 storage transfer candidate]
    T --> U[USRFLASH/VM backing store candidate]
```

## Strings and paths found in official app

- `0x02057298` `SAVE`
- `0x020574c4` `BANK %c`
- `0x02057672` `Preset-%d`
- `0x02057baf` `Enable PATCH first`
- `0x02057d2c` `mnt/sdfile/app/usrflash`
- `0x02057f18` `mnt/sdfile/app/cfg_tool.bin`
- `0x02057f6c` `Please select a bank to save`
- `0x0205d97a` `#D9D9D9 SAVE#`
- `0x0205d988` `#f5bc27 SAVED#`
- `0x0205d9c5` `Pad Bank-`
- `0x0208ad85` `app_dir_head`
- `0x0208ade4` `cfg_tool.bin`
- `0x0208adf1` `flash.bin`
- `0x0208adfb` `flash2.bin`
- `0x020929cc` `vmH`

## Reproduction

Run:

```sh
python3 baselines/v15/analysis/ui-preflash/state-persistence/analyze_state_persistence.py
```

The script regenerates `state_persistence_evidence.json` and this report from v15-only inputs.
