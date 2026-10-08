# v15/S1C5 authoritative memory map

Scope: exact v15 and current S1C5 evidence only. This consolidates physical Flash/package/JLFS/user tail, app runtime 0x02000000 mapping, global RAM 0x01c33260 object offsets, SysEx staging, current snapshot, owned S1C5 16-slot RAM, BSS/heap boundaries, storage raw records/flags/selection, persistent seed records, and MMIO/unknown regions only when evidenced. It does not claim v12 evidence and no device access was performed.

Confidence: PROVEN means exact byte/static or live-validated evidence; OBSERVED means exact evidence with partial boundary; INFERRED means arithmetic or policy consequence; BLOCKED means explicitly unsafe/refuted/unknown.

## Live Validated

| Start | End exclusive | Size | Type/owner | Evidence confidence | Mutability/patch policy | Source artifact links | Notes |
|---:|---:|---:|---|---|---|---|---|
| `0x0201c644` | `0x0201c64a` | `0x6` | S1C5 app patch: Note Off register reload | PROVEN | PATCHED: S1C5-owned change. Preserve in current baseline. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/live-validation-20260804.md` | lb.z r5,[r0] with padding. Live user result perfect. |
| `0x0201c682` | `0x0201c688` | `0x6` | S1C5 app patch: Note On register reload | PROVEN | PATCHED: S1C5-owned change. Preserve in current baseline. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/live-validation-20260804.md` | lb.z r6,[r0] with padding. Velocity store preserved. |
| `0x01c46e80` | `0x01c46f20` | `0xa0` | owned S1C5 16-slot RAM envelope | OBSERVED | S1C5 VOLATILE OWNED while installed. Rebuild only with selector ABI proof. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/code-evidence/report.md`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json` | Resident 16-slot selector/metadata envelope from S1C lineage. |
| `0x01c46f20` | `0x01c46f30` | `0x10` | S1C5 16-slot Playback Note RAM map | OBSERVED | S1C5 VOLATILE OWNED. Re-send after reboot until persistence milestone. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/live-validation-20260804.md` | Producer stores wire byte 161 to 0x01c46f20+slot. |

## Static Proven

| Start | End exclusive | Size | Type/owner | Evidence confidence | Mutability/patch policy | Source artifact links | Notes |
|---:|---:|---:|---|---|---|---|---|
| `0x00000000` | `0x00004000` | `0x4000` | physical Flash/package/JLFS/user tail protected boot and layout prefix | PROVEN | DO NOT PATCH. Protected hash unchanged. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/package-manifest.json` | Includes boot/layout and uboot/config subranges evidenced by package protected hashes. |
| `0x00004000` | `0x0009ad33` | `0x96d33` | physical Flash app area | PROVEN | PATCH ONLY via validated app-only candidate, CRC fields, rollback manifest. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/package-manifest.json` | app_area_start=0x4000, app_area_end_exclusive=0x9ad33. |
| `0x00004120` | `0x0009ad0c` | `0x96bec` | physical Flash app data payload | PROVEN | PATCH ONLY by runtime VA=file offset+0x02000000 mapping. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/package-manifest.json` | app_data_start=0x4120, app_data_size=0x96bec. |
| `0x0009ad33` | `0x000ab2d4` | `0x105a1` | physical Flash/package/JLFS/user tail post-app resources/reserved | PROVEN | DO NOT PATCH unless separately proven. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/package-manifest.json` | Package size 701140; post_app_resources_and_reserved hash unchanged. |
| `0x02000000` | `0x02096934` | `0x96934` | app runtime 0x02000000 mapping | PROVEN | Static address model. Patch only within validated app windows. | `baselines/v15/analysis/evidence.md`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json` | Runtime base proven by pointer/string evidence. S1C5 app size 0x96934. |
| `0x02000000` | `0x020000a4` | `0xa4` | boot/reset/data-copy/BSS-zero code | PROVEN | DO NOT PATCH. Boot memory and stacks. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | Copies data to 0x01c00000..0x01c099d4 and zeros BSS. |
| `0x02004870` | `0x02004b14` | `0x2a4` | storage raw read/write wrappers | PROVEN | Callable only with return==requested_length checks. | `baselines/v15/analysis/persistence-s2/storage/report.md` | read_02004870 and write_02004b02 wrapper ABIs. |
| `0x02005660` | `0x02005780` | `0x120` | stock selected-record loader and current snapshot producer | PROVEN | Do not bypass without preserving stock lifecycle. | `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md`<br>`baselines/v15/analysis/persistence-s2/storage/report.md` | Copies raw 0xa3 then expands packed fields. |
| `0x0201c5ec` | `0x0201c6a0` | `0xb4` | Note On/Off dispatcher current snapshot consumer | PROVEN | Patch only at S1C5 validated post-hook bytes. | `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md`<br>`baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/evidence.json` | Copies 0x9c from current snapshot to per-voice slot. |
| `0x0201e13e` | `0x0201e254` | `0x116` | S1C5 producer/selector/code cave region | PROVEN | S1C lineage owned. Preserve SHA unless rebuilding slot ABI. | `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app-manifest.json` | Selector returns r0=dest+0x9c; producer stores playback map byte. |
| `0x0201e254` | `0x0201e6a0` | `0x44c` | SysEx staging/current ingress handler | PROVEN | Do not use as durable storage. Supported traffic mutates staging/current. | `baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md`<br>`baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md` | Bulk and single-parameter SysEx paths. |
| `0x02048cce` | `0x02048d00` | `0x32` | memcpy-like routine | OBSERVED | Call only under established ABI. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | 146 decoded callsites observed. |
| `0x02060e2c` | `0x02060f20` | `0xf4` | allocator/heap init and malloc-like region | OBSERVED | Do not claim heap ownership. Arena bounds blocked. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | heap_init, malloc_like, and free_like observed but no arena proof. |
| `0x01c00000` | `0x01c099d4` | `0x99d4` | initialized data RAM | PROVEN | Stock RAM. Not free unless owner proven. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | Data copy destination. |
| `0x01c099d4` | `0x01c4651c` | `0x3cb48` | BSS/heap boundaries zero span | PROVEN | Not free by zeroing. Stack/globals/heap/task aliases must be excluded. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md`<br>`baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md` | BSS zero size 0x3cb48. |
| `0x01c33260` | `0x01c33264` | `0x4` | global RAM 0x01c33260 object base | OBSERVED | Stock global. Patch only by proven field offsets. | `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md`<br>`baselines/v15/analysis/persistence-s2/storage/report.md` | 492 base refs observed. |
| `0x01c333c0` | `0x01c333c4` | `0x4` | global RAM 0x01c33260 object offset +0x160 storage address/offset view | PROVEN | Read stock field. Do not repurpose. | `baselines/v15/analysis/persistence-s2/storage/report.md` | Boot stores translated write address. |
| `0x01c333c4` | `0x01c333c8` | `0x4` | global RAM 0x01c33260 object offset +0x164 direct mapped read pointer | PROVEN | Read stock field. Do not repurpose. | `baselines/v15/analysis/persistence-s2/storage/report.md` | Stock loader source pointer. |
| `0x01c33600` | `0x01c33609` | `0x9` | global RAM 0x01c33260 object offset +0x3a0 selection mirror | PROVEN | Stock selection. Do not encode custom state. | `baselines/v15/analysis/persistence-s2/storage/report.md` | Boot reads 9 selection bytes. |
| `0x01c344fc` | `0x01c3457c` | `0x80` | global RAM 0x01c33260 object offset +0x129c flag mirror | PROVEN | Stock flags. Do not encode custom state. | `baselines/v15/analysis/persistence-s2/storage/report.md` | Boot reads 0x80 flags. |
| `0x01c34c74` | `0x01c34d17` | `0xa3` | current snapshot raw/current record | PROVEN | Mutable stock current. Never owned S1C RAM. | `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md`<br>`baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md` | g+0x1a14; 0xa3 raw/current record. |
| `0x01c34c74` | `0x01c34d10` | `0x9c` | current snapshot dispatch prefix | PROVEN | Mutable. Safe source only at copy instant. | `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md` | 0x9c copied by dispatcher. |
| `0x01c34d10` | `0x01c34d17` | `0x7` | current snapshot stock tail | PROVEN | Stock tail. Not metadata/free. Preserve. | `baselines/v15/analysis/persistence-s2/storage/report.md` | Tail +0x9c..+0xa2 has stock consumers. |
| `0x01c37030` | `0x01c37034` | `0x4` | SysEx staging base | OBSERVED | Transient. No durable ownership. | `baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md` | Stage uses +0xfa0. |
| `0x01c37fd0` | `0x01c3806d` | `0x9d` | SysEx staging complete-message window | PROVEN | Transient. Never reread for Note Off. | `baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md`<br>`baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md` | 0x9c payload plus F7 at +0x9c. |
| `0x01c3a2d4` | `0x01c3c5d4` | `0x2300` | boot stack initializer value range | OBSERVED | No patch. Not a complete allocation map. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | sp/ssp/usp values inside BSS. |
| `STORAGE+0x0000` | `STORAGE+0x4000` | `n/a` | storage packed banks | PROVEN | Stock storage. Use stock packer only. | `baselines/v15/analysis/persistence-s2/storage/report.md` | 4*32*0x80. |
| `STORAGE+0x4000` | `STORAGE+0x9180` | `n/a` | storage raw records | PROVEN | Stock library records. Policy reservation only, not free. | `baselines/v15/analysis/persistence-s2/storage/report.md` | 128*0xa3 raw records. |
| `STORAGE+0x9180` | `STORAGE+0x9200` | `n/a` | storage flags | PROVEN | Stock flags. Do not encode custom state. | `baselines/v15/analysis/persistence-s2/storage/report.md` | 0x80 flag table. |
| `STORAGE+0x9200` | `STORAGE+0x9209` | `n/a` | storage selection | PROVEN | Stock selection. Do not encode custom state. | `baselines/v15/analysis/persistence-s2/storage/report.md` | 9-byte selected-bank/preset state. |

## Inferred

| Start | End exclusive | Size | Type/owner | Evidence confidence | Mutability/patch policy | Source artifact links | Notes |
|---:|---:|---:|---|---|---|---|---|
| `STORAGE+0x7d20` | `STORAGE+0x8740` | `n/a` | persistent seed records D1..D16 raw-prefix area | INFERRED | Policy reservation if Bank D records 96..111 are accepted as occupied. | `baselines/v15/analysis/persistence-s2/storage/report.md`<br>`baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed/report.md` | 16 records. Prefix 0x00..0x9b encodes S1C5 voice/playback note; tail preserved. |

## Refuted

| Start | End exclusive | Size | Type/owner | Evidence confidence | Mutability/patch policy | Source artifact links | Notes |
|---:|---:|---:|---|---|---|---|---|
| `0x01c099d4` | `0x01c4651c` | `0x3cb48` | generic zeroed BSS gap as owned RAM | BLOCKED | Refuted. Zero-on-boot is not ownership. | `baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md`<br>`baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | Blocked without owner/lifetime/no-alias proof. |
| `0x01c34c74` | `0x01c34d17` | `0xa3` | current snapshot as immutable S1C RAM | BLOCKED | Refuted. Mutable UI/SysEx/loader target. | `baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md` | Would repeat shared-current behavior. |
| `0x01c37fd0` | `0x01c3806c` | `0x9c` | SysEx staging as permanent voice storage | BLOCKED | Refuted. Transient assembly workspace. | `baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md`<br>`baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md` | Unsafe especially for Note Off. |

## Unknown

| Start | End exclusive | Size | Type/owner | Evidence confidence | Mutability/patch policy | Source artifact links | Notes |
|---:|---:|---:|---|---|---|---|---|
| `MMIO/IOREGIONS` | `MMIO/IOREGIONS` | `n/a` | MMIO/unknown regions | BLOCKED | Unknown. No row admitted without exact v15 evidence. | `baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md` | No evidenced MMIO range consolidated. |

## Explicit exclusions

- No v12 evidence is cited or required.
- BSS zeroing, absent decoded xrefs, raw-record tails, flags, and selection bytes are not free-space claims.
- MMIO/unknown hardware windows remain blocked unless a future exact v15 artifact proves a concrete range.
