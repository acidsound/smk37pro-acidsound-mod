# USB 안전 플래싱 준비 조사 — 확장 메모리 맵 v2

작성: 2026-10-01 · 상태: **오프라인 조사 완료 / 실기기 미접촉 / 플래시 미승인**

이 문서는 "바닥부터"(Jieli AC79 SDK) 경로가 2026-08-15에 브릭으로 중단된 뒤,
**확실한 근거를 가지고 USB로 플래싱할 수 있게** 하기 위해 기존 확정 메모리 맵을
확장한 결과다. 장치를 만지지 않았고, 어떤 쓰기·OTA·리셋도 수행하지 않았다.
모든 주장에는 저장소 안에 존재하는 산출물 경로가 붙어 있다
(`validate.py`가 경로 존재와 수치 일관성을 강제한다).

- 기계 판독용 맵: [`memory-map-v2.json`](memory-map-v2.json) (43행)
- 실행 커버리지: [`coverage.json`](coverage.json) — [`analyze_coverage.py`](analyze_coverage.py)로 재생성
- 운영용 게이트: [`docs/usb-flash-safety-case.md`](../../../../docs/usb-flash-safety-case.md)
- 기존 기준 맵(대체하지 않음): [`../memory-map/memory-map.json`](../memory-map/memory-map.json)

---

## 0. 결론 세 줄

1. **브릭의 직접 원인을 코드 수준에서 특정했다.** 플래시된 SDK 앱은
   `-DCONFIG_NO_SDRAM_ENABLE`이 빠진 채 빌드되어 `.data`/`.bss`/malloc 힙이
   **SDRAM 창 `0x04000000`** 에 배치됐다. 이 장치의 정상 v15 앱은 그 주소를
   전혀 쓰지 않는 SFC/XIP 빌드다. 즉 앱이 부팅 직후 USB를 초기화하기도 전에
   존재하지 않거나 초기화되지 않은 메모리를 건드렸다.
2. **오프라인 게이트를 통과한 산출물과 실제로 플래시된 산출물이 달랐다.**
   검증된 것은 `SDK-DEMO-HELLO`(NO_SDRAM 포함 빌드)였고, 실제로 올린 것은
   `SDK-DEMO-OTA`(NO_SDRAM 누락 빌드)였다. 어떤 게이트도 "플래시할 바이너리의
   링크 맵이 장치의 확정 메모리 모델과 맞는가"를 검사하지 않았다.
3. **메모리 맵을 3축으로 확장했다.** (a) 물리 플래시 1 MiB 전체를 빈틈·중복 없이
   닫고, (b) 런타임 `0x02000000` 창의 UI→Synth 소유권과 **미해독 256 KiB**를
   정량화하고, (c) SDK 기본 레이아웃이 요구하는 SDRAM 창을 BLOCKED로 못박았다.

---

## 1. 2026-08-15 브릭 사건 재구성

### 1.1 타임라인 (근거 있는 항목만)

| 시각 (KST) | 사건 | 근거 |
|---|---|---|
| 2026-08-14 | P0a 빌드 PASS, `SDK-DEMO-HELLO` fwsc 패킹 — **플래시되지 않음** | [from-scratch-platform-plan.md](../../../../docs/from-scratch-platform-plan.md) |
| 2026-08-15 00:26–00:27 | 자체 복구 SDK 앱(demo_ota) 빌드 + fwsc 패킹. 토큰 `INSTALL-SMK37PRO-V15-SDK-DEMO-OTA-673DA1D5`, fwsc SHA-256 `673da1d518eff494d0cf63c549d0ccffd63f5a8764f49ffa60d0d4d283af33bb` | [package-manifest.json](../fwsc-repack-sdk-app/output/sdk-demo-ota/package-manifest.json) |
| 2026-08-15 00:34 | 정상 모드에서 exact_ota로 플래시. stage-1(`0xE0000000`)·stage-2(`0xF0000000`) **둘 다 ACK = 쓰기 자체는 완료** | [ota-sdk-demo-ota-install-20260815T003442Z.log](../../../../logs/v15/ota-sdk-demo-ota-install-20260815T003442Z.log) |
| 직후 | USB 버스에 장치가 **전혀 없음**. 정상 `4353:cf4d`도, 업데이트 `4d4a:4155`도 나타나지 않음 | 세션 기록(§1.2) |
| 2026-08-15 01:37 | 사용자 보고: "bricked 되었는데?" | 세션 기록 |
| 2026-08-15 | 녹색 LED 꺼짐. Jieli Forced Upgrade Tool 4.0으로만 복구 가능 | 세션 기록 |
| 2026-08-16 01:44 | 사용자가 강제 도구로 복원 → **스톡 v15**(표시 1.10), 브릭 직전 버전은 아님 | 세션 기록, [m09-restore-2026-08-14.md](../../../../docs/m09-restore-2026-08-14.md)(동일 절차 선례) |
| 2026-08-16 01:50 | exact_ota로 S1C6(S16) 재설치 성공 | [ota-v15-s1c6-restore-from-stock-20260816.log](../../../../logs/v15/ota-v15-s1c6-restore-from-stock-20260816.log) |

> **현재 장치 상태는 이 저장소의 마지막 기록(2026-08-16, S16 설치) 이후 6주간
> 확인되지 않았다.** 다음 세션은 어떤 조치보다 먼저 read-only `device-info`로
> 현재 identity를 확인해야 한다.

### 1.2 세션 기록의 취급

위 타임라인의 "직후"·"사용자 보고" 항목은 DSH 로컬 세션 저장소
`.freebuff/desktop-v2.db`(이 워크스페이스의 이전 대화 기록, 커밋되지 않음)에서
복원했다. 재현:

```sh
sqlite3 .freebuff/desktop-v2.db \
  "select seq,role,datetime(ts/1000,'unixepoch','localtime'),substr(parts_json,1,300) \
   from messages where thread_id='1b57b180-7e67-4e36-b8f7-30bba5f69a85' order by seq;"
```

이 항목은 저장소 산출물이 아니므로 `memory-map-v2.json`의 근거로는 등록하지
않았다. 저장소 근거만으로 확정되는 것은 **"쓰기는 성공, 부팅 후 USB 미인식"**
까지이며, 그것만으로도 아래 원인 판정에는 충분하다.

---

## 2. 근본 원인 판정

### 2.1 RC-1 (주 원인, 근거 확정): SDK 앱이 SDRAM 레이아웃으로 링크됐다

**증거 사슬 (전부 오프라인 재현 가능):**

1. 플래시된 fwsc 안의 `app.bin` SHA-256은
   `5caaaf32d214e04617ff03e3dd4a40221a578e01be06e4188316bc0568ee8daa`(125,024 B).
2. 현재 SDK 빌드 트리의 `cpu/wl82/tools/app.bin`도 **같은 SHA-256**이다 →
   디스크의 빌드 산출물이 곧 플래시된 바이너리다.
3. 그 바이너리를 만든 `sdk.map`:
   `.data @ 0x04000000 (0x988)`, `.bss @ 0x040009a0 (0x2bb0)`,
   `_HEAP_END = 0x041fffe0`.
4. 링커 스크립트 생성 경로: `cpu/wl82/sdk_ld.c`가
   `CONFIG_NO_SDRAM_ENABLE` **정의 여부**로 `sdk_ld_sfc.c`와
   `sdk_ld_sdram.c` 중 하나를 고른다.
5. 두 앱의 보드 Makefile `DEFINES`를 diff하면 **정확히 한 줄** 차이다:

   ```
   < -DCONFIG_NO_SDRAM_ENABLE         # demo_hello: 있음
   ```

   `demo_ota`(플래시된 쪽)에는 이 정의가 **없다**. → `sdk_ld_sdram.c`가 선택되고
   `.data`/`.bss`와 **malloc 힙 전체**가 `0x04000000` 창으로 간다.
6. 이 장치의 확정 메모리 모델: 정상 v15 앱은 런타임 `0x02000000`,
   RAM `0x01c00000..0x01c4651c`, 스택 `0x01c3a2d4`만 사용한다. `0x04000000`을
   쓰는 행은 하나도 없다. 게다가 `0x04000000` SDRAM **탑재 여부 자체가
   "미입증"으로 이미 문서화**되어 있었다.
7. **SDK에 동봉된 공식 AC7911B8 데이터시트**(V1.0, 2021-12-10, §4 Package Type
   Specification)가 이 물음을 사실상 닫는다. 부품 번호는
   `AC7911` + ①(칩/본딩) + ②(메모리 코드)이고 **메모리 코드는 한 자리**다:

   ```
   0: 없음   2/4/8/6/3/5/7: 2/4/8/16/32/64/128 Mbit Flash
   A: 1Mx16 SDRAM   B: 4Mx16 SDRAM   C: 16 Mbit PSRAM   D: 64 Mbit PSRAM
   ```

   이 장치는 `C108221-11B8`로 표기되고 플래시는 **1 MiB = 8 Mbit**로 실측된다
   → 코드 `8` = 8 Mbit Flash와 정확히 일치한다. 즉 **AC7911B8은 8 Mbit Flash
   부품이지 SDRAM/PSRAM 부품이 아니다.** SDK 데모의 4 MiB/2 MiB 기본값은 이
   부품의 값이 아니다.
   → `baselines/v15/analysis/usb-flash-readiness/memory-map-v2.json` `v2-sd-005`

**결과**: `startup`의 `.data` 복사와 `.bss` 제로화, 그리고 `app_main`의
`os_task_create`(힙 할당)가 모두 SDRAM 창을 건드린다. SDRAM 컨트롤러가 이
장치의 부트 체인에서 초기화되지 않았다면 그 첫 접근에서 멈춘다 — USB
enumeration 이전이다. 관측된 증상(쓰기 완료 → USB 완전 부재)과 정확히 일치한다.

**반증 조건과 잔여 확인**: RC-1을 뒤집으려면 이 보드에 **외부** DRAM 다이가
실장되어 있고 SMK 부트 체인이 SDRAM 컨트롤러를 초기화한다는 증거가 필요하다.
데이터시트가 SiP 메모리 옵션을 배제했으므로 남은 것은 PCB 실장 여부뿐이고,
이는 기존 FCC 내부 사진·오너 보드 사진으로 판정 가능하다(개방 불필요).
→ §5 G-01

### 2.2 RC-2 (기여 요인): 플래시 크기 가정 불일치

`app_config.h`의 `__FLASH_SIZE__ (4 * 1024 * 1024)`와 `isd_config.ini`의
`FLASH_SIZE=4M`은 SDK 데모 기본값이다. 실제 칩은 **1 MiB**다. SDK의 mtd/update
배치 계산이 4 MiB를 전제하면 칩 경계 밖 주소를 계산한다.
[m09-wl82-dump-2026-08-15.md](../../../../docs/m09-wl82-dump-2026-08-15.md)

### 2.3 RC-3 (기여 요인): SMK에 없는 SDK 부트 규약

`sdk_ld_sfc.c`/`sdk_ld_sdram.c`는 `BOOT_INFO_SIZE=48`(→ `0x01c7fd50`)와
`UPDATA_BEG = 0x1c7fe00 - 128`(→ `0x01c7fd80`)을 전제한다. 이는 SDK의
uboot/update 규약이며, SMK의 부트 체인이 이 값을 써 준다는 증거가 없다.
SDK 앱이 이 영역을 읽으면 미초기화 RAM을 소비한다.

### 2.4 RC-4 (프로세스 원인 — "조사가 부족했다"의 실체)

| 실패 | 내용 |
|---|---|
| 게이트-산출물 불일치 | 오프라인 게이트 9종은 `SDK-DEMO-HELLO`(NO_SDRAM **포함**)로 통과했고, 올린 것은 `SDK-DEMO-OTA`(NO_SDRAM **누락**)였다. 게이트는 "패키지 구조 불변"만 봤지 **링크 맵**을 보지 않았다. |
| 메모리 모델 교차검증 부재 | 확정 맵에 `0x04000000`이 **없다는 사실**이 경고로 쓰이지 않았다. |
| 폴백 제거 | 앱이 "정상 모드 identity 없음 + 업데이트 모드 전용"으로 설계되어, USB 초기화가 실패하면 소프트웨어 복원 경로가 **0**이 된다. M09 교훈("복원 경로가 앱 부팅에 의존하면 안 된다")이 새 형태로 반복됐다. |
| 자기복구 가정 | "4d4a:4155로 뜨면 복원 가능"은 **USB가 뜬다는 전제** 위에 세워졌고, 그 전제 자체가 미검증이었다. |

---

## 3. 확장 메모리 맵 (v2)

`memory-map-v2.json`은 기존 맵을 **대체하지 않고 확장**한다. 주소 공간을
명시적으로 분리해 v1에서 섞여 있던 물리 플래시·런타임·RAM·파일 오프셋을
구분한다.

### 3.1 물리 플래시 (칩 경계를 닫음)

| 범위 | 크기 | 소유 | 정책 |
|---|---:|---|---|
| `0x000000..0x00100000` | 1 MiB | **실장 SPI NOR 전체** | 상한. `>= 0x100000` 절대 금지 |
| `0x000000..0x00004000` | 16 KiB | 부트 헤더/uboot/레이아웃 | **PRESERVE** |
| `0x00004000..0x00004300` | 768 B | JLFS 헤더 (`plain ^ lfsr(0x132b)`) | **PRESERVE** |
| `0x00004300..0x0009A833` | 598 KiB | 애플리케이션 영역 | 앱 전용 OTA/가드 복원만 |
| `0x0009A833..0x0009C000` | 6 KiB | tail 메타데이터(동적) | **PRESERVE** |
| `0x0009C000..0x00100000` | 400 KiB | 패키지 밖 사용자/프리셋 데이터 | **PRESERVE** |

행들은 `0x0..0x100000`을 빈틈·중복 없이 덮는다(`validate.py`가 강제).
`0x9C000` 이후에는 DX7 뱅크(`0xF4000..`)와 per-preset 레코드(`0xF8000..`)가
있어, 여기를 잃으면 사용자 데이터가 사라진다.

### 3.2 런타임 `0x02000000` 창 — UI부터 Synth까지

| 주소 | 소유/역할 | 등급 | 상태 |
|---|---|---|---|
| `0x02000000..0x020000A4` | 부트/데이터 복사/BSS 제로 | PROVEN | DO NOT PATCH |
| `0x02004870..0x02004B14` | 스토리지 read/write 래퍼 | PROVEN | 반환값 검사 필수 |
| `0x02005660..0x02005780` | 선택 레코드 로더 / 스냅샷 producer | PROVEN | 우회 금지 |
| `0x0201C5EC..0x0201C6A0` | Note On/Off 디스패처 (**Ch10 판별점**) | PROVEN | 실기 검증된 훅만 |
| `0x0201C63E`, `0x0201C67C` | Note Off/On 음색 소스 복사 지점 | PROVEN | S1C5/S1C6 계보 |
| `0x0201E13E..0x0201E254` | S1C producer/selector + 리셋 시그니처 | PROVEN | 여유 2 B |
| `0x0201E254..0x0201E6A0` | SysEx ingress/staging | PROVEN | 영구 저장 금지 |
| `0x02029290`, `0x02029528` | **UI 상태머신 / grid·submode 디스패치** | OBSERVED | 후보, 미검증 |
| `0x0201A67C` | UI 객체 C-string setter | OBSERVED | 후보 |
| `0x02026D6C..0x02026DD4` | 현재 Patch 저장 writer | OBSERVED | S1C7~9 영속화 실패 지점 |
| `0x0205773B..0x02058314` | **stock USB-MIDI 디스크립터/문자열/클래스 테이블** (device descriptor `0x02057B53` = VID `0x4353`/PID `0x4B4D`, MIDIStreaming interface `0x020579AE`, CIN 표 `0x02057AB0`, UTF-16 제품 문자열 `0x02057FA8`, EP `0x02057FC6`/`0x02057FD6`, 12-descriptor jack graph `0x02058274`) | PROVEN | 읽기 전용 기준 |
| `0x02058248..0x02058314` | 11엔트리 콜백 벡터 | **BLOCKED** | 테이블 존재만 확인, dispatcher 미발견 |
| `0x02057000..0x02097000` | **미해독 256 KiB** | **BLOCKED** | 코드 아님(문자열·테이블 데이터). 세부는 부록 B.3 |

**UI→Synth 경로의 현재 상태를 정직하게 요약하면:**

- **확보**: MIDI ingress → 채널 판별(`0x0201C5EC`) → 156/0x9c 바이트 voice
  스냅샷(`0x01C34C74`) → S1C 16슬롯 RAM(`0x01C46E80`). 이 경로는 실기 검증됨.
- **미확보 (UI 쪽)**: renderer의 **최종 LCD write**, 물리 입력 producer/ID,
  `0x02058248` 콜백 벡터의 dispatcher. ui-preflash의 REQ-06/REQ-05가 그대로
  미완료다. → [ui-preflash/README.md](../ui-preflash/README.md)
- **미확보 (Synth 쪽)**: **v15의 Note On/Off·synth context·voice 구조체 주소는
  의도적으로 "미할당" 상태다.** SDK 대조에서 두 개의 독립 일치를 얻지 못했기
  때문이다. → [sdk-signatures/evidence.md](../sdk-signatures/evidence.md)

즉 "UI부터 Synth까지"는 **양 끝이 비어 있다**. 가운데(디스패치·스냅샷·저장)만
확정되어 있다. 이것이 지금 바닥부터 접근했을 때 가장 먼저 부딪히는 벽이며,
동시에 다음 조사의 우선순위다.

### 3.3 디코드 커버리지 (정량)

`coverage.json` (공식 v15 앱 617,012 B = `0x96A34` 창, 4 KiB 151페이지):

| 지표 | 값 |
|---|---:|
| recursive 디코드 바이트 | 149,332 (**24.2 %**) |
| exhaustive 디코드 바이트 | 325,010 (**52.7 %**) |
| recursive 디코드가 0인 페이지 | 67 / 151 |
| 그중 exhaustive도 페이지당 < 512 B인 구간 | `0x02057000..0x02097000` (64페이지, **정확히 256 KiB**) |

**미해독은 자유 공간의 증거가 아니다(not evidence of free space).** M09는
"정적 참조 0건 + 전부 0"이라는 이유로 1,264 B를 데이터 저장에 썼다가 장치를
잃었다. 그 256 KiB 블록 안에는 이미 `0x02058314`의 `Keys Channel-` 문자열과
`0x02058248` 콜백 테이블이 있으므로 **적어도 일부는 stock 데이터**다.

### 3.4 RAM0 와 SDRAM 창

| 범위 | 소유 | 정책 |
|---|---|---|
| `0x01C00000..0x01C099D4` | 초기화 데이터 | stock, 소유자 증명 없이는 자유 아님 |
| `0x01C099D4..0x01C4651C` | BSS/heap 제로 span | 제로화는 소유권이 아님 |
| `0x01C4651C..0x01C7FD50` | stock 상한 위 RAM0 (230 KiB) | **BLOCKED** — 소유/별칭 증명 없음 |
| `0x01C7FD50..0x01C7FD80` | SDK `BOOT_INFO` 슬롯 | **BLOCKED** — SMK에 규약 증거 없음 |
| `0x01C7FD80..0x01C7FE00` | SDK `UPDATA_BEG` 갱신 플래그 | **BLOCKED** |
| `0x04000000..0x04200000` | **SDK SDRAM 창** | **BLOCKED** — 이 장치에서 입증 전까지 사용 금지 |

---

## 4. USB 안전 플래싱 게이트 (요약)

상세 절차·체크리스트·중단 조건은
[`docs/usb-flash-safety-case.md`](../../../../docs/usb-flash-safety-case.md)에 있다.
핵심만 옮기면:

1. **쓰기 경로를 구분하라.** (A) 앱 슬롯만 바꾸는 fwsc OTA와 (B) `isd_download
   -uboot … -app …` 전체 tonorflash 쓰기는 위험이 전혀 다르다. (B)는 부트
   헤더(`0x0..0x4000`)를 덮으므로 **현재 승인 불가**다.
2. **바이너리 게이트를 링크 맵까지 확장하라.** 플래시 전에 `sdk.map`에서
   모든 섹션 VMA가 `0x01c00000..0x01c7FFFF` 또는 `0x02000120..` 안에 있음을
   **기계적으로** 검사한다. `0x04000000`이 한 줄이라도 나오면 중단한다.
3. **복원이 앱 부팅에 의존하지 않게 하라.** 최소한 강제 로더 경로
   (Jieli Forced Upgrade Tool 4.0 / WL82 UBOOT1.00, 1 MiB 덤프 A·B)가 준비되고
   **이번 세션에서 동작 확인**된 뒤에만 쓰기한다.
4. **복구 자산을 먼저 고정하라.** 현재 설치본(§1 기준 S16) fwsc + exact_ota +
   강제 로더 번들 + 사전 1 MiB 덤프 A/B(hash 일치) 없이는 쓰지 않는다.
5. **첫 실험은 관측 가능한 최소 앱으로.** "아무것도 안 하는 복구 전용 앱"은
   실패 시 판별 신호가 USB 하나뿐이었다. 다음 시도는 **관측 가능한 출력**
   (예: USB descriptor identity 변경 또는 LCD 단색)을 가진 최소 앱이어야 한다.

---

## 5. 남은 증거 목록 (Gap register)

| ID | 필요한 증거 | 왜 결정적인가 | 획득 방법(오프라인 우선) |
|---|---|---|---|
| G-01 | 이 보드에 **외부 DRAM 다이가 실장**되어 있는가 | RC-1의 잔여 반증 조건. SiP 옵션은 데이터시트로 이미 배제됨 | **대부분 해소** — SDK 동봉 `AC7911B8_Datasheet_V1.0.pdf` §4가 부품 번호 메모리 코드를 정의(`8` = 8 Mbit Flash, SDRAM/PSRAM은 A/B/C/D). 잔여: FCC 내부 사진·오너 보드 사진에서 DRAM 다이 유무 판독(개방 불필요) |
| G-02 | SMK 부트 체인이 `0x01c7fd50..0x01c7fe00`을 쓰는지 | SDK `BOOT_INFO`/`UPDATA_BEG` 재사용 가능성 | 기존 1 MiB 덤프로는 불가. 런타임 관측 또는 부트 코드 정적 분석 |
| G-03 | v15의 **USB 초기화 시퀀스**와 디스크립터 등록 함수 주소 | SDK 앱이 USB를 띄우려면 필수 | v15 앱에서 USB descriptor 상수 xref 추적(리스트 보유) |
| G-04 | v15의 **클럭/PLL/보드 init** 시퀀스 | RC-3 계열 위험 제거 | `0x02000000..0x020000a4` 이후 부트 코드 정적 추적 |
| G-05 | LCD 최종 write 경로 + 버스(SPI 여부) | P1 LCD 관측 | ui-preflash REQ-06 잔여 + 연속성 측정 |
| G-06 | 물리 입력 producer와 ID | REQ-05 잔여 | watchpoint 런타임 추적 |
| G-07 | **v15 synth voice/allocation 구조체 주소** | UI→Synth 하단 연결 | sdk-signatures 임계값(2개 독립 일치)을 만족하는 추가 대조 |
| G-08 | `0x02057000..0x02097000` 256 KiB의 정체 | 배치/저장 후보 판정 | 문자열·테이블 스캔, Ghidra 데이터 타입 지정 |
| G-09 | `0x00000000..0x00004000` 부트 영역 포맷 | 전체 플래시(B 경로)를 언젠가 승인하려면 필수 | 공식 Jieli uboot 포맷 문서 + 덤프 대조 |

---

## 6. 재현

```sh
cd baselines/v15/analysis/usb-flash-readiness
python3 analyze_coverage.py     # coverage.json 재생성 (app.bin SHA 고정)
python3 validate.py             # 스키마/근거경로/플래시 타일링/수치 일관성
```

RC-1 증거 재현:

```sh
# 플래시된 패키지와 디스크 산출물의 app.bin 동일성
shasum -a 256 linux-build/fw-AC79_AIoT_SDK/cpu/wl82/tools/app.bin
# → 5caaaf32d214e04617ff03e3dd4a40221a578e01be06e4188316bc0568ee8daa
python3 -c "import json;m=json.load(open('baselines/v15/analysis/fwsc-repack-sdk-app/output/sdk-demo-ota/package-manifest.json'));print(m['sdk_app_bin']['sha256'], m['output']['sha256'])"
# → 5caaaf32…  673da1d5…

# 링크 맵이 SDRAM 레이아웃인지
grep -nE "^\.(data|bss)\b" linux-build/fw-AC79_AIoT_SDK/cpu/wl82/tools/sdk.map
# → .data 0x04000000 / .bss 0x040009a0  ← 차단 대상

# 왜 그렇게 링크됐는가
diff <(sed -n '/^DEFINES/,/^$/p' linux-build/fw-AC79_AIoT_SDK/apps/demo/demo_hello/board/wl82/Makefile) \
     <(sed -n '/^DEFINES/,/^$/p' linux-build/fw-AC79_AIoT_SDK/apps/demo/demo_ota/board/wl82/Makefile)
# → 14d13 "< -DCONFIG_NO_SDRAM_ENABLE \"
```

---

## 부록 A. git 이력 조사 결과 (G-01 / G-03 / G-04)

"이미 조사한 적이 있는가"를 이력 전체(191 커밋, 단일 `main`, reset으로 버려진
dangling 객체 포함)에서 확인한 결과다. **세 항목 모두 "질문은 기록됐지만 해소는
없다"**가 결론이며, 예외가 G-01이다(아래).

| 항목 | 이력에 있는 것 | 이력에 없는 것 |
|---|---|---|
| **G-01** SDRAM | `820dd50`(2026-08-02) public-research: SDK 링크 맵이 `sdram` `0x04000120`을 선언, AC79는 "optional 2/8 MiB SDRAM packages", 그리고 **"Public SDK default flash and SDRAM sizes are build configuration, not SMK hardware proof."** · `c593c78` app-extension 감사: `ENTRY=0x2000120` ↔ `CONFIG_SFC_ENABLE`/`CONFIG_NO_SDRAM_ENABLE` · `ab0c02c` pcm-realtime-synth: **"Whether the SMK board has external SDRAM populated is not proven by current product evidence."** · `e446402`/`f11df3c`: 7911B8 = 8-Mbit internal-Flash variant | 부품 번호 메모리 코드 해독. **단, 이는 이 저장소의 git 객체가 아니라 SDK 체크아웃 안에 동봉된 `AC7911B8_Datasheet_V1.0.pdf` §4에 있었다** — 이력이 아니라 디스크에 있던 것을 이번에 읽었다 |
| **G-03** USB 초기화 | `d4149bd`/`820dd50`: 디스크립터 바이트 패턴(device descriptor `0x02057b53`, jack graph, CIN 표) · `evidence.md`: xref 결과 **0건** + "**No address is reported as a USB MIDI receive or dispatch entry point.**" · runtime-trace(2026-08-01): 실기 관측 시도했으나 **장치가 버스에 없어 0건** | v15가 USB를 **활성화하는 코드 경로와 그 주소**. 이력 어디에도 없다 |
| **G-04** 클럭/PLL/보드 init | `c593c78`: "**The recovered raw ISD strings include SPI and clock configuration, but no exact v15 loader bound was recovered** that authorizes appended post-app code." · `0x02000000..0x020000A4`의 데이터 복사/BSS 제로/스택 초기화는 문서화됨 | v15의 **클럭/PLL 초기화 시퀀스 자체**. 부트 영역(`0x0..0x4000`)의 ISD 설정 문자열이 있다는 사실까지만 기록됨 |

참고로 dangling 객체(`efbbc4e` M09 복원 번들, 미사용 `src/ota.c`·`src/usb_probe.c`
blob들)도 확인했으나 G-01/G-03/G-04에 관한 추가 분석은 없다. `usb_init` 매치는
호스트 도구의 libusb 초기화 함수명이다.

## 부록 B. 소거법으로 본 남은 조사 영역 (2026-10-01)

"다음에 어디를 파야 하는가"를, 이미 지운 것과 아직 안 건드린 것으로 나눠 정리한다.
근거는 모두 이 저장소의 산출물이며, 새로 계산한 부분은 그 명령을 함께 적었다.

### B.1 소거된 영역 (더 파도 나오지 않는다)

| 영역 | 왜 지웠나 |
|---|---|
| 앱 내부 writable code cave / listing gap | M09가 장치를 잃었다. 큰 gap 4개(`0x02016a88`, `0x02039be6`, `0x0202bc62`, `0x02007248`)는 전용 감사로 REFUTED |
| S1C hot window `0x0201e13e..0x0201e254` | 여유 2 B |
| 앱 tail 확장 | `cfg_tool.bin` 즉시 시작 + UFW `USR` 충돌 |
| RAM `0x01c4651c` 위 | 소유/별칭 증명 없음(M09와 같은 추론 오류) |
| **SDRAM 창 `0x04000000`** | 데이터시트 메모리 코드로 배제(§2.1) |
| `0x02057000..` 256 KiB | **코드가 아니라 문자열/테이블 데이터**(B.3) |
| "디스크립터 xref 0건"이라는 기존 결론 | **도구 한계였음**(B.3) — 결론을 그대로 믿으면 안 됨 |
| v15 안에서 PLL/클럭 초기화를 찾는 것(G-04 원래 틀) | 부트 스텁이 PLL을 하지 않는다. 클럭은 상류(uboot) 책임 → **질문 자체를 수정**(B.2-3) |

### B.2 살아남은 조사 영역 (우선순위 순)

**1. 저주소 init 영역 `0x020000A4..0x02004870` — 가장 큰 미매핑 코드 덩어리.**
recursive 디코드로 확보된 함수 684개 중 **274개가 `0x02000000..0x02005000`(20 KB)에
몰려 있는데**, 메모리 맵이 이름을 붙인 것은 부트 스텁 `0x02000000..0x020000A4`와
`0x02004870`의 스토리지 래퍼뿐이다. 즉 **약 18 KB, 250여 개 함수가 "디코드됐지만
소유자 미상"** 이다. 부트→main 초기화 체인이 여기 있으므로 **USB/보드 init도 여기
있어야 한다.** 방법: 진입점에서 호출 그래프를 유계 탐색(무작위 gap 스캔이 아니라
결정적 순회). 신규 map row `v2-rx-011`.

**2. 부트 파라미터 블록(r0) 계약 — 새로 발견한 결정적 지점.**
부트 스텁이 `call 0x020000c6`으로 부르는 `FUN_020000c6`는 **진입 시 r0로 넘어온
포인터**에서 `+0x00/+0x04/+0x08/+0x0c/+0x0e/+0x100` 필드를 읽어 `0x01c7fd50`
(SDK `BOOT_INFO`, 48 B)에 복사한다. 즉 **SMK uboot ↔ 앱 사이의 계약 구조체가
r0로 전달된다.** 이 구조체 레이아웃을 복원하는 것은 유계 작업이고, "SDK 앱이 이
부트 체인에서 정상 부팅할 수 있는가"라는 질문에 직접 답한다. map row `v2-rm-004`.

```
02000004  mov sp,#0x1c3a2d4        0200002c  mov r4,#0x1c00000    ; .data 목적지
0200000a  mov ssp,#0x1c3b2d4       02000032  mov r1,#0x208d160    ; .data 원본
02000010  call 0x020000c6   <-- r0 = uboot 파라미터 블록
02000016  mov r3,#0x1c099d4        0200007e  call 0x01c00d6c      ; RAM 상주 코드
0200001e  mov r2,#0x3cb48          02000084  call 0x02060e2c      ; heap init
0200004a  mov r0,#0x4000120        0200008a  call 0x02007424      ; UPDATA_BEG 검사
0200005c  je  r0,r1,0x02000068     02000090  mov r6,#0x20020a0
                                   02000096  goto r6              ; = main
```

부수 확인: `0x4000120`(SDRAM 진입) 경로는 **컴파일되어 있으나 이 빌드에서 불활성**
(복사 크기 r2=0). 플랫폼 자체가 두 레이아웃을 지원하고 이 장치는 SFC 변형이라는
뜻으로, RC-1을 독립적으로 뒷받침한다.

**3. `main = 0x020020A0`의 tick/clock 설정 + SFR 후보 3함수.**
main 부근 코드가 `0xf4240`(1e6), `0x2dc6c00`(48e6) 상수로 나눗셈/곱셈을 한다 →
앱 측 clock/tick 환산 지점이다. 그리고 51,089행 전체를 즉치 스캔했을 때 **코어 SFR을
건드리는 함수는 단 3개**였다: `FUN_020014ee`, `FUN_0200152a`, `FUN_02003ef0`
(모두 `0x1eef100`/`0x1eef300`). clock/컨트롤러 설정 후보는 사실상 이 셋뿐이다.
map row `v2-rx-012`, `v2-rx-014`.

```sh
python3 /tmp/mmio.py    # 즉치 스캔 재현 (recursive listing 51,089행)
```

**4. MMIO/SFR 축 — 아직 거의 안 쓴 새 탐색축.**
지금까지의 모든 탐색은 **데이터 주소**(디스크립터·문자열·RAM) 기준이었다. USB와
클럭 초기화는 **레지스터 코드**이므로 데이터 xref로는 안 잡힌다. 위 스캔에서 SFR
즉치는 7건뿐이었는데, 이는 (a) 디코드 커버리지 24%와 (b) pi32v2가 대부분
"베이스 레지스터 + 오프셋"으로 접근하기 때문이다. **베이스 상수 로드**
(`mov rN,#<base>`)를 축으로 삼는 것이 다음 탐색이며, 메모리 맵의
"MMIO/IOREGIONS: BLOCKED — 근거 있는 MMIO 범위 없음" 상태를 처음으로 깰 수 있다.
주의: pi32v2 즉치는 시프트되어 저장될 수 있어 단순 스캔은 오식별 위험이 있다.

**5. 디코드 프런티어 68페이지 + 공식 툴체인의 선형 스윕.**
recursive 디코드가 0보다 크고 70% 미만인 페이지가 68개다(연속 구간은
`0x02001000..0x02003000`, `0x02004000..0x0200a000`, `0x02013000..0x0201e000`,
`0x02031000..0x02048000` 등). 여기가 "도구가 중간에 멈춘" 곳이다. 가장 값싼
확장은 **공식 pi32v2 툴체인의 objdump로 선형 스윕**하는 것 — Ghidra SLEIGH의
휴리스틱 재귀 디코드보다 훨씬 촘촘하다(`symbol_tbl.txt` 생성에 이미 사용 중).
같은 방법으로 B.1의 "330개 데이터 영역 포인터 후보"가 즉치인지 실제 테이블인지도
판별된다.

**6. 데이터 블롭 내부의 포인터 테이블.**
디스크립터 베이스로 가는 32비트 포인터는 이미지 전체에 0건이지만, 블롭 안에는
코드 포인터 테이블이 있다(`0x0205785b` → `0x02040d6e/72/80`, `0x02057f04` →
`0x0202c348`). 디스크립터 선택이 테이블 구동이라면 이 구조가 실마리다.

**7. G-01 잔여**: 외부 DRAM 다이 실장 여부(FCC/오너 사진 판독). 이제 거의 무의미.

### B.3 이번에 확정·수정된 것

| 항목 | 이전 | 지금 |
|---|---|---|
| 부트 체인 | `0x02000000..0x020000A4`만 알려짐 | 전 구간 해독 + `main=0x020020A0` 확정 |
| `0x01c7fd50` (BOOT_INFO) | "SDK 전용, SMK가 안 쓸 수 있음" | **stock 앱이 직접 채운다** (`FUN_020000c6`) → 공유 규약. G-02 대부분 해소 |
| `0x01c7fd80` (UPDATA_BEG) | "SDK 전용" | **stock 부트가 검사**(`FUN_02007424`) → 공유 규약 |
| SDRAM 창 | "미입증" | 데이터시트로 배제 + 부트 코드의 SDRAM 경로가 **불활성**임을 확인 |
| 디스크립터 xref | "0건" | **도구 한계였음**. 단, 강한 리스팅으로 다시 찾은 12개 함수도 **문자열 참조**였고 디스크립터 베이스 참조는 여전히 0건 |
| 256 KiB 블롭 | "내용 미상" | 문자열/테이블 데이터로 분류(오디오 확장자, `app_area_head`, UI 문자열, 코드 포인터 테이블) |

## 7. 명시적 비주장 (non-claims)

- 이 문서는 **어떤 플래시도 승인하지 않는다.**
- 실기기에 접속하지 않았고, 어떤 쓰기·OTA·리셋·덤프도 수행하지 않았다
  (**Offline only**).
- RC-1은 **강한 추론**이다. SDK 동봉 AC7911B8 데이터시트(§4 메모리 코드)로
  "이 부품이 SDRAM/PSRAM 멤버가 아니다"까지 확정됐고, 잔여는 외부 DRAM 다이
  실장 여부(G-01)뿐이다. 그 확인 전까지 RC-1을 확정으로 승격하지 않는다.
- 미해독 구간을 자유 공간으로 승격하지 않는다. 미해독은 자유 공간의 증거가
  아니다(not evidence of free space).
- 기존 [`../memory-map/memory-map.json`](../memory-map/memory-map.json)을
  대체하지 않는다. v2는 그 위에 물리 상한·SDK 레이아웃·커버리지를 **추가**한다.
- 세션 DB(`.freebuff/desktop-v2.db`)에서 복원한 항목은 저장소 근거가 아니며,
  맵의 `source_artifacts`로 등록하지 않았다.
