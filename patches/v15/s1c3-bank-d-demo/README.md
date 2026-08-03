# SMK-37 Pro v15 S1-C3 16-Pad SysEx set

이 디렉터리는 라이브 검증에 성공한 16개 패치를 외부 DX7 패치 에디터에서 읽을 수 있는 개별 `.syx` 파일로 내보낸 것입니다.

## 중요 형식 차이

- 외부 에디터 파일: 163바이트 Yamaha DX7 single-voice SysEx
  - `F0 43 0n 00 01 1B`
  - 155바이트 voice data
  - Yamaha 7-bit checksum
  - `F7`
- S1-C3 장치 전송 패킷: 동일한 163바이트 구조지만 checksum 위치의 바이트를 SMK 런타임 플래그 `0x3F`로 바꿉니다.

따라서 `.bin` 파일의 확장자만 `.syx`로 바꾼 것이 아닙니다. 이 디렉터리의 파일은 표준 Yamaha checksum으로 다시 생성되었으며, sender가 전송 직전에 안전하게 `0x3F`로 변환합니다.

## 현재 Pad별 파일

| Physical Pad | MIDI note | Patch |
|---:|---:|---|
| 1 | 40 | BASS SLAP |
| 2 | 41 | BEAMER 2 |
| 3 | 42 | Onglon |
| 4 | 43 | SOFTSTEEL |
| 5 | 48 | HAND CLAP1 |
| 6 | 49 | Mooger #1 |
| 7 | 50 | Moog Solo2 |
| 8 | 51 | Mooger Low |
| 9 | 36 | BUZZ BASS |
| 10 | 37 | Bang ????? |
| 11 | 38 | BASSE BIEN |
| 12 | 39 | BASS-THING |
| 13 | 44 | BASS-ROADS |
| 14 | 45 | E.ORGAN 1 |
| 15 | 46 | YEAAAHH |
| 16 | 47 | HAND DRUM |

## 외부 에디터 패치로 교체

1. 에디터에서 **DX7 single voice, 163-byte `.syx`** 형식으로 저장합니다.
2. 교체할 Pad의 기존 `padNN-*.syx` 파일을 다른 곳에 백업하거나 디렉터리 밖으로 이동합니다.
3. 새 파일 이름을 `padNN-설명.syx`로 바꿉니다. 예: Pad 2는 `pad02-MyBass.syx`.
4. 각 Pad 번호마다 정확히 파일 하나만 있어야 합니다.
5. 전체 세트를 검증합니다.

```bash
python3 tools/smk37_v15_s1c3_syx.py validate-set patches/v15/s1c3-bank-d-demo
```

파일 하나만 검사할 수도 있습니다.

```bash
python3 tools/smk37_v15_s1c3_syx.py inspect path/to/patch.syx
```

## Sender 빌드

macOS와 Homebrew `libusb` 기준:

```bash
LIBUSB_PREFIX="$(brew --prefix libusb)"
cc -std=c11 -Wall -Wextra -Werror -O2 \
  -DS1C3_ENABLE_LIVE_USB \
  -I"$LIBUSB_PREFIX/include/libusb-1.0" \
  tools/smk37_v15_s1c3_syx_send.c \
  -L"$LIBUSB_PREFIX/lib" -lusb-1.0 \
  -o build/smk37-v15-s1c3-syx-send
```

## Dry-run

장치에 보내기 전에 16개 파일, Yamaha checksum, 물리 Pad 매핑, MIDI note 전송 순서를 검사합니다.

```bash
build/smk37-v15-s1c3-syx-send dry-run patches/v15/s1c3-bank-d-demo
```

## 장치로 전송

현재 S1-C3 펌웨어는 **16개를 하나의 휘발성 세트로 순서대로 적재**합니다. 개별 파일 하나만 단독 전송하는 방식이 아닙니다. 한 Pad만 바꾸더라도 나머지 15개 파일과 함께 전체 세트를 전송해야 합니다.

MidiSuite 등 MIDI 장치를 점유하는 앱을 닫은 뒤:

```bash
killall MIDIServer || true
build/smk37-v15-s1c3-syx-send send patches/v15/s1c3-bank-d-demo \
  --confirm SEND-SMK37PRO-V15-S1C3-EDITOR-SYX-SET
```

- 전송 순서는 내부 슬롯 규칙에 맞춰 MIDI note `36..51`입니다.
- sender가 물리 Pad 파일 순서를 자동 변환합니다.
- 패킷 사이에 100ms 간격을 둡니다.
- RAM 기반이므로 장치를 재부팅하면 다시 16개를 전송해야 합니다.
- 이 sender는 S1-C3 r3-reload 펌웨어가 설치된 장치용입니다.

## 재생성 및 왕복 확인

현재 검증 세트를 `.syx`로 다시 생성:

```bash
python3 tools/smk37_v15_s1c3_syx.py export-current
```

에디터 파일을 SMK 런타임 패킷으로 변환만 하기:

```bash
python3 tools/smk37_v15_s1c3_syx.py prepare-runtime \
  patches/v15/s1c3-bank-d-demo build/my-runtime-packets
```

`manifest.json`에는 Pad, MIDI note, 패치 이름, editor checksum, editor/runtime SHA-256가 기록되어 있습니다.
