# AC791N SDK — Windows 도구 vs Linux 경로 & 플래시 절차

작성: 2026-08-14 · 갱신: 2026-10-08 (no-SDRAM/SFC 재빌드 재현 경로 §3 추가) · 상태: 빌드 완료 · 플래시는 USB 접근 확보 대기

Jieli AC79 SDK가 동봉하는 도구는 **Windows(CodeBlocks) 공식 환경** 기준이라 `.bat`/`.exe`가
기본입니다. SDK Makefile은 Linux 경로(`/opt/jieli/pi32v2/bin`, `download.sh`)를 이미
전제하지만 **download.sh는 동봉되지 않아** 이 프로젝트가 재구성했습니다
(`linux-build/download.sh` → SDK `cpu/wl82/tools/download.sh`).

## 1. 도구 대조표

### 1.1 플래시 · 패키징 (핵심)

| 용도 | Windows (SDK 동봉) | Linux (linux-postbuild) | 비고 |
|---|---|---|---|
| USB 플래시 | `isd_download.exe` | `isd_download` (정적 x86-64) | tonorflash 프로토콜. **플래시 세션의 부산물로 `jl_isd.fw` 생성** |
| FW에 script.ver 추가 | `fw_add.exe` | `fw_add` (정적) | `-fw jl_isd.fw -add script.ver -out jl_isd.fw` |
| upgrade 파일 생성 | `ufw_maker.exe` | `ufw_maker` (정적) | `-fw_to_ufw jl_isd.fw` → `jl_isd.ufw` → `update.ufw` |
| 리소스 패킹 | `packres` (dir) | `packres`, `json_to_res`, `fat_comm` | audlogo/cfg 등 리소스 폴더 처리 |
| 크래시 주소 역추적 | `llvm-symbolizer.exe` | **없음** → `objdump -t sdk.elf` 대체 | `定位异常地址.bat` 대응 |

Linux post-build 도구는 **정적 바이너리**라 qemu-user에서 `-L` sysroot 없이 바로 실행됩니다
(단, `remove_tailing_zeros`만 동적 링크라 `-L /root/amd64-rootfs` 필요).

### 1.2 Windows 전용 (Linux 대응 없음)

| 도구 | 역할 | Linux 대체 |
|---|---|---|
| `AC791N_config_tool` | 칩 설정 도구 | 미확인 — 필요 시 VM에서 |
| `SM01-DFU.exe` | DFU(공장 플래시) 도구 | tonorflash 경로로 불필요할 가능성 높음 |
| `jtag/` | JTAG 디버그 도구 | UTM VM + USB-JTAG 시에만 |
| `llvm-symbolizer.exe` | 크래시 콜스택 | `objdump` 대체 |

### 1.3 공통 입력 파일 (플래시에 사용)

`cpu/wl82/tools/` 아래, 플랫폼 공용:

- `uboot.boot` — 부트로더 (플래시 `-uboot` 인자)
- `cfg_tool.bin` — 설정 영역 이미지
- `audlogo/`, `cfg/` — 리소스 (`-res` 인자)
- `isd_config.ini` — 칩/플래시/다운로드 설정 (CHIP_NAME=AC791N, FLASH_SIZE=4M,
  DOWNLOAD_MODEL=usb, ENTRY=0x2000120)
- `script.ver` — 버전 정보 (fw_add로 주입)
- `wl82loader.bin` / `usb_update2.bin` / `sd_update2.bin` / `ota.bin` — 부팅/업데이트 펌웨어

## 2. 플래시 절차 (linux-build 환경)

전체 흐름: **빌드 → post-build(app.bin) → isd_download 플래시 → OTA 패키징**

### 2.1 빌드 + post-build (현재 완료됨)

```bash
container exec smk-build bash -c \
  'ulimit -n 8192; cd /root/fw-AC79_AIoT_SDK && make ac791n_demo_demo_hello'
```

2026-08-14 빌드 컨테이너는 사라졌습니다. 현재 경로는 §3 (Rosetta amd64 컨테이너)이며,
같은 Makefile이 그대로 no-SDRAM/SFC 레이아웃을 만듭니다.

- Makefile `all` → `pre_build`(sdk_used_list/ld 생성) → 컴파일(-flto) → `lto-wrapper` 링크
  → `+POST-BUILD` → `download.sh sdk`
- `download.sh`: objcopy로 `.text/.data/.ram0_data/.cache_ram_data` 추출 → `app.bin` 결합
  + `symbol_tbl.txt`. **플래시 단계는 스킵** (장치 세션에서 별도 실행)
- 산출물: `cpu/wl82/tools/app.bin`(119,748B — demo_hello), `sdk.elf`(1MB)

### 2.2 플래시 — isd_download tonorflash (장치 필요)

download.bat의 플래시 라인을 그대로 Linux 도구로:

```bash
cd /build/fw-AC79_AIoT_SDK/cpu/wl82/tools
qemu-amd64-static /opt/jieli/jieli-linux-post-build-tools-20260728.1/isd_download \
  isd_config.ini -tonorflash -dev wl82 -boot 0x1c02000 -div1 -wait 300 \
  -uboot uboot.boot -app app.bin cfg_tool.bin -res audlogo cfg \
  -reboot 500 -update_files normal
```

- `-update_files normal` → `db_update_files_data.bin` 생성 (OTA 패키징 입력)
- 성공 시 부산물 `jl_isd.fw` 생성
- **현재 블로커**: Apple container에 USB 패스스루 없음 (`/dev/bus/usb` 부재).
  → USB가 있는 Linux VM(UTM/QEMU)에서 실행하거나, tonorflash 프로토콜을 호스트
  C 센더로 재구현 (exact_ota 기반 + 프로토콜 캡처)
- 장치 업데이트 모드 VID/PID `4d4a:4155` — 0x4D4A는 Jieli VID라 표준 tonorflash
  프로토콜일 가능성 높음 (P0b 판정 대상)

### 2.3 OTA / SD 업그레이드 패키징

플래시 후(또는 jl_isd.fw 존재 시):

```bash
PB=/opt/jieli/jieli-linux-post-build-tools-20260728.1
cd /build/fw-AC79_AIoT_SDK/cpu/wl82/tools
qemu-amd64-static $PB/fw_add -noenc -fw jl_isd.fw -add script.ver -out jl_isd.fw
qemu-amd64-static $PB/ufw_maker -fw_to_ufw jl_isd.fw
cp jl_isd.ufw update.ufw          # SD/U디스크 루트에 복사 → SD 업그레이드 (升级文件.bat 대응)
cp db_update_files_data.bin update-ota.ufw   # OTA (升级文件-OTA.bat 대응)
```

download.sh는 jl_isd.fw가 있으면 이 패키징을 자동 수행합니다.

### 2.4 기타 Windows 스크립트 대응

| .bat | 용도 | linux-build 대응 |
|---|---|---|
| `升级文件.bat` | SD 업그레이드 파일 생성 | §2.3 update.ufw |
| `升级文件-OTA.bat` | OTA 파일 생성 | §2.3 update-ota.ufw |
| `write_file_to_flash.bat` | 임의 파일을 플래시 주소에 기록 | isd_download `-todisk` 동일 인자 |
| `定位异常地址.bat` | 크래시 주소 콜스택 | `objdump -t sdk.elf` + sdk.map |

## 3. 재현 — Rosetta amd64 컨테이너 빌드 (2026-10-08 검증)

Apple Silicon 호스트에서 x86-64 Linux 툴체인을 그대로 돌리는 경로입니다. 계획서 §7의
qemu-user + LD_PRELOAD 셤은 **불필요**합니다: `--arch amd64` 컨테이너는 Rosetta 2로 실행되고
툴체인 바이너리를 수정 없이 돌립니다.

**이 절의 모든 명령은 저장소 루트(CWD = `$REPO`, 아래 블록에서 정의)에서 실행합니다.**
아래 bash 블록을 그대로 붙여 실행하면 `$OUT` 에 산출물이 생기고 8) 이
`LAYOUT GATE: PASS` 를 출력합니다. 두 개의 뿌리를 섞지 않도록 주의하세요: `linux-build/` 는
저장소 안에 없고(`$WORK` 아래에만 있음), 게이트는 저장소 안에만 있습니다.

```bash
# --- 경로 정의 (CWD = $REPO; 이 블록 이후 모든 명령도 CWD = $REPO) ---
REPO=/Users/spectrum/Documents/smk37pro-acidsound-mod   # 이 문서가 있는 저장소 루트
WORK=$HOME/Documents/SMK37ProMod                        # 개인 빌드 워크스페이스 (저장소 아님)
OUT=$WORK/linux-build/ac79-build-2026-10-08             # 산출물 스테이징 (known_builds[1] 의 그 경로)
C=smk-build                                             # 컨테이너 이름 (새 환경이면 새 이름으로)
cd "$REPO"

# 1) 컨테이너. --rosetta 플래그는 걸리므로 쓰지 않습니다.
#    이미 있고 running 이면 재사용합니다 (delete/start 는 멈추므로 쓰지 않음).
if container list | awk 'NR>1{print $1}' | grep -qx "$C"; then
  echo "reusing container $C"
else
  container run -d --name "$C" --arch amd64 ubuntu:24.04 sleep infinity
fi
container exec "$C" bash -c 'uname -m'                 # -> x86_64
#    STATE 가 running 이 아니면 재사용하지 말고 $C 를 새 이름으로 바꾸세요.

# 2) 패키지 — python3 필수 (lto-wrapper 가 '#!/usr/bin/env python3' 스크립트)
container exec "$C" bash -c 'apt-get update -qq && apt-get install -y -qq \
  git curl make xz-utils file bc bzip2 ca-certificates python3'

# 3) SDK — depth-1 + sparse (약 459 MB). 이미 있으면 clone 을 건너뜁니다.
container exec "$C" bash -c '[ -d /root/fw-AC79_AIoT_SDK/.git ] || git clone --depth 1 \
  --branch release/AC79NN_SDK_V1.0.3 --filter=blob:none --sparse \
  https://github.com/jeffreywugz/fw-AC79_AIoT_SDK.git /root/fw-AC79_AIoT_SDK'
container exec "$C" bash -c 'cd /root/fw-AC79_AIoT_SDK && \
  git sparse-checkout set apps cpu lib include_lib tools && git checkout'

# 4) 툴체인 + post-build (XZ). 툴체인 해시는 고정 — 다르면 즉시 중단합니다.
TC_SHA=f686586bcfb45e0f0bb27fd2b39c7a7f313cb4f0e88a66a14da621ffa8225958
PB_SHA=6949d48c4cd82e274d7943d4ca67f214593fdb4f699ef9f51c2ecc78125ab739   # 2026-10-08 관측값
container exec "$C" bash -c "cd /root && { [ -f linux-toolchain.bin ] && \
  echo '$TC_SHA  linux-toolchain.bin' | sha256sum -c --status; } || \
  curl -fL --retry 2 --max-time 1800 -o linux-toolchain.bin \
  https://pkgman.jieliapp.com/s/linux-toolchain"
container exec "$C" bash -c "cd /root && { [ -f linux-postbuild.bin ] && \
  echo '$PB_SHA  linux-postbuild.bin' | sha256sum -c --status; } || \
  curl -fL --retry 2 --max-time 1800 -o linux-postbuild.bin \
  https://pkgman.jieliapp.com/s/linux-postbuild"
container exec "$C" bash -c "cd /root && echo '$TC_SHA  linux-toolchain.bin' | sha256sum -c" \
  || { echo '툴체인 해시 불일치 — 중단합니다'; exit 1; }
container exec "$C" bash -c "cd /root && echo '$PB_SHA  linux-postbuild.bin' | sha256sum -c" \
  || echo '주의: pkgman 의 post-build 는 롤링 빌드입니다 (2026-07-28 f4a45873… / 2026-10-08 6949d48c… 관측). 이 빌드는 post-build 에 의존하지 않으므로 계속 진행해도 됩니다.'
container exec "$C" bash -c 'mkdir -p /opt/jieli && \
  tar -xJf /root/linux-toolchain.bin -C /opt/jieli && \
  tar -xJf /root/linux-postbuild.bin -C /opt/jieli && \
  TC_DIR=$(ls -d /opt/jieli/jieli-linux-toolchains-* | head -1) && \
  ln -sfn "$TC_DIR/pi32v2" /opt/jieli/pi32v2 && \
  ls -d /opt/jieli/pi32v2/bin/clang /opt/jieli/pi32v2/lib/r3/libc.a'

# 5) download.sh 배치 (SDK 미동봉 — 이 저장소가 재구성한 파일). 절대경로로 지정.
container exec -i "$C" bash -c 'cat > /root/fw-AC79_AIoT_SDK/cpu/wl82/tools/download.sh && \
  chmod +x /root/fw-AC79_AIoT_SDK/cpu/wl82/tools/download.sh' < "$WORK/linux-build/download.sh"

# 6) 빌드 (SFC/no-SDRAM: Makefile 에 -DCONFIG_NO_SDRAM_ENABLE 이미 존재) — fail-closed.
#    컨테이너의 산출물 4종을 먼저 지워서, 게이트가 "방금 빌드한" 것만 볼 수 있게 강제합니다.
#    make 가 실패하거나 크기를 보고하지 않으면 게이트를 실행하지 않고 즉시 중단합니다.
#    (2026-10-09 이전에는 make 실패를 무시한 채 예전 산출물을 회수해 PASS 를 출력했습니다.)
container exec "$C" bash -c \
  'rm -f /root/fw-AC79_AIoT_SDK/cpu/wl82/tools/{sdk.elf,sdk.map,app.bin,symbol_tbl.txt}'
BUILD_LOG=$(mktemp)
if ! container exec "$C" bash -c \
     'ulimit -n 8192; cd /root/fw-AC79_AIoT_SDK && make ac791n_demo_demo_hello' \
     > "$BUILD_LOG" 2>&1; then
  cat "$BUILD_LOG"
  echo 'BUILD FAILED — refusing to gate a build that did not succeed'; exit 1
fi
cat "$BUILD_LOG"
BUILT_SIZE=$(sed -n 's/^+app.bin: \([0-9][0-9]*\) bytes$/\1/p' "$BUILD_LOG" | tail -1)
if [ -z "$BUILT_SIZE" ]; then
  echo "빌드가 '+app.bin: N bytes' 를 보고하지 않았습니다 — 방금 만든 산출물인지 확인할 수 없어 중단합니다"; exit 1
fi

# 7) 산출물 회수 — container cp / bind mount 는 런타임 VM 을 멈추므로 금지.
#    stdin/stdout 스트리밍을 쓰면 양방향 바이트 동일이 확인됩니다.
#    주의: sdk.ld 만 tools/ 가 아니라 cpu/wl82/ 에 있습니다.
#    회수 직후 신원을 확인합니다: 빌드가 보고한 크기 + 컨테이너/호스트 해시 일치.
mkdir -p "$OUT"
for f in sdk.elf sdk.map app.bin symbol_tbl.txt; do
  container exec "$C" bash -c "cat /root/fw-AC79_AIoT_SDK/cpu/wl82/tools/$f" > "$OUT/$f" \
    || { echo "회수 실패: $f"; exit 1; }
done
container exec "$C" bash -c 'cat /root/fw-AC79_AIoT_SDK/cpu/wl82/sdk.ld' > "$OUT/sdk.ld"
HOST_SIZE=$(wc -c < "$OUT/app.bin" | tr -d ' ')
if [ "$HOST_SIZE" != "$BUILT_SIZE" ]; then
  echo "산출물 불일치: 빌드가 보고한 ${BUILT_SIZE} B vs 회수한 ${HOST_SIZE} B — 중단합니다"; exit 1
fi
CONTAINER_SHA=$(container exec "$C" bash -c \
  'sha256sum /root/fw-AC79_AIoT_SDK/cpu/wl82/tools/app.bin' | cut -d' ' -f1)
HOST_SHA=$(shasum -a 256 "$OUT/app.bin" | cut -d' ' -f1)
if [ -z "$CONTAINER_SHA" ] || [ "$CONTAINER_SHA" != "$HOST_SHA" ]; then
  echo "산출물 불일치: 컨테이너 ${CONTAINER_SHA:-?} vs 호스트 ${HOST_SHA} — 중단합니다"; exit 1
fi

# 8) P4 레이아웃 게이트 — 저장소의 게이트만 사용합니다.
#    ($WORK/tools/check_sdk_app_layout.py 사본은 237줄 구버전이라 쓰지 않습니다:
#     ELF 입력에서 'no allocatable sections parsed from the map file' 로 끝납니다.)
#    게이트 실패도 블록 실패로 전파합니다 (통과하지 않았는데 PASS 를 보고하지 않도록).
python3 "$REPO/tools/check_sdk_app_layout.py" "$OUT/sdk.elf" --app "$OUT/app.bin" \
  || { echo 'LAYOUT GATE FAILED (sdk.elf) — 플래시 후보로 쓰지 마세요'; exit 1; }   # -> LAYOUT GATE: PASS
python3 "$REPO/tools/check_sdk_app_layout.py" "$OUT/sdk.map" --app "$OUT/app.bin" \
  || { echo 'LAYOUT GATE FAILED (sdk.map) — 플래시 후보로 쓰지 마세요'; exit 1; }   # -> LAYOUT GATE: PASS
shasum -a 256 "$OUT/app.bin" "$OUT/sdk.elf" "$OUT/sdk.map"   # 크기/레이아웃 대조용 — 해시는 빌드마다 다를 수 있음 (§3.1)
echo "BUILD+GATE OK: $OUT/app.bin is the ${BUILT_SIZE} B artifact this run just built"
```

이 블록은 **fail-closed** 입니다 (2026-10-09 보강). 세 가지를 강제합니다: (a) `make` 의 종료
상태가 0 이 아니면 즉시 중단, (b) 빌드가 보고한 `+app.bin: N bytes` 와 회수한 파일 크기, 그리고
컨테이너·호스트 해시가 모두 일치할 때만 진행, (c) 게이트 실패도 블록 실패로 전파. 산출물 4종을
빌드 전에 지우기 때문에 "예전 산출물을 게이트에 통과시키는" 경로가 사라집니다 — 2026-10-09 에
그 경로가 실제로 발생했습니다(빌드 실패 + 스테일 산출물 회수 → `LAYOUT GATE: PASS`, 종료코드 0).
빌드가 실패하면 컨테이너에 `app.bin` 이 없는 상태로 남습니다: 의도된 결과이고, 다음 성공 빌드가
다시 만듭니다.

산출물 기록 (2026-10-08, 대상 맵 `ac79/target/smk37pro-ac7911b8.json` `known_builds[1]`).
**이 해시는 빌드 1회의 지문이고 결정적 재현값이 아닙니다** — 근거는 §3.1:

| 파일 | 크기 | sha256 |
|---|---|---|
| `app.bin` | 119,748 | `c7463a0e04711b53933054e00c2b8b4bbdfb12a729fa813ad227a68de3ff8fe4` |
| `sdk.elf` | 1,024,408 | `5525df2a42f47afc9084aa717137f3057db36310c3007ab8142605d5b32bfd4c` |
| `sdk.map` | 64,868 | `c0da41defc13e23c1d65e9a0bbf2d0916eb68d876d3ba10892843245b4f1eedd` |

재현성 범위 (실측): 같은 절차를 **새 컨테이너**에서 다시 돌리면 크기(119,748 B)·섹션
레이아웃·`sdk.map` 해시는 그대로지만 `app.bin`·`sdk.elf` 해시는 달라집니다. 두 빌드를
바이트 비교한 결과 119,748 B 중 **10바이트**만 달랐고, 그 바이트들은 소스에 박히는 빌드 시각
문자열이었습니다 (`14:39:55` → `15:01:03`, `14:39:59` → `15:01:07`; .text 안 0x12707…0x1271F).
즉 이 빌드는 **레이아웃·크기는 재현되지만 바이트는 재현되지 않습니다** — 게이트가 검사하는
것도 레이아웃과 크기입니다. "같은 해시" 를 재현 조건으로 삼지 마세요.

확인점:

- `.text` 0x02000120 + 0x14EC0, `.ram0_data` 0x01C00000 + 0x84F4, `.ram0_bss`
  0x01C084F4 + 0x3CB0, `.boot_info` 0x01C7FD50 + 0x28, `.cache_ram_data`
  0x01F28000 + 0x10 — 모두 허용 창 안입니다.
- `.data` / `.bss` 는 이 레이아웃에서 **크기 0** 이지만 섹션 헤더는 0x04000000 에
  남습니다. 바이트를 담지 않으므로 게이트가 무시하고, app.bin 에도 기여하지 않습니다
  (85,696 + 0 + 34,036 + 16 = 119,748 — 정확히 일치).
- 2026-08-15 브릭 빌드는 같은 게이트에서 REFUSE 입니다 (`.data` 0x04000000+0x988,
  `.bss` 0x040009A0+0x2BB0).
- 빌드 실패 시 가장 흔한 지점은 링크 단계의 `python3` 부재입니다: 소스 17개는 모두
  컴파일된 뒤 `/usr/bin/env: 'python3': No such file or directory` (Error 127).

### 3.1 재실행과 검증 상태

위 bash 블록은 그대로 다시 실행해도 됩니다(재실행 경로): 컨테이너는 재사용되고,
clone·다운로드·추출은 건너뛰고, 게이트는 다시 돌아 PASS 를 출력합니다. 완전히 새 환경이
필요하면 `$C` 만 새 이름으로 바꾸면 됩니다. `container delete` / `container start` 는 런타임이
멈추므로 기존 컨테이너를 지우거나 다시 시작하려 하지 마세요.

주의: `$WORK/linux-build/download.sh` 안의 `PB=/opt/jieli/jieli-linux-post-build-tools-20260728.1`
은 호스트 사본 기준 값이라 컨테이너의 추출 디렉터리명과 다를 수 있습니다. 그 변수는
`jl_isd.fw` 가 있을 때만 쓰이는 분기(이 절차에서는 진입하지 않음)에만 등장합니다.

검증 상태 — 실행한 것만 적습니다 (2026-10-08). 두 경우 모두 §3 bash 블록을 **문서에서 그대로
추출해** `bash` 로 실행했습니다(손으로 옮겨 적지 않음).

| 경로 | 실행 | 결과 |
|---|---|---|
| 재실행 (기존 컨테이너 재사용) | 예 | 1) `reusing container smk-build` → 2)–4) 기존 자원 재사용(`sha256sum -c`: 툴체인·post-build `OK`) → 6) post-build 재실행(`+app.bin: 119748 bytes`) → 7) 회수 → 8) `LAYOUT GATE: PASS` ×2, 종료코드 0, 해시 3종이 위 표와 일치 |
| 클린 스테이트 (새 컨테이너) | 예 | `$C` 만 `smk-build-verify` 로 바꿔 같은 블록 실행: 생성 → apt → clone/다운로드/추출 → 빌드(`+app.bin: 119748 bytes`) → 8) `LAYOUT GATE: PASS` ×2, 종료코드 0. 해시는 `app.bin 2c9f9911…` / `sdk.elf 3d556652…` / `sdk.map c0da41de…` — 크기·레이아웃·map 동일, 앞의 두 개만 시각 문자열 때문에 다름 |
| 부작용 | — | 클린 실행은 `$OUT` 을 덮어씁니다. 이 저장소의 산출물은 **기록된 빌드로 되돌려** 두었습니다(위 표 해시와 일치, 게이트 재확인 PASS). `container delete` 가 멈추므로 검증용 컨테이너 `smk-build-verify` 는 남아 있습니다 |

### 3.2 프로젝트 소스 증분 — `sdk-2026-10-09-ota-transport` (2026-10-09 검증)

§3 은 stock `demo_hello` 만 빌드합니다. 이 절은 **저장소 자체 소스**를 같은 컨테이너의 SDK 앱에
넣어 빌드하는 첫 증분입니다 (`docs/self-recovering-sdk-app.md` §4 의 패킷/전송 계층; 기록은
`ac79/target/smk37pro-ac7911b8.json` 의 `known_builds` 항목).

무엇을 넣나 — `ac79/app/smk_ota_transport.{h,c}`: 호스트 참조 `src/protocol.c` 의 디바이스측
미러(15 B 요청 인코더 + 응답 패킷 디코더 + 7비트 프레이밍과 USB 4바이트 패킷화). `app_main()` 이
부팅 시 `smk_ota_transport_self_test()` 를 한 번 호출해 결과를 static volatile 에 담고
`smk_ota_transport_self_test: PASS|FAIL` 을 콘솔에 출력합니다.

넣지 않는 것 — USB 열거·디스크립터(B1), MIDI 엔드포인트 I/O(B2), 세션·플래시 정책(B3),
fwsc 패킹(B4). 플래시 접근도 USB 접근도 없습니다. 오프라인 산출물이며 **하드웨어 실행은
미검증**입니다(부팅 자기검사 결과를 장치에서 본 적이 없음).

재현 (호스트, 저장소 루트, 컨테이너는 §3 의 것을 재사용):

```bash
bash ac79/build/build_sdk_app_project_source.sh
# 기본 출력 $REPO/build/ac79-project-source
# 기록된 산출물: ~/Documents/SMK37ProMod/linux-build/ac79-build-2026-10-09-ota-transport
```

스크립트는 컨테이너 안 SDK 앱 트리를 `git checkout` 으로 stock 으로 되돌린 뒤 패치하고, 빌드 후
**다시 stock 으로 복원**합니다 — 따라서 §3 재실행은 여전히 stock 119,748 B 를 만듭니다. 소스 두
개의 SHA-256 을 고정해 두고 달라지면 빌드를 거부합니다(`SMK_ALLOW_SOURCE_CHANGE=1` 로 해제).

검증 상태 — 실행한 것만 적습니다 (2026-10-09, 컨테이너 `smk-build`):

| 항목 | 결과 |
|---|---|
| 빌드 | `+app.bin: 120868 bytes` (stock 119,748 + 1,120 B = 프로젝트 TU 와 호출부) |
| 레이아웃 | `.text 0x02000120+0x15320`(86,816 B), `.data`/`.bss` `0x04000000` = 0 B, `.ram0_bss` +4 B |
| 게이트 | `LAYOUT GATE: PASS` ×2 (`sdk.elf`, `sdk.map`), 종료코드 0 |
| 프로젝트 기원 증거 | `symbol_tbl.txt`: `smk_ota_transport_self_test`(0x0200285C, 0x2FA)·`smk_ota_parse_response`·`smk_ota_selftest_result`(`.ram0_bss` 0x01C08A68); `app.bin` 에 자체 테스트 벡터 2종 각 1회, stock `app.bin` 에는 0회 |
| 차분 테스트 | `make test-ota-transport` → `HOST COMPAT: PASS` (23,657 비교/0 실패; 트랜스크립트 지정 시 24,947/0, 실제 요청 1,290개 재생) |
| 재현성 | 2회 빌드 크기·레이아웃·`sdk.map` 해시 동일, `app.bin` 은 `__TIME__` 3바이트만 다름 |
| 해시 | `app.bin ef26db6b…` / `sdk.elf 04f02eb0…` / `sdk.map 01962e29…` / `symbol_tbl.txt 9f7d3864…` |
| 부작용 | 없음 — SDK 앱 트리는 stock 으로 복원(`git status` clean), 장치 접촉·플래시 없음 |

| fail-closed 검증 (2026-10-09) | 예 | 앱 소스 1개를 rename 해 `make` 를 강제 실패시킴 → `BUILD FAILED — refusing to gate a build that did not succeed`, `LAYOUT GATE` **미출력**, 종료코드 1. 신원 검사에 어긋나는 artifact(빌드 보고 크기/해시 불일치) → `산출물 불일치 ...`, 종료코드 1. 정상 경로 → `BUILD+GATE OK: ... is the 119748 B artifact this run just built` + `LAYOUT GATE: PASS` ×2, 종료코드 0. 검증 후 컨테이너 SDK 트리는 stock, `known_builds` 스테이징은 원래 해시 그대로 |

### 3.3 B1 증분 — `sdk-2026-10-09-b1-usb-descriptors` (2026-10-09 검증)

§3.2 위에 `docs/self-recovering-sdk-app.md` §4 의 **B1**(업데이터 신원 `4d4a:4155` 의 USB
디스크립터)을 올린 빌드입니다. 같은 스크립트가 두 번째 TU 를 함께 넣습니다:

```bash
bash ac79/build/build_sdk_app_project_source.sh
# 기록된 산출물: ~/Documents/SMK37ProMod/linux-build/ac79-build-2026-10-09-b1-usb-descriptors
```

무엇을 넣나 — `ac79/app/smk_usb_descriptors.{h,c}`: 라이브 덤프 flash `0x0BDDE5` 에서 **바이트
그대로 회수한** 18 B 디바이스 디스크립터(`4d4a:4155`), **저작한** 39 B 구성 집합(MIDIStreaming
인터페이스 1개 + 벌크 OUT `0x04`/IN `0x84`, 버스 파워 100 mA), `GET_DESCRIPTOR` 식 조회, 부팅
자기검사. 회수와 저작은 소스와 테스트 출력에서 엄격히 구분됩니다.

무엇이 회수 불가인가 — 디스크립터 집합 중 **디바이스 디스크립터 18 B 만** 회수됩니다. 구성/
인터페이스/엔드포인트/스트링 디스크립터는 어떤 산출물에도 없습니다: 18개 전체 플래시 덤프 + 47개
앱 슬롯 페이로드 + 607개 기타 캡처 + 자체 SDK 빌드 전체에서 구성 체인 0, `07 24 06` 0,
`07 05 04 …`/`07 05 84 …` 0. 덤프에서 그 신원은 USB 디스크립터 표가 아니라 ASCII 마커
(`2f 2a 2e 75 66 77`) 로 시작하는 패키지 레코드 안에 있고, 뒤에는 10 B 트레일러와 `0x0BE000`
섹터 경계까지의 0xFF 채움뿐입니다. 증거표: `ac79/evidence/updater-usb-identity.json`
(재생성: `python3 ac79/evidence/recon_updater_usb_identity.py`). 저작한 바이트의 부재는 호스트
검사가 매 실행 재확인하므로, 나중에 덤프에서 나오면 테스트가 실패하며 회수본으로 교체하라고
요구합니다.

넣지 않는 것 — USB 컨트롤러 초기화, 디스크립터 전달, 열거, 엔드포인트/전송 I/O(모두 다음 단계),
플래시 접근. 장치 접촉 없음.

디스크립터 대조 (호스트):

```bash
make test-usb-descriptors
# 전체 플래시 덤프 일괄 대조:
make test-usb-descriptors SMK_LIVE_DUMP="$(ls ~/Documents/SMK37ProMod/baselines/v15/device-dumps/*.bin)"
```

검증 상태 — 실행한 것만 적습니다 (2026-10-09, 컨테이너 `smk-build`):

| 항목 | 결과 |
|---|---|
| 빌드 | `+app.bin: 121188 bytes` (stock 119,748 + 1,440 B; §3.2 대비 +320 B) |
| 레이아웃 | `.text 0x02000120+0x15460`(87,136 B), `.data`/`.bss` `0x04000000` = 0 B, `.ram0_bss` §3.2 대비 +4 B (`smk_usb_selftest_result` 0x01C08A6C) |
| 게이트 | `LAYOUT GATE: PASS` ×2 (`sdk.elf`, `sdk.map`), 종료코드 0 |
| 프로젝트 기원 증거 | `symbol_tbl.txt`: `smk_usb_device_descriptor`(0x02012BC7, 0x12)·`smk_usb_config_descriptor`(0x02012BA0, 0x27)·`smk_usb_selftest_result`; `sdk.map` 이 두 TU 를 모두 `LOAD`; `app.bin` 에 18 B 디스크립터 1회·39 B 구성 집합 1회, stock·§3.2·벽돌 이미지에는 각 0회 |
| 디스크립터 대조 | `make test-usb-descriptors` → `USB DESCRIPTORS: PASS` (덤프 없이 12 검사, 덤프 지정 시 22 검사; 18개 파일 일괄 시 175 검사/0 실패 = 전체 플래시 덤프 15개 바이트 일치 + 음성 대조 1개) |
| 재현성 | 2회 빌드 크기·레이아웃·`sdk.map` 해시 동일, `app.bin` 은 `__TIME__` 2바이트만 다름 |
| 해시 | `app.bin 7110628a…` / `sdk.elf d77c76a0…` / `sdk.map ecffbcc2…` / `symbol_tbl.txt e9cc04f0…` |
| 부작용 | 없음 — 빌드 직후 stock §3 빌드가 `+app.bin: 119748 bytes` 로 그대로 성공, SDK 앱 트리는 stock (`git status` clean, 잔여 오브젝트 없음) |

주의 (측정된 함정) — `__attribute__((used))` 는 장식이 아니라 필수입니다. 붙이기 전 첫 빌드의
`app.bin` 에는 18 B 회수 디스크립터가 **0회** 들어 있었습니다 (`-flto -Oz` 가 아직 아무도 관측하지
않는 표를 즉시값 비교 상수로 접은 결과). 두 표는 런타임에 USB 가 서빙해야 하므로 바이트로 남아야
하고, 그 덕분에 산출물 자체가 검사 가능해집니다.

### 3.3 정정 (2026-10-09 감사)

§3.3 의 디스크립터 집합은 **증거 기반이 아니었습니다**. 읽기 전용 감사가 실행으로 확인한 내용입니다:

- 저작한 `bInterfaceNumber = 0` 은 저장소 자체 기록과 모순됩니다 — `docs/research-notes.md` 는 업데이트
  모드를 **MIDI Streaming interface 1**, product `USB Composite Device`(즉 복합)로 기록합니다.
  단일 인터페이스 구성도 이 기록과 어긋납니다.
- 호스트 검사의 "CS_HEADER 없음" 단언은 `07 24 06 01` 패턴을 찾았는데, 실제 헤더는
  `07 24 06 00 01 …` (bcdADC 0x0100) 이므로 **절대 일치할 수 없는 공허한 단언**이었습니다.
- `wMaxPacketSize`·`bInterfaceNumber`·CS_HEADER `wTotalLength`·`bmAttributes` 변이를 모두 통과시켰습니다.
- "16 of 18 덤프" 는 같은 이미지를 두 번 센 수치입니다(고유 이미지 기준 8/9). 정찰은 워크스페이스의
  707개 `.bin` 중 32개를 건너뛰었고, 그중에는 SDK 자체 도구 이미지(`usb_update2.bin` 등)가 있었습니다.

이 항목은 기록으로만 남깁니다. 그 디스크립터 집합을 재사용하면 안 됩니다.

### 3.4 증거 기반 B1 재작성 — `sdk-2026-10-09-b2-evidence-set` (2026-10-09 검증)

§3.3 을 기록에 맞춰 다시 지은 빌드입니다. 산출물 `ac79/app/smk_usb_descriptors.{h,c}` 는 이제
구성을 꾸며내는 대신 **증거 원장**을 내보냅니다.

회수된 바이트 — **18 B 디바이스 디스크립터 하나뿐**입니다. flash `0x0BDDE5` 에서 바이트 그대로
회수했고, 9개 고유 1 MiB 이미지 중 8개 고유 이미지(19개 저장 경로)가 이를 보유합니다.

기록으로 고정된 값 — 30 B MIDIStreaming 인터페이스 단편의 25개 필드 전부가 출처를 갖습니다 (§3.5 정정: 초판은 24개로 적었으나 원장은 25행입니다):

| 출처 | 고정하는 것 |
|---|---|
| `docs/research-notes.md` (업데이트 모드 실측) | 인터페이스 번호 **1**, 엔드포인트 `0x04`/`0x84`, "USB Composite Device" |
| `baselines/v15/device-info/probe.txt` (정상 모드 프로브) | alt 0 하나뿐, class `0x01`/subclass `0x03`, 엔드포인트 2개, 벌크, max-packet 64, interval 0 |
| USB MIDI 1.0 정의 | 디스크립터 형상, bcdADC `0x0100`, protocol 0 |

미회수(조용히 채우지 않고 목록으로 선언하고 이미지에 동봉) — 구성 디스크립터 전체, 복합의 나머지
인터페이스, iConfiguration/iInterface 문자열 내용, MIDI jack, CS_ENDPOINT. 단편의 iInterface(offset 8)
한 바이트만 근거 없이 설정되었고, 그 사실이 목록에 적혀 있습니다. 따라서 `GET_DESCRIPTOR(CONFIG, 0)`
은 **의도적으로 보류**됩니다 — 이전 개정은 꾸며낸 단일 인터페이스 구성을 서빙했습니다.

```bash
bash ac79/build/build_sdk_app_project_source.sh
make test-usb-descriptors
# 기록된 산출물: ~/Documents/SMK37ProMod/linux-build/ac79-build-2026-10-09-b2-evidence-set
```

검증 상태 — 실행한 것만 적습니다 (2026-10-09, 컨테이너 `smk-build`):

| 항목 | 결과 |
|---|---|
| 빌드 | `+app.bin: 122820 bytes` (§3.3 대비 +1,632 B) |
| 레이아웃 | `.text 0x02000120+0x15AC0`(88,768 B), `.data`/`.bss` `0x04000000` = 0 B, `.ram0_data` 34,036 B |
| 게이트 | `LAYOUT GATE: PASS` ×2 (`sdk.elf`, `sdk.map`), 종료코드 0 |
| 기원 증거 | `symbol_tbl.txt`: `smk_usb_device_descriptor`(0x12)·`smk_usb_midi_fragment_bytes`(0x1E)·`smk_usb_fact_table`(0x190)·`smk_usb_unrecovered_table`(0x30); `app.bin` 에 회수 18 B 1회, 단편 30 B 1회 |
| 호스트 검사 | `make test-usb-descriptors` → `USB DESCRIPTORS: PASS` (덤프 없이 109 검사, 덤프 지정 시 118 검사) |
| 변이 시험 | 회수 idVendor 변이 적발; 단편 `wMaxPacketSize`(양쪽)·`bInterfaceNumber`·CS_HEADER `wTotalLength`·`bmAttributes` 변이 각각 적발; 원장을 틀린 값에 맞추면 문서 재유도 검사가 적발; iInterface 선언을 지우면 "조용한 바이트 없음" 검사가 적발; `probe.txt` 를 32 로 고치면 문서 검사가 적발; 주입한 실제 MS 헤더·엔드포인트·구성 체인과 서술자 바이트 변조도 모두 적발 |
| 재현성 | 2회 빌드 크기·레이아웃·`sdk.map` 해시 동일, `app.bin` 은 `__TIME__` 7바이트만 다름 |
| 해시 | `app.bin c2bca0d7…` / `sdk.elf 4c2e8af5…` / `sdk.map 80b7ca5e…` / `symbol_tbl.txt fcad0a7c…` |
| 부작용 | 없음 — 직후 stock §3 빌드가 `+app.bin: 119748 bytes`, 컨테이너 트리는 stock |

정찰 범위 정정 — `ac79/evidence/recon_updater_usb_identity.py` 는 워크스페이스의
`*.bin`·`*.fwsc`·`*.elf` 를 스캔하고(스캔 집합 규칙과 정확한 수치는 §3.5 정찰 v4), sha256 기준 고유
이미지로 수를 보고하며, 짧은 패턴의 우연 적중 기대치를 스캔 바이트 수에 맞춰 함께 기록합니다. 계획서의
"v15 디스크립터 캡처 완료" 는 `baselines/v15/device-info/probe.txt` 를 가리키며(인용 절이 §5 로 잘못
적혀 있음), 그 파일은 바이트가 아니라 **필드**를 기록합니다.

### 3.5 B1 증거 정정 + 업데이터 이미지 직접 수색 — `sdk-2026-10-09-b3-updater-image-evidence` (2026-10-09 검증)

§3.4 를 두 번째 읽기 전용 감사가 다시 검증했고, §3.4 의 서술 두 문장을 **반증**했습니다. 반증된
산출물은 그대로 기록으로 남기고(`known_builds[4]` 에 `superseded_by` + 정정 주석), 증거가 실제로
있는 곳을 다시 수색해 이 빌드로 대체했습니다.

무엇이 틀렸나 — (1) "이 프로젝트 어디에도 원시 디스크립터 바이트 캡처는 없다" 와 "어떤 `*.bin` 도
디스크립터 체인을 담고 있지 않다" 는 **너무 넓은 문장**이었습니다. 문자열 디스크립터 바이트는
존재합니다: 업데이터 이미지 `usb_hid_ota.bin` 이 flash `0xBB558` 에 UTF-16LE product 이름
`USB Composite Device` 를 그대로 담고 있고, `*.bin` 정찰 자신도 정지된 `known_builds[3]` 빌드
출력에서 구성 체인 1개를 세고 있었습니다. (2) "OTA 페이로드는 이 영역을 덮지 않으므로 대체 앱은
사이트를 계승할 수 없다" 는 정확히는 **앱 페이로드 한정**입니다 — 전체 `.fwsc` 재플래시는
`ota.bin` 엔트리를 쓰므로 이 영역을 씁니다. (3) 호스트 검사가 증거 문서 두 개가 없어도 PASS(exit 0)
였고, (4) 정찰은 `*.bin` 만 스캔했습니다.

무엇을 찾았나 — 디스크립터 사이트는 독립 레코드가 아니라 **업데이터 이미지의 꼬리**입니다:
벤더 패키지(`.fwsc`)의 `ota.bin` UFW 엔트리(0x4E01 B)가 flash `0x0B9000..0x0BDE01` 에 매핑되고
디스크립터가 그 안 `0x4DE5` 에 있습니다(베이스는 `0x0BDDE5 - 0x4DE5` 로 유도하며, 도구가 모든
덤프에서 이 값을 검증합니다). 새 도구 `ac79/evidence/search_updater_usb_image.py` 가 이 19,969 B
이미지를 덤프에서 잘라 **와이어 포맷으로** 수색합니다:

| 수색 항목 | 결과 |
|---|---|
| 구성 체인 | 0 |
| 그럴듯한 인터페이스 레코드 (길이 9/타입 4, 필드 범위내) | 0 (원시 (9,4) 바이트 쌍 3개는 우연) |
| 엔드포인트 레코드 (길이 7/타입 5, 합법 `bmAttributes`) | 0 |
| MIDIStreaming MS 헤더 (`07 24 01`·`07 24 06` 둘 다) | 0 |
| CS_ENDPOINT (`07 25`) | 0 |
| 걸어갈 수 있는 문자열 테이블 | 0 |

반면 **문자열 바이트는 있습니다**: 40 B UTF-16LE product 이름 텍스트가 flash `0x0BB558`
(이미지 `0x2558`)에, 정확히 디스크립터와 같은 8/9 고유 이미지에, 프리스트어 음성 대조에는 없고,
앞 2 바이트는 `2a 03` 입니다. 그 앞 2 바이트가 문자열 디스크립터 헤더인지는 **미확립** 입니다
(LANGID 앵커 `04 03 09 04` 에서 레코드를 걸으면 두 번째에서 끊깁니다). 그래서 텍스트는 **회수된
증거**로 내보내고(`smk_usb_updater_product_name`, 검사 때마다 덤프와 바이트 비교) 서빙은 하지
않습니다 — `GET_DESCRIPTOR(CONFIG, 0)` 과 모든 문자열 요청은 여전히 absent 입니다.

이번 빌드의 주장 구조는 세 채널로 나뉩니다: **회수 바이트**(디바이스 디스크립터, 서빙됨),
**회수 텍스트**(product 이름, 증거 전용), **저작 바이트**(30 B MIDIStreaming 단편, 두 문서가 필드
고정).

```bash
bash ac79/build/build_sdk_app_project_source.sh
make test-usb-descriptors
# 기록된 산출물: ~/Documents/SMK37ProMod/linux-build/ac79-build-2026-10-09-b3-updater-image-evidence
```

검증 상태 — 실행한 것만 적습니다 (2026-10-09, 컨테이너 `smk-build`):

| 항목 | 결과 |
|---|---|
| 빌드 | `+app.bin: 123332 bytes` (§3.4 대비 +512 B) |
| 레이아웃 | `.text 0x02000120+0x15CC0`(89,280 B), 게이트 `LAYOUT GATE: PASS` ×2 (`sdk.elf`/`sdk.map`), 종료코드 0 |
| 기원 증거 | `symbol_tbl.txt`: `smk_usb_device_descriptor`(0x12)·`smk_usb_midi_fragment_bytes`(0x1E)·`smk_usb_updater_product_name_utf16`(0x28)·`smk_usb_fact_table`(0x190)·`smk_usb_unrecovered_table`(0x30); `app.bin` 에 프로젝트 바이트 문자열 5종 각 1회 (빌드 레시피가 회수 전에 단언) |
| 호스트 검사 | `make test-usb-descriptors` → `USB DESCRIPTORS: PASS` (덤프 없이 112 검사, 덤프 지정 시 131 검사). **문서 누락 시 fail-closed** — `SMK_REPO_ROOT` 를 빈 디렉터리로 주면 exit 1 |
| 정찰 v4 | `recon_updater_usb_identity.py`: **765 파일 / 179,592,140 B** (704 `.bin` + 56 `.fwsc` + 5 `.elf`) — 자체 재생성 빌드 산출물(`linux-build/ac79-build-*`)은 스캔 집합에서 제외하고 `scope.excluded` 에 파일별 크기·sha256으로 명시, `scope.manifest_sha256` 이 스캔 집합을 고정. `.fwsc` 56개 전부가 사이트와 product 이름을 보유; 앱 슬롯 페이로드 47개는 0. 구성 체인은 파일별로: 벤더 SDK MP-test 툴 `AC790N` sdk.elf 1개, `AC791N` sdk.elf 1개 — 회수 코퍼스에는 0 |
| 변이 시험 | 문서 2종(probe 64→32, notes iface 1→0), 원장 `bInterfaceNumber`, 단편 `wMaxPacketSize`, iInterface 선언 삭제, 꾸며낸 구성 서빙, **회수된 product 이름 바이트 뒤집기**, 덤프 주입(서술자 변조·MS 헤더+엔드포인트 주입·이중 신원·절단·64 B) — 전부 적발, 비-1MiB 덤프 exit 2 |
| 재현성 | 2회 빌드 크기·레이아웃·`sdk.map`·`symbol_tbl.txt` 해시 동일, `app.bin`/`sdk.elf` 는 `__TIME__` 문자열의 분·초 자릿수에서만 다름 (2026-10-09c 쌍: 3바이트, 최초 쌍: 2바이트) |
| 해시 | `app.bin a3fc85eb…` / `sdk.elf 467c61ff…` / `sdk.map ab2f27c3…` / `symbol_tbl.txt 81078e82…` (2026-10-09c 재빌드 값) |
| 부작용 | 없음 — 직후 stock §3 빌드가 `+app.bin: 119748 bytes`, 컨테이너 트리는 stock |

여전히 불가한 것 — 구성/인터페이스/엔드포인트/jack/CS_ENDPOINT 는 와이어 포맷 바이트로 **어디에도
없습니다** (업데이터 이미지 자체를 수색해도). 구성은 계속 보류되며, 다음 단계는 단편을 실체로
대체할 증거(업데이터 이미지의 코드 정적 분석 등)를 찾는 것입니다.

2026-10-09c 정정 (기록만 — 실기기 접촉·flash 없음) — 세 가지를 바로잡았고 그 밖의 파일은 건드리지
않았습니다. (1) `known_builds[5]` 의 `project_code_evidence` 심볼 주소 세 개가 정지된 b2 산출물 값을
그대로 갖고 있었습니다 — 이 빌드의 `symbol_tbl.txt` 실제 값(`smk_usb_device_descriptor` `0x02013230`,
`smk_usb_midi_fragment_bytes` `0x02013242`, `smk_usb_fact_table` `0x020145F4`; 나머지 두 개는 이미
일치)으로 다시 기록했습니다. (2) 구성 체인 서술이 "벤더 SDK MP-test 툴" 로 뭉뚱그려져 있었고, 인용된
정찰 JSON 자신은 그중 하나를 이 프로젝트의 정지된 B1 빌드 산출물로 귀속시켰습니다 — 이제 체인을
파일별로 적고(스캔 집합 기준 `AC790N` 1, `AC791N` 1), 자체 빌드 산출물은 스캔에서 제외합니다.
(3) 정찰 스캔 집합에서 이 프로젝트의 재생성 빌드 산출물(`linux-build/ac79-build-*`)을 제외하고
`scope.excluded`(파일별 크기·sha256)와 `scope.manifest_sha256` 을 기록해, 헤드라인 수치가 자체 빌드
때문에 흔들리지 않게 했습니다. 소스 핀은 새 해시로 다시 기록했고 산출물은 새 소스로 다시 빌드했습니다
(모두 위 표와 `known_builds[5]` 에 반영).

## 4. 참고

- Linux 툴체인: `pkgman.jieliapp.com/s/linux-toolchain` (x86-64 전용 — §3의 amd64
  컨테이너에서 그대로 실행. 계획서 §7의 qemu-user + LD_PRELOAD 셤은 불필요)
- Linux post-build: `pkgman.jieliapp.com/s/linux-postbuild`
- SDK GitHub 미러: `jeffreywugz/fw-AC79_AIoT_SDK` (branch `release/AC79NN_SDK_V1.0.3`)
