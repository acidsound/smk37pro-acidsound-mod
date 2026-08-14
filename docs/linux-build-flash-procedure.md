# AC791N SDK — Windows 도구 vs Linux 경로 & 플래시 절차

작성: 2026-08-14 · 상태: 빌드(post-build) 완료 · 플래시는 USB 접근 확보 대기

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
container exec smk-jieli-build bash -c \
  'ulimit -n 8192; cd /build/fw-AC79_AIoT_SDK && make ac791n_demo_demo_hello'
```

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

## 3. 참고

- Linux 툴체인: `pkgman.jieliapp.com/s/linux-toolchain` (x86-64 전용 — qemu-user +
  LD_PRELOAD 셤으로 실행, 상세는 `docs/from-scratch-platform-plan.md` §7)
- Linux post-build: `pkgman.jieliapp.com/s/linux-postbuild`
- SDK GitHub 미러: `jeffreywugz/fw-AC79_AIoT_SDK` (branch `release/AC79NN_SDK_V1.0.3`)
