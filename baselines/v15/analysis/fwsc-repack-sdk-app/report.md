# SMK v15 OTA로 Jieli SDK 앱 플래시 — fwsc 재포장 판정 보고서

작성: 2026-08-14 · 상태: **판정 PASS — pack 도구 구현 + 오프라인 검증 완료** (실기기 플래시는 P0c)

## 1. 결론

**OrbStack(VM), 호스트 센더(tonorflash 재구현) 없이**, Jieli AC79 SDK로 빌드한
`app.bin`을 기존 SMK v15 OTA 경로(`exact_ota`)로 플래시할 수 있습니다.
디스크 추가 0, 새 도구 설치 0. `fwsc`는 Jieli 표준 **UFW** 포맷이고 검증은
**CRC16 자체일관성(서명 없음)** 이므로, 올바르게 패키징된 임의의 app 내용이 장치
검증을 통과합니다 — S1C1~S1C6(모두 변경된 app 내용)이 전부 stage-1을 통과한 것이
이미 증거입니다.

## 2. 판정 표

| 항목 | 판정 | 근거 |
|---|---|---|
| 검증이 계산 가능한가 | ✅ **예** | UFW = CRC16 기반. 서명 없음. S1C1~S1C6 변경 내용 전부 통과 |
| 포맷 도구 | ✅ 있음 | jl-misctools 기반 역분석(`tools/smk37_v15_app_patch.py`): Ufw/AppImage/crc16/enc_cipher/sfc_cipher |
| 플랫폼 동일성 | ✅ 확정 | SMK v15 = AC791N/wl82 앱 (복원 작업의 "WL82 forced-loader 덤프" + 우리 SDK 타깃 `cpu/wl82`) |
| 엔트리 포인트 정합 | ✅ **일치** | SDK 기본 `ENTRY=0x2000120` == v15 area 헤더 요구값 `0x02000120` |
| 레이아웃 구조 | ✅ 보존 | 패딩 방식으로 구조 불변 (아래 §4) |
| 부팅 | ⚠️ 실험 필요 | = P0c 첫 플래시 관측 |
| 안전망 | ✅ 있음 | 보호 부트(0x0..0x3FFF) 불변 + forced-loader 덤프/복원 (restore 작업 증명) |

## 3. 구조

```
FWSC (701,140 B)
├─ 메타데이터 슬롯 20×48B (SMK-37 Pro_015 버전)
└─ UFW payload (701,120 B)                     [Jieli 업데이트 포맷]
   ├─ UFW 헤더 0x40  (CRC16 + image_size + entry_count=8 + AC791N)
   ├─ 엔트리 8×0x50   (type/index/data_crc/offset/size/aligned/name)
   │   └─ flash.bin 엔트리: offset=0x400, size=0x9C000 (SFC 암호화)
   └─ flash.bin (0x9C000 = 638,976 B)          [SFC cipher, CHIP_KEY=0x980F]
      ├─ 0x0000..0x3FFF  보호 부트/설정 (우리가 절대 건드리지 않음)
      ├─ 0x4000  JLFS "app_area_head" (진입점 0x02000120, area 크기)
      ├─ 0x4020  JLFS "app.bin" 엔트리 헤더
      ├─ 0x4120  app 데이터 617,012 B  ← SDK app.bin 교체 지점
      └─ 0x9ACD3..0x9C000  보호 리소스/예약 (불변)
```

## 4. pack 방식 — "패딩 치환"

SDK app.bin(119,748 B)을 **0xFF로 617,012 B까지 패딩**해 기존 v15 app 슬롯에
치환합니다. 모든 크기/오프셋/엔트리/암호화 구조가 **바이트 단위 불변**이라
부팅 체인·업데이트 검증이 기존과 동일한 레이아웃을 봅니다. 변경되는 것은
app 내용과 재계산된 CRC뿐이며 `build_package`의 감사(변경 범위 = app 데이터 +
헤더 CRC 필드, 보호 해시 불변)로 검증됩니다.

## 5. 구현 — `tools/pack_sdk_app_fwsc.py`

```
python3 tools/pack_sdk_app_fwsc.py \
  --app linux-build/fw-AC79_AIoT_SDK/cpu/wl82/tools/app.bin \
  --name SDK-DEMO-HELLO \
  --output-dir baselines/v15/analysis/fwsc-repack-sdk-app/output
```

생성물:
- `SMK37Pro-v15-SDK-DEMO-HELLO.fwsc` (701,140 B)
  - sha256 `4d39efe4d8133a1fa15f16619d28c1402cebdc3a14269fdfdca330926a3bcb45`
  - 토큰 `INSTALL-SMK37PRO-V15-SDK-DEMO-HELLO-4D39EFE4`
- `package-manifest.json` — app/sha/패딩/변경 감사/보호 해시
- `exact_ota.c` — 패키지 전용 OTA 래퍼 (S1C6 양식, 컴파일 확인)

## 6. 오프라인 검증 (전부 PASS)

| 게이트 | 결과 |
|---|---|
| 양성 check (SDK-DEMO-HELLO) | ✅ PASS (701,120-byte OTA payload) |
| 음성 check (공식 v15) | ✅ REJECT ("not exact SDK-DEMO-HELLO package") |
| 출력 재파싱 (UFW → flash → AppImage) | ✅ app 내용 == 패딩된 SDK app.bin |
| 보호 해시 불변 (부트/설정/리소스/예약) | ✅ `protected hashes equal: True` |
| 변경 범위 감사 | ✅ app 데이터 585,849 B + CRC 필드만 |
| upload dry-run (무장치) | ✅ 인터페이스 4 클레임 실패로 안전 종료 (크래시 없음) |

## 7. 남은 단계

1. **레이아웃 추가 정합 (권장 사전 확인)**: SDK 빌드 config(isd_config.ini
   `-boot 0x1c02000`)와 SMK 실제(app 0x4000+) 차이는 UFW 템플릿 구조 덕에
   무관하지만, SDK 앱의 **섹션 배치**(sdk.ld의 RAM/flash 주소)가 v15 빌드와
   호환되는지 실기기 부팅으로 확인.
2. **실기기 플래시 (= P0c)**: exact_ota 컴파일 → `check` → 장치 업데이트 모드
   진입 → `upload --confirm INSTALL-SMK37PRO-V15-SDK-DEMO-HELLO-4D39EFE4`
   → 부팅 관측 (SDK 앱이 뭔가 보이는 것 — 콘솔/LED/USB).
3. **복원 준비**: S1C6 fwsc + 복원 자산 보관. SDK 앱도 CONFIG_UPDATA_ENABLE로
   빌드되므로 업데이트 모드 재진입 가능성 높음; 최후 안전망은 forced-loader.
4. P0c 성공 시: demo_ui 기반 LCD 테스트 패턴(P1)로 확장.

## 8. 참고 파일

- `tools/pack_sdk_app_fwsc.py` — pack 도구 (신규)
- `tools/smk37_v15_app_patch.py` — UFW/AppImage 역분석·재포장 (기존)
- `docs/from-scratch-platform-plan.md` §7 — P0a/P0b 상태
- `docs/linux-build-flash-procedure.md` — Windows/Linux 도구 대조·플래시 절차
