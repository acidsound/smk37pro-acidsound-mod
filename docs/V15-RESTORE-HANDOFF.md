# SMK-37 Pro v15 복원 handoff

작성 시각: 2026-08-02 UTC
실기기 정상 확인: 2026-08-02 18:33 UTC
공식 v15 재업그레이드 및 `015` identity 확인: 2026-08-02 18:44 UTC

## 현재 최종 상태

148-sector 기록은 **v15 상태에서 v012로 긴급 복구한 중간 단계**이다. 그 후
exact 공식 v15 OTA를 다시 설치했으며, 장치는 read-only `device-info`에서
`SMK-37 Pro_015`를 반환했다.

- 공식 v15 package SHA-256:
  `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- 복구 후 v15 dump A/B SHA-256:
  `2795c51dbac4f82ff6fb6c38ffcf27a596829ea9ef5354f7959fc3657f85dcfb`
- 두 1 MiB dump: byte-identical
- package-managed Flash `0x00000..0x9BFFF` SHA-256:
  `9d68aaece688d23f487cad734c387399a720e9dbebed613a09304dc666a11936`
- 위 package-managed 범위는 최초 clean v15 dump와 byte-identical
- 최초 clean v15 dump와 다른 sector는 package 밖의
  `0xBE000`, `0xC2000`, `0xF8000`, `0xFD000`뿐이다. 이들은 설정/사용자 데이터
  tail로 취급하며 v15 application rollback에 포함하지 않는다.

## 한 줄 요약

v15 상태에서 v012 기준 148개 sector를 복원해 긴급 부팅에 성공한 뒤, exact
공식 v15 OTA를 다시 설치했다. 현재 기준선은 firmware `015`이며 v15
package-managed Flash 범위가 최초 clean v15와 완전히 일치한다.

## 향후 v15 forced recovery의 고정 규칙

다음 v15 mod 실패에서는 이 문서의 148-sector v012 복원을 반복하지 않는다.

1. `WL82 / UBOOT1.00 / 1.00`, device ID `15425556`, flash ID `60256`을 확인한다.
2. 쓰기 전에 새 1 MiB dump A/B를 읽고 byte-identical인지 확인한다.
3. 실패 이미지와 exact 공식 v15 package의 `flash.bin`을 비교해 변경된 4 KiB
   sector 집합을 target별로 새로 산출한다.
4. 현재 장치의 각 대상 sector SHA-256이 실패 이미지의 expected hash와 모두
   일치할 때만 erase/write를 허용한다.
5. 공식 v15의 해당 sector만 기록하고 즉시 readback SHA-256을 확인한다.
6. 사후 전체 dump에서 대상 외 sector가 바뀌지 않았는지 확인한다.
7. package 범위 밖 `0x9C000..0xFFFFF`는 장치별 설정/사용자 데이터이므로,
   별도 손상 증거 없이 복원하지 않는다.

R01d 실패 이미지에 한해서 공식 v15 대비 변경 sector는 정확히 다음 네 개다.

- `0x04000`
- `0x0A000`
- `0x20000`
- `0x22000`

전용 guarded bundle:

`build/SMK37Pro-WL82-v15-R01d-rollback-20260802-v1.zip`

ZIP SHA-256:

`47fc436920a6b24c6bc7aaa0b2acb438e14da6c30018f724459b3e7ea3e17307`

이 bundle은 **현재 Flash가 원래 R01d sector hash와 일치할 때만** 사용할 수
있다. 공식 v15로 복귀한 현재 장치나 다른 실패 이미지에는 사용하지 않는다.

## 다음 세션이 먼저 할 일

1. 루트 `AGENTS.md`를 읽는다.
2. 사용자가 녹색 LED OFF, SMK 전원 ON 상태인지 확인한다.
3. Windows에서 `WL82 UBOOT1.00 USB Device`와 실제 `PHYSICALDRIVE` 번호를 다시 조회한다.
4. 아래 self-test를 통과시킨다.
5. 현재 Flash가 전용 매니페스트의 사전 해시와 일치할 때만 전용 래퍼를 실행한다.

## 성공에 사용한 파일

기준 폴더:

`SMK37Pro-WL82-M10-rollback-20260801-v4`

- `restore/smk37_wl82_v15_full_restore.py`
- `restore/run-restore-v15-full-elevated.ps1`
- `recovery-sectors/manifest-v15-full-diff-20260802.json`
- `recovery-sectors/v15-full/`
- `restore/restore-evidence-20260802-183112/`
- `restore/guarded-restore-v15-full-20260803-033111.log`

매니페스트 SHA-256:

`4f9d34d60356f8b94152c052d5f34d4c6870a2e45b86624585a8c1c63d0757aa`

성공 사후 덤프 SHA-256:

`de29d3bfa043b9f83094afc28cb01c643b3d793dff0e70f15da0d2382444c491`

## 실제 복원 과정

1. `WL82 / UBOOT1.00 / 1.00`, device ID `15425556`, flash ID `60256` 확인
2. 공식 RAM loader 업로드
3. 새 1MiB pre-dump A/B 획득 및 바이트 동일성 확인
4. v15와 정상 v012 사후 덤프를 4KiB 단위 비교
5. 최초 확인된 차이: 156개 섹터
6. 기존 M10용 6개 섹터 복원 시도
7. 쓰기와 readback은 성공했지만 실기기는 복원되지 않음
8. 6개 복원 후 남은 차이: 150개 섹터
9. 두 정상 v012 덤프에서도 변한 `0xBE000`, `0xFD000` 제외
10. 남은 148개 섹터를 erase-to-FF 후 256바이트 단위로 기록
11. 각 섹터 즉시 readback SHA-256 검증
12. 사후 전체 덤프에서 대상 외 변경 없음 확인
13. 정상 v012 기준과 남은 차이는 `0xBE000`, `0xFD000`뿐임 확인
14. 사용자가 정상 부팅과 복원을 확인

## 실행 예시

먼저 장치 번호 확인:

```powershell
Get-CimInstance Win32_DiskDrive |
  Select-Object Index,DeviceID,Model,PNPDeviceID,Size
```

오프라인 검사:

```powershell
py -3 .\SMK37Pro-WL82-M10-rollback-20260801-v4\restore\smk37_wl82_v15_full_restore.py self-test
py -3 -m py_compile .\SMK37Pro-WL82-M10-rollback-20260801-v4\restore\smk37_wl82_v15_full_restore.py
```

장치가 `PHYSICALDRIVE5`로 확인된 경우:

```powershell
$wrapper = (Resolve-Path '.\SMK37Pro-WL82-M10-rollback-20260801-v4\restore\run-restore-v15-full-elevated.ps1').Path
$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $wrapper,
  '-Device', '\\.\PHYSICALDRIVE5'
)
exit $p.ExitCode
```

## 주의

이 매니페스트는 성공 당시의 6섹터 시도 직후 상태에 고정되어 있다. 다음 장치 상태가 다르면 `SAFE STOP`할 수 있다. 그때는 expected hash를 억지로 바꾸지 말고 새 이중 덤프와 정상 v012 기준 비교로 복원 대상을 다시 만든다.

기존 M10 6섹터 래퍼만 실행하거나 전체 1MiB 덤프를 통째로 쓰지 않는다.

이 148-sector 절차는 v15와 v012의 정상적인 firmware 차이를 함께 덮어쓴 응급
복원 기록이다. 최종 목표가 v15이면 정상 USB 복귀 후 exact 공식 v15 OTA와
`015` identity 확인까지 완료해야 한다. 향후 v15 brick에는 위의 target-specific
v15 최소-sector 규칙을 우선한다.
