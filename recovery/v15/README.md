# v15 recovery

현재 실기기 복구 기준선은 `post-recovery-baseline-20260802.json`이다.

- exact 공식 v15 OTA 설치 후 `SMK-37 Pro_015` 확인
- 복구 직후 1 MiB dump A/B byte-identical
- package-managed `0x00000..0x9BFFF`가 최초 clean v15와 byte-identical
- `0x9C000..0xFFFFF` persistent tail은 application rollback에서 기본적으로 보존

향후 v15 rollback은 실패 이미지와 exact 공식 v15 package를 비교해 target별
변경 sector 집합을 새로 만든다. 현재 sector hash가 실패 이미지와 일치해야만
erase/write하고, readback 및 대상 외 불변성을 검증한다.

M10용 v12 six-sector bundle이나 148-sector v012 응급 복원을 일반 v15 복구에
사용하지 않는다.

R01d는 `BRICKED/REVOKED`다. 해당 실패 이미지의 정확한 변경 sector는
`0x04000`, `0x0A000`, `0x20000`, `0x22000`이며, 전용 guarded bundle은 현재
Flash가 원래 R01d sector hash와 일치할 때만 사용할 수 있다.
