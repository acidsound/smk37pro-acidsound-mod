# SMK-37 Pro v15 clean baseline

이 디렉터리는 공식 v15와 정상 부팅 장치에서 확보한 순정 기준선을 보존한다.
기존 v12/M09/M10 증거 파일은 이곳으로 이동하지 않는다.

## Layout

- `official/`: 공식 FWSC의 해시, manifest, parser 결과
- `device-dumps/`: 정상 `SMK-37 Pro_015` 장치의 1 MiB dump A/B와 해시
- `device-info/`: `probe`, `device-info`, 화면 및 기능 확인 기록
- `analysis/`: v12/v15 code, data, sector 및 boot invariant 비교

대용량 바이너리는 Git에 추가하지 않고 각 디렉터리의 `SHA256SUMS` 또는 manifest로
식별한다. 공식 원본과 clean dump는 수정하지 않는다.

