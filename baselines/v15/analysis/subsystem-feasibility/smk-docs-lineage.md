# smk-37-pro-docs lineage and evidence notes

조사 시각: 2026-08-02 UTC  
대상 공개 저장소: <https://github.com/jonathaslacerda/smk-37-pro-docs>  
읽기 전용 수집 방법: git mirror clone, GitHub REST API, upstream README/docs 링크 HEAD/GET 확인. 이 문서는 v15 근거만 분리하기 위해 작성되었으며 v12 주소를 v15 근거로 사용하지 않았다.

## Executive summary

* 저장소는 `jonathaslacerda/smk-37-pro-docs` 단일 upstream 문서/아티팩트 저장소이며, GitHub API상 fork가 아니고 공개 저장소다. 직접 근거: GitHub API `fork: false`, `visibility: public`.
* 조사한 HEAD는 `main`의 `8f1bf1115cc8fe874bbac326d4f1f1513d743844`이며 2026-03-24T17:47:59Z에 push된 상태다. 직접 근거: `refs/heads/main` 및 `/branches` API.
* 저장소는 firmware, manuals, images, stock sysex banks를 포함한다. v15 직접 아티팩트는 `firmware/FIRMWARE.md`의 “Firmware 15 (Remains 1.10) - 26-01-2026” 항목과 그 네 개의 `.fwsc` 파일이다.
* 핵심 하드웨어/펌웨어 주장은 README에 혼합되어 있다. 일부는 외부 링크 인용에 근거한 직접 주장이고, 일부는 “possibly/probable”로 적힌 추론이다. 특히 `.fwsc` 포맷이 `kagaimiq/jielie`의 `newfw`와 유사/동일하다는 내용은 README 자체도 “probable”이라고 명시하므로 추론으로 분류한다.
* 링크 상태 확인 결과, `https://www.m-vave.com/productinfo/1431195.html`은 404였다. `https://www.cuvave.com/productinfo/1431195.html`은 TLS 자체 서명 인증서 오류로 검증 실패했다. Reddit 두 링크는 403 Blocked로 자동 검증 불가였다. 바이너리 이미지/PDF 내부 XMP namespace URL은 문서 인용 링크가 아닌 메타데이터로 별도 dead-link 판단에서 제외하는 것이 타당하다.

## Repository identity and GitHub metadata

| Field | Value | Evidence |
|---|---|---|
| HTML URL | <https://github.com/jonathaslacerda/smk-37-pro-docs> | GitHub API `html_url` 직접 근거 |
| Clone URL | <https://github.com/jonathaslacerda/smk-37-pro-docs.git> | GitHub API `clone_url` 직접 근거 |
| Description | `Documentation repository for M-Vave SMK 37 Pro` | GitHub API and README 직접 근거 |
| Created | 2025-09-24T21:01:10Z | GitHub API 직접 근거 |
| Updated | 2026-07-01T12:22:49Z | GitHub API 직접 근거 |
| Pushed | 2026-03-24T17:47:59Z | GitHub API 직접 근거 |
| Default branch | `main` | GitHub API 직접 근거 |
| HEAD | `8f1bf1115cc8fe874bbac326d4f1f1513d743844` | `git show-ref`, GitHub `/branches` 직접 근거 |
| License | Apache-2.0 | GitHub API and `LICENSE` 직접 근거 |
| Stars/watchers | 24 | GitHub API 직접 근거, 조사 시점 값 |
| Fork count/network count | 1/1 | GitHub API 직접 근거, 조사 시점 값 |
| Contributors | `jonathaslacerda`, 124 contributions | GitHub `/contributors` 직접 근거 |
| Tags | none | GitHub `/tags` 직접 근거 |
| Branches | `main` only | GitHub `/branches` 직접 근거 |

## Forks and derived repositories

GitHub API `/forks?per_page=100`에서 확인된 fork는 하나다.

| Repository | URL | Created | Pushed | Evidence type | Notes |
|---|---|---:|---:|---|---|
| `taupter/smk-37-pro-docs` | <https://github.com/taupter/smk-37-pro-docs> | 2026-04-06T00:20:34Z | 2026-03-24T17:47:59Z | Direct GitHub API | Upstream의 public fork. API 출력상 `fork: true`, `default_branch: main`, stars 0. 추가 독자 commit 여부는 이번 조사에서 별도 clone하지 않았으나 pushed time이 upstream HEAD와 동일해 미변경 fork일 가능성이 높다. |

README가 인용하거나 사용법을 제시한 cited/derived repositories:

| Repository/document | Exact URL | Evidence type | Relation/claim |
|---|---|---|---|
| probonopd gist | <https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc> | Direct citation in README | README의 Firmware/Hacking 섹션이 “thanks to probonopd”로 감사를 표하고, `.fwsc` unpacking 예시 및 Jieli 관련 식별에 연결한다. |
| probonopd gist comment | <https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc?permalink_comment_id=5739103#gistcomment-5739103> | Direct citation in README | 취소선 처리된 “SoC JieLi C108221-11B8” 주장 출처로 링크되어 있다. README HEAD에서는 이 주장이 취소선이고 AC7911B8 주장이 채택되어 있다. |
| `kagaimiq/jl-misctools` | <https://github.com/kagaimiq/jl-misctools> | Direct command reference in README | README Hacking 섹션에서 `git clone` 및 `fwunpack_newfw.py` 실행 예시를 제공한다. 저장소 자체가 파생되었다는 직접 근거는 아니며, 분석 도구로 사용한 인용이다. |
| kagaimiq jielie newfw document | <https://kagaimiq.github.io/jielie/datafmt/newfw.html> | Direct citation, inferential claim | `.fwsc` 파일이 이 문서의 형식과 유사/동일할 가능성이 있다고 서술한다. README 표현이 “probable”이므로 추론 근거다. |
| kagaimiq chips document | <https://kagaimiq.github.io/jielie/chips/> | Direct citation | Jieli chip reference로 링크되어 있다. |
| Jieli AC79 SDK | <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK> | Direct citation | README SoC AC7911B8 섹션의 SDK 링크다. 저장소가 해당 SDK에서 직접 파생되었다는 근거는 아니고 칩 SDK 참조다. |
| Jieli bootloader | <https://github.com/Jieli-Tech/fw-Bootloader/tree/main/user_boot/cpu/wl82> | Direct citation | README SoC AC7911B8 섹션의 “Bootloader: Bootloader wl82” 링크다. |
| Jieli AC63 BT SDK | <https://github.com/Jieli-Tech/fw-AC63_BT_SDK/> | Inferential citation | README는 `btstack_lowpwer_deal` 같은 문자열이 이 SDK 또는 유사 SDK 사용을 “possibly suggest”한다고 적는다. 추론이다. |

## Commit history relevant to v15 and docs lineage

Full mirror log contained 124 commits from 2025-09-24 to 2026-03-24, all authored by Jonathas Lacerda `<jonathassl@gmail.com>`. 주요 lineage 지점:

| Commit | Date | Subject | Evidence/impact |
|---|---:|---|---|
| `19286ca40c84fa0ed54a3c1201a47b799cc660b8` | 2025-09-24T18:01:10-03:00 | Initial commit | 저장소 최초 커밋. |
| `6a9b8406eb7d00bcc49d3a87b51a255b9c4c5476` | 2025-09-26T09:45:20-03:00 | Create firmware-history.MD | firmware history 문서의 초기 생성 계열. |
| `74170b782d905a72b8be7e328217645026bdab7e` | 2025-09-26T10:38:11-03:00 | Update and rename firmware-history.MD to FIRMWARE.md | firmware history가 현 경로 `firmware/FIRMWARE.md`로 정착. |
| `6990ba81ced21bda76b9a1bbf684d394628f1db9` | 2026-01-26T18:05:48-03:00 | new firmware 15 | v15 firmware 도입으로 보이는 직접 commit subject. |
| `f4db5354042cef2d947ee36481f9c6758aa5b3ba` | 2026-01-26T18:09:13-03:00 | Update FIRMWARE.md | v15 관련 문서 업데이트 계열. |
| `6835c7af30fda628f41abfd47d580056c4799702` | 2026-01-26T18:35:24-03:00 | Update FIRMWARE.md | v15 관련 문서 업데이트 계열. |
| `ccd161e1fe033b3245ff54b78bbcfbfdcfddd37b` | 2026-02-08T13:51:00-03:00 | Update FIRMWARE.md | variant firmware reorganization 이후 문서 업데이트. |
| `094cc2a243c4c4197d1634f3ded61295cdeca316` | 2026-02-08T14:16:53-03:00 | Update FIRMWARE.md | HEAD 근처 firmware 문서 업데이트. |
| `b0173b4e3cabb30a28fe313aa86a1cd79510e5e8` | 2026-03-24T14:38:31-03:00 | Create SYSEX.md | sysex documentation 생성. |
| `90a0156f9763bd9c72ff335312dfc36f80b0e60e` | 2026-03-24T14:39:02-03:00 | Add files via upload | sysex preset banks 업로드로 보임. |
| `8f1bf1115cc8fe874bbac326d4f1f1513d743844` | 2026-03-24T14:47:59-03:00 | Rename SMK37-Pro Presets 3.syx to SMK37-Pro-Presets-3.syx | 조사 대상 HEAD. |

## HEAD tree contents

HEAD `8f1bf1115cc8fe874bbac326d4f1f1513d743844`의 주요 파일:

* `README.md`
* `LICENSE`
* `manual/smk-37-pro-user-manual.pdf`
* `manual/smk-37-pro-daw-setup-manual.pdf`
* `firmware/FIRMWARE.md`
* v15 firmware files:
  * `firmware/smk37pro/SMK-37_Pro_015.fwsc`
  * `firmware/smk37elite/SMK-37_Elite_015.fwsc`
  * `firmware/mkep37/MKE-P37_015.fwsc`
  * `firmware/starrykey37play/STARRYKEY-37_PLAY_015.fwsc`
* earlier SMK-37 Pro firmware files also present in the tree: `SMK-37_Pro_011.fwsc`, `SMK-37_Pro_012.fwsc`, `SMK-37_Pro_013.fwsc`, `SMK-37_Pro_014.fwsc`. 이 문서의 v15 판단에는 이 파일들의 URL을 v15 근거로 사용하지 않는다.
* `images/IMAGES.md` and image folders for `smk37pro`, `smk37elite`, `black`, `allblack`, `pink`, `red`.
* `sysex/SYSEX.md` and four stock preset `.syx` banks.

## Exact v15 artifact URLs and hashes

All URLs below are anchored to HEAD commit `8f1bf1115cc8fe874bbac326d4f1f1513d743844`, not floating `main`.

| Artifact | Exact URL | SHA-256 | Evidence type |
|---|---|---|---|
| SMK-37 Pro v15 firmware | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/firmware/smk37pro/SMK-37_Pro_015.fwsc> | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` | Direct file in upstream git |
| SMK-37 Elite v15 firmware | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/firmware/smk37elite/SMK-37_Elite_015.fwsc> | `6cb061bda6fc4a285a1a1014e4fc30782278fa62bdc3add75d14b29d4d76253e` | Direct file in upstream git |
| MKE-P37 v15 firmware | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/firmware/mkep37/MKE-P37_015.fwsc> | `280ee7aae59a17c38bc2e854802c7d08f076e51afff13eb5315ad3748476491f` | Direct file in upstream git |
| Starrykey 37 Play v15 firmware | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/firmware/starrykey37play/STARRYKEY-37_PLAY_015.fwsc> | `3ef5d835e88324a925593e1e6959106e16abeabbabf824263803bb236b09224b` | Direct file in upstream git |
| Firmware documentation | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/firmware/FIRMWARE.md> | text file | Direct file in upstream git |
| User manual PDF | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/manual/smk-37-pro-user-manual.pdf> | `738cb672a06387f72361bfdf2964525526bde947c6cc4dea5a4a6f458745caab` | Direct bundled document |
| DAW setup manual PDF | <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/manual/smk-37-pro-daw-setup-manual.pdf> | `cd6f55c74e2c55f641d4e9641fc57608d09185883b4893cdb2e7f92a33711e6f` | Direct bundled document |

## README claims and evidence classification

| Claim | Upstream location | Direct or inference | Evidence and notes |
|---|---|---|---|
| SMK 37 Pro is a MIDI keyboard master controller with FM engine compatible with Yamaha DX7 tone generator. | `README.md` About | Direct upstream claim | README text, no independent verification in this pass. |
| Variants include SMK 37 Elite, MKE-P37, Donner Starrykey 37 Play, and v15 firmwares are different binaries. | `README.md` About | Direct upstream claim plus directly checkable file fact | README states variants and “Inspecting their v15 firmwares, I've found different binary.” SHA-256 hashes above directly confirm the four v15 files differ in HEAD. |
| Official docs are product page, user manual PDF, DAW setup manual PDF. | `README.md` Official Docs | Direct upstream claim | Product pages are external. Two manuals are bundled in git. |
| DAC is Cirrus Logic CS4344-CZZR. | `README.md` Hardware | Direct upstream claim with datasheet citation | Linked datasheet <https://br.mouser.com/datasheet/3/75/1/CS4344_45_48_F2.pdf> returned 200. Independent board verification not performed. |
| Li-Ion charger is AIP4056 compatible with/pointing to TP4056 datasheet. | `README.md` Hardware | Direct upstream claim with datasheet citation | Link redirects to <https://www.lcsc.com/datasheet/C16581.pdf>, returned 200. |
| SoC is JieLi AC7911B8. | `README.md` Hardware | Direct upstream claim with external forum citation | README cites EdCo at <https://www.sequencer.de/synthesizer/threads/m-vave-smk-37-pro-midi-controller-mit-eingebauter-dx7-engine-und-sequenzer.175956/page-3#post-2980924>, returned 200. Earlier C108221-11B8 claim is struck through. |
| Jieli AC79 documentation/SDK/bootloader are relevant. | `README.md` Hardware | Direct citation, relation inferred | README links AC79 docs, Gitee SDK, bootloader tree, but does not prove the product firmware is built from these exact source trees. |
| Internal synthesis engine has six FM operators, DX7 MK1 compatibility with issues/glitches, 32 algorithms, 12-note polyphony, FX. | `README.md` Internal Synthesis Engine | Direct upstream claim | No independent validation in this pass. |
| v15 firmware date 2026-01-26 and “Remains 1.10”. | `firmware/FIRMWARE.md` | Direct upstream claim | File lists four v15 artifacts. Commit `6990ba...` subject “new firmware 15” supports lineage timing. |
| v15 changelog repeats fixes/additions such as wheel calibration, latch toggle, delay UI transitions, OTG name fix, sustain issues. | `firmware/FIRMWARE.md` v15 | Direct upstream claim | These are upstream changelog claims, not independently tested. |
| `.fwsc` files likely use a scheme similar or identical to kagaimiq `newfw`. | `README.md` Hacking | Inference | README says “seem probable”. Treat as hypothesis. |
| Strings such as `btstack_lowpwer_deal` suggest Jieli AC63 BT SDK or similar. | `README.md` Hacking | Inference | README says “possibly suggest”. Treat as hypothesis only. |
| JL_AC79_DevKit V1.0 may be development environment. | `README.md` Hacking | Inference | README says “Possbly” [sic]. Treat as hypothesis only. |

## Firmware docs, no v12-as-v15 substitution

`firmware/FIRMWARE.md` contains sections for firmware 11, 12, 13, 14, and 15. For v15 feasibility, use only the v15 section and four `_015.fwsc` artifacts listed above. Do not treat `firmware/smk37pro/SMK-37_Pro_012.fwsc` or the README's historical unpacking example path `/SMK-37 Pro_012.fwsc` as v15 evidence. That v12 unpacking block is useful only as context for the hypothesized `.fwsc` format.

## Outbound link inventory and status

Status was checked with Python `urllib` HEAD then GET fallback on 2026-08-02. `403 Blocked` and TLS failures are not necessarily content absence, but they are not verified alive by this automated check.

| Source | URL | Status | Notes |
|---|---|---|---|
| `README.md:9` | <https://www.m-vave.com/productinfo/1431195.html> | DEAD: 404 | Product link currently returns Not Found. |
| `README.md:15` | <https://www.cuvave.com/productinfo/1431195.html> | UNVERIFIED: TLS self-signed cert | `CERTIFICATE_VERIFY_FAILED`. Browser/manual verification may still load if certificate accepted. |
| `README.md:21` | <https://www.reddit.com/r/diyelectronics/comments/1dxwom5/how_to_identify_jieli_jl%CF%80_bluetooth_chips> | UNVERIFIED: 403 Blocked | Reddit blocks automated request. |
| `README.md:25` | <https://br.mouser.com/datasheet/3/75/1/CS4344_45_48_F2.pdf> | 200 | Alive. |
| `README.md:38` | <https://datasheet.lcsc.com/lcsc/1809261820_TOPPOWER-Nanjing-Extension-Microelectronics-TP4056-42-ESOP8_C16581.pdf> | 200 via redirect | Final <https://www.lcsc.com/datasheet/C16581.pdf>. |
| `README.md:54` | <https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc?permalink_comment_id=5739103#gistcomment-5739103> | 200 | Alive. |
| `README.md:55` | <https://www.sequencer.de/synthesizer/threads/m-vave-smk-37-pro-midi-controller-mit-eingebauter-dx7-engine-und-sequenzer.175956/page-3#post-2980924> | 200 | Alive. |
| `README.md:56` | <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/> | 200 | Alive. |
| `README.md:57` | <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK> | 200 | Alive. Duplicate in README. |
| `README.md:58` | <https://kagaimiq.github.io/jielie/chips/> | 200 | Alive. |
| `README.md:59` | <https://www.axtekic.com/web/uploads/file/20230313/gNZPgyZMJ87VB3CB0873B102SR6868n8.pdf> | 200 | Alive. |
| `README.md:67` | <https://github.com/Jieli-Tech/fw-Bootloader/tree/main/user_boot/cpu/wl82> | 200 | Alive. |
| `README.md:161` | <https://www.youtube.com/playlist?list=PLYwLyF01evmMiaq1pv3QuYgvn-m5aVVDD> | 200 | Alive. |
| `README.md:178` | <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/MidiSuite.zip> | 200 | Alive. |
| `README.md:179` | <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/MidiSuite.dmg> | 200 | Alive. |
| `README.md:180` | <https://apps.apple.com/us/app/midi-suite/id6737530581> | 200 | Alive. |
| `README.md:181` | <https://resource.m-vave.com/software/app/MidiSuite.apk> | 200 | Alive. |
| `README.md:183` | <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/M-UPGRADE.zip> | 200 | Alive. |
| `README.md:184` | <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/M-UPGRADE.dmg> | 200 | Alive. |
| `README.md:186` | <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/Sinco_Connector.exe> | 200 | Alive. |
| `README.md:192` | <https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc> | 200 | Alive. |
| `README.md:198` | <https://www.reddit.com/r/synthesizers/comments/1kz1m4a/mvave_smk37_pro_pitchmod_wheel_not_working_after/> | UNVERIFIED: 403 Blocked | Reddit blocks automated request. |
| `README.md:199` | <https://www.youtube.com/watch?v=I4OdTniRRtU> | 200 | Alive. |
| `README.md:200` | <https://www.youtube.com/watch?v=DHvQLDJARNc> | 200 | Alive. |
| `README.md:205` | <https://kagaimiq.github.io/jielie/datafmt/newfw.html> | 200 | Alive. |
| `README.md:208` | <https://github.com/kagaimiq/jl-misctools> | 200 | Alive. |
| `README.md:245` | <https://github.com/Jieli-Tech/fw-AC63_BT_SDK/> | 200 | Alive. |
| `README.md:247` | <https://doc.zh-jieli.com/AC79/zh-cn/master/board_description/board_overview/index.html> | 200 | Alive. |
| `LICENSE:3`, `LICENSE:195` | <http://www.apache.org/licenses/>, <http://www.apache.org/licenses/LICENSE-2.0> | 200 | Alive. |

Excluded from README/docs link conclusions: URLs embedded in binary image/PDF XMP metadata such as `http://ns.adobe.com/xap/...`, `http://ns.adobe.com/pdf/1.3/`, and RDF namespaces. These appeared when scanning binary files as text and are not authored lineage citations.

## Open questions / caveats

* GitHub API was unauthenticated and rate-limited, but required endpoints succeeded. Stars/forks/open-issues values are point-in-time.
* External forum/gist pages were checked for reachability, not fully archived or semantically verified line-by-line.
* The product page at `m-vave.com` is dead by HTTP 404 at the time of check. `cuvave.com` failed due TLS verification, not a 404.
* This pass did not reverse-engineer firmware contents beyond hashing included v15 binaries and recording README's upstream unpacking example.

## Verification commands run

```sh
git clone --mirror https://github.com/jonathaslacerda/smk-37-pro-docs.git "$JCODE_SCRATCH_DIR/.../repo.git"
git --git-dir="$JCODE_SCRATCH_DIR/.../repo.git" show-ref
git --git-dir="$JCODE_SCRATCH_DIR/.../repo.git" log --all --date=iso-strict --pretty=format:'%H%x09%aI%x09%an%x09%ae%x09%D%x09%s'
git --git-dir="$JCODE_SCRATCH_DIR/.../repo.git" ls-tree -r --name-only HEAD
python3 scripts embedded in shell to call:
  https://api.github.com/repos/jonathaslacerda/smk-37-pro-docs
  https://api.github.com/repos/jonathaslacerda/smk-37-pro-docs/forks?per_page=100
  https://api.github.com/repos/jonathaslacerda/smk-37-pro-docs/contributors?per_page=100
  https://api.github.com/repos/jonathaslacerda/smk-37-pro-docs/tags?per_page=100
  https://api.github.com/repos/jonathaslacerda/smk-37-pro-docs/branches?per_page=100
sha256sum firmware/smk37pro/SMK-37_Pro_015.fwsc firmware/smk37elite/SMK-37_Elite_015.fwsc firmware/mkep37/MKE-P37_015.fwsc firmware/starrykey37play/STARRYKEY-37_PLAY_015.fwsc sysex/*.syx manual/*.pdf
python3 urllib HEAD/GET link checker over extracted upstream text links
```
