# GitHub Pages 배포 가이드

> **이 저장소(`smk37pro-acidsound-mod`)에서의 실제 배포**: 저장소 루트의
> `.github/workflows/deploy-pages.yml`이 `public/`을 `patch-set-editor/` 하위
> 경로로 스테이징해 배포합니다. 사이트 주소는
> `https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/` 입니다.
> 아래 방법들은 이 폴더를 별도 저장소로 분리했을 때 적용하는 독립 배포 절차입니다.

이 프로젝트는 빌드가 없는 순수 정적 사이트이므로 GitHub Pages 배포 방법이 여러
가지입니다. 가장 추천하는 방법은 **GitHub Actions 자동 배포**입니다.

## 방법 A — GitHub Actions 자동 배포 (추천)

`.github/workflows/deploy-pages.yml`이 이미 포함되어 있습니다. `main` 브랜치에
push할 때마다 테스트(`node --test`) 후 `public/`을 GitHub Pages로 배포합니다.

1. **저장소 생성**: 이 폴더의 내용을 새 GitHub 저장소로 push합니다.

   ```bash
   git init
   git add .
   git commit -m "SMK-37 Patch Set Editor (GitHub Pages)"
   git branch -M main
   git remote add origin https://github.com/<your-name>/<repo-name>.git
   git push -u origin main
   ```

2. **Actions 활성화**: GitHub 저장소의 **Settings → Actions → General →
   Workflow permissions**에서 "Read and write permissions"가 선택되어 있는지
   확인합니다 (또는 workflow 파일 push 시 GitHub가 자동으로 권한을 요청).

3. **Pages 활성화**: **Settings → Pages → Build and deployment → Source**에서
   **GitHub Actions**를 선택합니다. 첫 배포가 실행되면 몇 분 내로 사이트가
   `https://<your-name>.github.io/<repo-name>/`에 뜹니다.

> 참고: `actions/deploy-pages`는 `github-pages` environment를 자동 생성하며,
> workflow의 `permissions: pages: write, id-token: write`로 인증합니다. 별도의
> Personal Access Token은 필요 없습니다.

## 방법 B — 브랜치 직접 배포 (Actions 없이)

1. 저장소 **Settings → Pages → Build and deployment → Source**에서
   **Deploy from a branch** 선택.
2. Branch를 `main`, 폴더를 `/ (root)`로 지정하고 Save.
3. `public/`이 아니라 저장소 **루트**가 사이트 루트가 되므로, 이 방법을 쓸 거라면
   `public/` 안의 파일들을 저장소 루트로 옮겨야 합니다 (index.html, styles.css,
   app.js, sysex.mjs, samples/).
   - 저장소 루트에도 `.nojekyll`이 이미 들어 있으므로 Jekyll 처리 없이 그대로
     서빙됩니다.
4. 몇 분 후 `https://<your-name>.github.io/<repo-name>/`에서 확인.

## 방법 C — `docs/` 폴더 배포

1. `public/`의 내용을 `docs/`로 복사.
2. **Settings → Pages → Deploy from a branch → `main` → `/docs`** 선택.

## 방법 D — gh-pages 브랜치 수동 push

정적 파일만 필요하다면 `public/`을 `gh-pages` 브랜치로 push하는 방법도 있습니다.

```bash
git subtree push --prefix public origin gh-pages
```

또는 저장소 Settings → Pages → Source에서 `gh-pages` 브랜치를 선택합니다.

---

## 배포 후 확인 체크리스트

1. **URL**: `https://<your-name>.github.io/<repo-name>/` 접속.
2. **샘플 로드**: `검증 세트 불러오기` / `FM Drum Preset 불러오기`가 정상 동작하는지
   (네트워크 탭에서 manifest·syx 200 확인).
3. **Web MIDI**: Chrome에서 `Web MIDI 연결` 클릭 → SysEx 권한 프롬프트 → 장치 선택.
   - Web MIDI는 secure context(HTTPS)에서만 노출됩니다. GitHub Pages는 HTTPS이므로 OK.
4. **전송**: `16개 Patch 전송` 후 Pad 1–16 청취.

## 자주 하는 실수

- **Safari/iOS에서는 Web MIDI가 없습니다.** Desktop Chrome 사용을 안내하세요.
- **권한 프롬프트가 안 뜨는 경우**: Chrome 주소창의 자물쇠 → 사이트 설정에서
  "MIDI" 권한을 확인하거나 `chrome://settings/content/midiDevices`를 확인하세요.
- **404**: 모든 자산 참조는 상대 경로입니다. 하위 경로 배포에서도 깨지지 않습니다.
  절대 경로(`/app.js`)로 고치지 마세요.
- **캐시**: `index.html`의 `app.js?v=...` 쿼리를 버전 변경 시 갱신하세요.

## 사용자 지정 도메인

1. 저장소 **Settings → Pages → Custom domain**에 도메인 입력 → Save.
2. DNS 공급자에서 CNAME 레코드(`<repo-name>` → `<your-name>.github.io`) 또는
   A 레코드(GitHub Pages IP 4개)를 설정.
3. GitHub가 HTTPS 인증서를 자동 발급합니다 (몇 분~수십 분).
