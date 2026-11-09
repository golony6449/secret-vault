# 로컬 시크릿 볼트 데몬 & 격리 러너 설계서 (Secret Vault Daemon & Runner)

- **작성일**: 2026-11-08 (v2.1 개정: 키 라이프사이클 및 에이전트 가이드 프로토콜 추가)
- **상태**: 승인 및 설계 확정
- **대상 환경**: Linux 서버 (1차 구축), Windows PC (호환성 유지)

---

## 1. 배경 및 문제 정의

### 1.1 배경
- 클라우드 기반 시크릿 매니저(GCP Secret Manager 등)는 API 호출 레이턴시(수십~수백 ms)와 오프라인/네트워크 단절 시 가용성 문제로 인해 채택하지 않음.
- 로컬 환경에서 시크릿을 집중 관리하고 공용 모듈을 통해 주입하는 방식을 채택함.

### 1.2 기존 방식의 한계 (평문 파일 + 가드 훅)
1. **디스크 평문 노출 위험**: 홈 디렉터리에 평문 파일(`secrets.json`)이 상시 존재하여 유출 위험 상존.
2. **다중 훅 유지보수 피로도**: 에이전트(Claude Code, Antigravity)가 평문 파일을 읽거나 출력하지 못하도록 명령어 파싱, 파라미터 감시, 파일 경로 차단 등 수많은 가드 훅(`guard-hook.py` 등)을 덧대어야 함.
3. **오탐(False Positive) 발생**: 정상적인 명령어(`git grep`, 주석에 파일명이 포함된 스크립트 실행 등)까지 훅에 의해 차단되는 일상적인 개발 방해 발생.
4. **대량 유출(All-or-Nothing) 취약점**: 파일 1개만 열리면 등록된 모든 서비스의 시크릿 수십 개가 일괄 노출됨.

### 1.3 설계 진화 과정 및 극복된 맹점 (Architecture Decision Records)
- **맹점 1 (스크립트 해시/Git 커밋 검증의 무력화)**:
  - *반론*: 에이전트가 `auto 모드`로 동작하므로 코드 수정은 물론 `git commit`까지 스스로 수행할 수 있음. 또한 LLM 연동 스크립트가 수십 개에 달해 해시 관리가 불가능함.
  - *해결*: 스크립트 코드가 바뀌든 말든, 스크립트 프로세스에 시크릿을 직접 넘겨주지 않거나 격리된 자식 프로세스로만 한정 주입하는 아키텍처 채택.
- **맹점 2 (완제품 CLI 바이너리의 프록시 불가)**:
  - *반론*: `gh`(GitHub CLI), `litestream`(GCS 백업) 같은 외부 완제품 바이너리는 코드를 고쳐서 프록시 URL로 바꿀 수 없고 환경변수 주입이 필수적임.
  - *해결*: 프록시 단일화 대신, **"바이너리 화이트리스트 러너"**를 도입하여 시스템 완제품 바이너리에만 환경변수를 주입하고, 임의 인터프리터(`python -c`, `bash` 등)의 실행을 원천 차단.
- **맹점 3 (인증서 및 파일 형태 자격증명)**:
  - *반론*: GCP 서비스 계정 JSON 키(`GOOGLE_APPLICATION_CREDENTIALS`), Cloudflare DNS 자격증명(`cloudflare.ini`), mTLS 인증서 등 파일 경로를 요구하는 자격증명이 다수 존재.
  - *해결*: 디스크에 평문 파일을 두지 않고, **RAM 디스크(`/dev/shm`, 퍼미션 0600)**에 실행 순간에만 임시 가상 파일을 생성하고 프로세스 종료 즉시 완전 파기(Unlink/Shred)하는 메커니즘 도입.

---

## 2. 최종 시스템 아키텍처

```
+───────────────────────────────────────────────────────────────────────────────────+
| Linux 서버 (User Session)                                                         |
|                                                                                   |
|  [ 에이전트 (Claude 등) ] ── (auto 모드로 자유롭게 코드 수정 & Git 커밋 가능)       |
|         │                                                                         |
|         │ 1. CLI/스크립트 실행 요청 (secret-run)                                  |
|         ▼                                                                         |
|  [ Unix Domain Socket (/run/user/<UID>/secret-vault.sock) ]                       |
|         │                                                                         |
|         ▼ (커널 레벨 SO_PEERCRED 검증)                                            |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  | 문지기 데몬 (Secret Vault Daemon: secret-vaultd)                            |  |
|  |  - systemd --user 백그라운드 상시 구동                                      |  |
|  |  - 부팅 시 OS Keyring에서 복호화하여 메모리(RAM)에만 안전 보관               |  |
|  |                                                                             |  |
|  |  [보안 검증 레이어]                                                         |  |
|  |   ① 임의 인터프리터(python -c, bash, sh) 실행 요청 원천 차단                |  |
|  |   ② 허용된 바이너리/공식 도구만 실행 승인                                    |  |
|  |                                                                             |  |
|  |  [2대 주입 엔진]                                                            |  |
|  |   가. 문자열 시크릿 주입  -> 자식 프로세스의 env(환경변수)로만 주입         |  |
|  |   나. 인증서/키 파일 주입 -> RAM 가상 디스크(/dev/shm, 0600)에 일시 생성     |  |
|  |                                                                             |  |
|  |  [최후 안전망]                                                              |  |
|  |   출력 스트림(stdout/stderr) 실시간 감시 -> 시크릿 패턴 [REDACTED] 강제 치환 |  |
|  +──────────────────────────────────────┬──────────────────────────────────────+  |
|                                         │ (프로세스 포크 & 실행)                  |
|         ┌───────────────────────────────┴───────────────────────────────┐         |
|         ▼                                                               ▼         |
|  [ 완제품 CLI 도구 ]                                            [ Python 도구 ]   |
|  (gh, litestream 등)                                            (사내 스크립트)   |
|   - 환경변수 주입 실행                                           - RAM 파일 주입  |
|   - 바이너리 자체는 기계어라 변조 불가                           - 실행 종료 즉시 |
|                                                                    RAM 파일 파기  |
+───────────────────────────────────────────────────────────────────────────────────+
```

---

## 3. 핵심 보안 및 실행 메커니즘

### 3.1 OS Keyring 기반 인메모리 금고
- 디스크 상의 평문 `secrets.json` 완전 제거.
- Linux Secret Service / Keyutils를 통해 암호화 저장되며, 오직 `secret-vaultd` 데몬만 부팅 시 마스터 키로 열어 **메모리(RAM)에만 유지**.

### 3.2 유형별 안전 주입 메커니즘
- **문자열 시크릿**: 데몬이 자식 프로세스를 `fork & exec`할 때 해당 자식 프로세스의 `os.environ`에만 일시 주입.
- **인증서/JSON 파일**: RAM 디스크(`/dev/shm/secret-vault/<UUID>.json`, 퍼미션 `0600`)에 생성 후 경로 주입, 프로세스 종료 즉시 Shred & Unlink.

### 3.3 임의 코드 실행(RCE) 차단 (러너 방어선)
- `python -c "..."`, `bash -c "..."`, 임의의 `/tmp/*.py` 실행 요청은 입구에서 전면 거부.
- 오직 시스템 등록 바이너리(`/usr/bin/gh` 등) 및 공식 스크립트 경로(`~/.claude/bin/*`)만 허용.

### 3.4 최후의 안전망: 출력 실시간 마스킹 (Sanitizer)
- 자식 프로세스의 stdout/stderr 스트림을 실시간 감시하여 주입된 시크릿 패턴 감지 시 `[REDACTED_SECRET]`으로 자동 치환.

---

## 4. 컴포넌트별 상세 사양

### 4.1 데몬 (`secret-vaultd.py`)
- UDS 소켓 서버 (`/run/user/<UID>/secret-vault.sock`, 퍼미션 `0600`).
- Keyring 연동, RAM 가상 파일 생명주기 관리, 프로세스 포크 및 환경변수 주입.

### 4.2 러너 CLI (`secret-run`)
- 사용 예시:
  ```bash
  secret-run gh pr create --title "..."
  secret-run litestream replicate
  secret-run python path/to/my_script.py --task task-123
  ```

### 4.3 공용 모듈 (`secrets_client.py`) 하위 호환성
```python
import os
import sys

def get(key: str) -> str:
    # 1. secret-run에 의해 환경변수로 주입된 경우 (최우선)
    env_val = os.environ.get(key.upper()) or os.environ.get(key)
    if env_val:
        return env_val

    # 2. Windows PC: 기존 로컬 JSON + 훅 방식 유지
    if sys.platform == "win32":
        return _get_from_windows_json(key)

    raise RuntimeError(f"시크릿을 찾을 수 없습니다: {key}")
```

---

## 5. 키 관리 및 신규 도구 추가 가이드 (Key Management)

향후 새로운 CLI 도구, LLM API, 클라우드 서비스가 계속 추가될 때를 대비하여, **"에이전트가 직접 시크릿을 다루지 않고도 사용자에게 올바르게 안내할 수 있는 표준 관리 체계"**를 정의한다.

### 5.1 관리자 CLI (`secret-vault`) 인터페이스
사용자(인간)가 터미널에서 직접 시크릿을 안전하게 등록·조회·삭제하는 전용 대화형 도구:

```bash
# 1. 등록된 키 목록 확인 (키 이름만 출력, 실제 값은 절대 출력하지 않음)
secret-vault list

# 2. 문자열 시크릿 등록/수정 (화면에 입력값 마스킹)
secret-vault set DEEPSEEK_API_KEY
# Input Value (Hidden): ********************************
# [OK] 'DEEPSEEK_API_KEY' registered in OS Keyring.

# 3. 파일형 시크릿(인증서/JSON) 등록 (파일 내용을 Keyring에 암호화 적재)
secret-vault set-file GCP_SERVICE_ACCOUNT ~/Downloads/service-account.json
# [OK] 'GCP_SERVICE_ACCOUNT' file encrypted and registered. Original file can be removed.

# 4. 키 삭제
secret-vault delete OLD_API_KEY
```

### 5.2 시크릿 메타데이터 매니페스트 (`secrets-manifest.yaml`)
에이전트가 시스템에 어떤 키가 존재해야 하는지, 어디서 발급받아야 하는지 알 수 있도록 돕는 공개 메타데이터 (비밀값 없음):

```yaml
# ~/.claude/config/secrets-manifest.yaml
secrets:
  DEEPSEEK_API_KEY:
    type: string
    env_name: DEEPSEEK_API_KEY
    description: "DeepSeek Coder / Chat API 인증 키"
    provider_url: "https://platform.deepseek.com/api_keys"
    used_by: ["llm-run.py", "llm-loop.py"]

  QWEN_API_KEY:
    type: string
    env_name: DASHSCOPE_API_KEY
    description: "Qwen DashScope API 키 (코드 리뷰용)"
    provider_url: "https://dashscope.console.aliyun.com/apiKey"
    used_by: ["llm-review.py"]

  GCP_SERVICE_ACCOUNT:
    type: file
    env_name: GOOGLE_APPLICATION_CREDENTIALS
    target_format: json
    description: "GCP 서비스 계정 키 (GCS 백업)"
    provider_url: "https://console.cloud.google.com/iam-admin/serviceaccounts"
    used_by: ["litestream"]

  GH_TOKEN:
    type: string
    env_name: GH_TOKEN
    description: "GitHub CLI PR 생성 및 저장소 연동용 PAT"
    provider_url: "https://github.com/settings/tokens"
    used_by: ["/usr/bin/gh"]
```

---

## 6. 에이전트의 사용자 요청 표준 프로토콜 (Agent-Human Protocol)

에이전트(Claude/Antigravity)가 작업을 수행하다가 **필요한 시크릿이 누락되었거나 만료되었을 때**, 임의로 에러를 내거나 파일을 뒤지지 않고 **사용자에게 정중하고 명확하게 입력을 요청하는 표준 행동 양식**을 규정한다.

### 6.1 에이전트 가이드 원칙
1. **에이전트는 시크릿 값을 묻거나 받지 않는다**: 사용자가 채팅창에 키를 적어주면 안 되며, 사용자가 터미널 CLI를 통해 직접 OS Keyring에 넣도록 유도한다.
2. **반드시 발급처 링크와 등록 명령어 한 줄을 제공한다**: 사용자가 즉시 복사-붙여넣기(Tab)로 실행할 수 있는 명령어 형태로 제시한다.

### 6.2 표준 요청 템플릿 (Markdown Alert)
에이전트는 시크릿 부재 시 다음과 같은 정형화된 블록을 사용자에게 응답한다:

> [!IMPORTANT] 시크릿 등록 필요: `{KEY_NAME}`
> 
> 해당 작업을 수행하려면 **`{KEY_NAME}`** 시크릿이 필요합니다.
> - **용도**: `{description}`
> - **필요 도구**: `{used_by}`
> - **발급 위치**: [{service_name} 콘솔]({provider_url})
> 
> 터미널에서 아래 명령어를 실행하여 등록해 주세요:
> ```bash
> secret-vault set {KEY_NAME}
> ```
> *(파일 형태인 경우: `secret-vault set-file {KEY_NAME} <파일경로>`)*

---

## 7. 단계별 롤아웃 로드맵

| 단계 | 작업 내용 | 검증 기준 |
| :--- | :--- | :--- |
| **Phase 1** | **설계 확정 및 메타데이터 정의**<br>- `secrets-manifest.yaml` 스키마 작성<br>- 에이전트 가이드 프로토콜 확정 | 현재 단계 완료 |
| **Phase 2** | **서버 데몬 및 관리자 CLI 구현**<br>- `secret-vaultd.py` (UDS + Keyring + RAMFS)<br>- `secret-vault` (대화형 등록/조회 CLI)<br>- `secret-run` CLI (바이너리 화이트리스트 + 마스킹) | `secret-vault set`으로 키 등록 확인, 임의 `python -c` 실행 차단 확인 |
| **Phase 3** | **공용 모듈 연동 및 테스트**<br>- `secrets_client.py` 환경변수 우선 로드 로직 배포<br>- Python 도구, `gh`, `litestream` 연동 테스트 | 누락 시 에이전트 안내 템플릿 정상 동작 확인 |
| **Phase 4** | **서버 배포 및 완전 전환**<br>- `systemd --user` 서비스 등록<br>- 서버 내 기존 평문 파일 파기<br>- 서버 내 가드 훅 비활성화 | 훅 없이도 오탐 제로 & 완전 격리 달성 |
