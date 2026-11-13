# secret-vault

> **자율 AI 에이전트 시대의 로컬 시크릿 볼트 데몬 & 격리 실행 러너**  
> 평문 시크릿 파일과 수많은 정규식 가드 훅을 대체하여, 에이전트(LLM)의 `auto 모드` 실행 환경에서도 비밀번호·API 키·인증서를 완벽하게 보호합니다.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()

---

## 📚 목차
- [1. 탄생 배경 및 해결 과제](#1-탄생-배경-및-해결-과제)
- [2. 4대 보안 원칙 & 핵심 기능](#2-4대-보안-원칙--핵심-기능)
- [3. 시스템 아키텍처](#3-시스템-아키텍처)
- [4. 구성 요소](#4-구성-요소)
- [5. 빠른 시작 및 사용 가이드](#5-빠른-시작-및-사용-가이드)
  - [5.1 데몬 구동 (`secret-vaultd`)](#51-데몬-구동-secret-vaultd)
  - [5.2 시크릿 관리 CLI (`secret-vault`)](#52-시크릿-관리-cli-secret-vault)
  - [5.3 격리 실행 러너 (`secret-run`)](#53-격리-실행-러너-secret-run)
  - [5.4 공용 시크릿 모듈 연동](#54-공용-시크릿-모듈-연동)
- [6. 에이전트 상호작용 프로토콜 (Missing Secret Card)](#6-에이전트-상호작용-프로토콜-missing-secret-card)
- [7. 테스트 및 검증](#7-테스트-및-검증)
- [8. 설계 문서 및 참고 자료](#8-설계-문서-및-참고-자료)

---

## 1. 탄생 배경 및 해결 과제

자율 코딩 에이전트(Claude Code, Antigravity 등)가 `auto 모드`로 터미널과 파일을 제어하는 환경에서, 홈 디렉터리에 상시 보관되던 평문 시크릿 파일(`secrets.json`)은 심각한 보안 딜레마를 야기했습니다:

1. **디스크 평문 노출**: 파일 하나만 열려도 수십 개 서비스의 비밀번호가 일괄 유출됨.
2. **가드 훅의 유지보수 피로도**: 파일 읽기, 검색, 실행을 막기 위해 수많은 정규식 훅(`guard-hook.py`)을 덧대어야 함.
3. **일상적인 오탐(False Positive)**: `git grep`이나 주석에 키 이름이 들어간 정상 작업까지 훅에 의해 차단됨.
4. **완제품 CLI 및 인증서 파일 지원 한계**: `gh` 같은 기계어 바이너리나 GCP JSON 키 파일 등 다양한 자격증명 형태를 안전하게 주입할 단일 체계 부재.

`secret-vault`는 **"디스크 평문 제로 + 3대 시크릿 격리 주입 + RCE 원천 차단 + 실시간 스트림 마스킹"**을 통해 이 문제를 근본적으로 해결합니다.

---

## 2. 4대 보안 원칙 & 핵심 기능

### ① 디스크 평문 제로 (Zero Plaintext on Disk)
- 디스크 상에 평문 시크릿 파일이 상시 존재하지 않습니다.
- OS Keyring 및 퍼미션 `0600`의 AES-256 암호화 저장소(`vault.enc`)를 사용하여 부팅 시 메모리(RAM)에만 시크릿을 유지합니다.

### ② 3대 시크릿 주입 엔진
- **문자열 환경변수 주입**: 프로세스 실행 시 해당 자식 프로세스의 `os.environ`에만 일시 주입합니다.
- **인증서/JSON 파일 주입**: RAM 기반 가상 파일시스템(Linux `/dev/shm`, Windows temp, `0600`)에 실행 순간에만 생성하고, 프로세스 종료 즉시 **Shred & Unlink로 영구 파기**합니다.
- **로컬 인증 프록시**: 스크립트에 키를 넘기지 않고 로컬 프록시가 HTTP 요청 헤더에 실제 키를 대리 주입합니다.

### ③ 임의 코드 실행(RCE) 원천 차단
- 에이전트가 환경변수나 RAM 파일을 빼돌리기 위해 시도하는 인라인 인터프리터(`python -c`, `bash -c`, `sh -c`, `cmd.exe /c`, `powershell -Command` 등) 및 임시 폴더(`/tmp/*.py`, `%TEMP%/*.py`) 스크립트 실행을 입구에서 거부합니다.
- 시스템 표준 바이너리(`/usr/bin/gh` 등) 및 공식 스크립트 경로(`~/.claude/bin/*`, 현재 레포 내 스크립트)만 실행을 허용합니다.

### ④ 최후의 안전망: 실시간 출력 마스킹 (Sanitizer)
- 자식 프로세스가 표준 출력(stdout)이나 표준 에러(stderr)로 시크릿을 출력하더라도, 실시간 스트림 감시를 통해 `[REDACTED_SECRET]`으로 자동 마스킹합니다.
- 청크 경계에 걸친 분할 출력 및 Base64 파생 변종까지 탐지하여 차단합니다.

---

## 3. 시스템 아키텍처

```
+─────────────────────────────────────────────────────────────────────────────+
| [ 사용자 / 자율 코딩 에이전트 (auto 모드) ]                                  |
|        │                                                                    |
|        ├─ (1) 시크릿 관리: python claude/bin/secret-vault.py <set|list|...> |
|        └─ (2) 격리 실행:   python claude/bin/secret-run.py <명령어...>       |
|                                                                             |
|                                    │ (IPC 통신)                             |
|                                    ▼                                        |
| [ IPC 통신 레이어 ]                                                         |
|   - Linux: Unix Domain Socket (/run/user/<UID>/secret-vault.sock, 0600)     |
|   - Windows Fallback: 127.0.0.1 TCP + 0600 접속 토큰 파일                   |
|                                    │                                        |
|                                    ▼                                        |
| [ 문지기 데몬: secret-vaultd.py ]                                           |
|   - 인메모리 금고: OS Keyring / 메모리(RAM) 보관                            |
|   - RCE 방어선: python -c, bash -c, 임시 스크립트 전면 거부                 |
|   - 화이트리스트 검증: 시스템 바이너리(gh 등) 및 레포/공식 스크립트만 허용   |
|   - 2대 주입 엔진:                                                          |
|       * 문자열: 자식 프로세스 os.environ에만 일시 주입                       |
|       * 파일/인증서: RAM 가상 디스크(/dev/shm, 0600) 임시 생성              |
|   - 최후 안전망 (Sanitizer): stdout/stderr 실시간 스트림 마스킹             |
|                                    │ (fork & exec)                          |
|                                    ▼                                        |
| [ 격리 실행 대상 프로세스 ] ──(종료 즉시 RAM 파일 Shred & Unlink 파기)       |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 4. 구성 요소

| 파일 경로 | 컴포넌트 | 주요 역할 |
| :--- | :--- | :--- |
| `claude/bin/secret-vaultd.py` | **볼트 데몬 (Daemon)** | IPC 소켓 서버, OS Keyring 연동, 시크릿 메모리 보관, 프로세스 격리 실행, 스트림 마스킹 |
| `claude/bin/secret-vault.py` | **관리자 CLI (Admin)** | 대화형 키 등록/조회/삭제 도구 (`list`, `set`, `set-file`, `delete`, `status`). 값은 절대 미출력 |
| `claude/bin/secret-run.py` | **격리 실행 러너 (Runner)** | `secret-run <명령어...>` 형태로 안전 실행. 데몬 중계 및 마스킹 스트림 출력, 종료 코드 동기화 |
| `claude/bin/secret-vault-service.py` | **자동 기동 설치 (Service)** | systemd 사용자 유닛 + linger 등록/해제. 사용자가 직접 실행할 때만 등록 |
| `tests/test_secret_vault.py` | **통합 테스트 슈트** | 데몬, CLI, 러너, RCE 차단, 마스킹, 생명주기 등 34개 이상의 단위 및 통합 테스트 시나리오 |

---

## 5. 빠른 시작 및 사용 가이드

### 5.1 데몬 구동 (`secret-vaultd`)

데몬은 스스로 시스템 서비스를 등록하지 않습니다. 평소에는 수동으로 구동하고, 재부팅 뒤 자동 기동이 필요하면 아래 [자동 기동](#자동-기동-systemd-사용자-유닛)처럼 사용자가 직접 사용자 유닛을 등록합니다.

```bash
# 1. 포그라운드 실행 (로그 및 디버깅 콘솔)
python claude/bin/secret-vaultd.py --foreground

# 2. 백그라운드 수동 실행
python claude/bin/secret-vaultd.py

# 3. 사용자 지정 소켓 경로 구동
python claude/bin/secret-vaultd.py --socket /path/to/custom.sock --foreground

# 4. 실행 중인 데몬 종료
python claude/bin/secret-vaultd.py --stop
```

#### 헤드리스 서버: TPM2 마스터 키 (`--key-backend tpm2`)

화면 없는 서버는 잠금 해제할 OS Keyring이 없어 기본값으로는 0600 키 파일(`master.key`)을 씁니다. `--key-backend tpm2`를 주면 마스터 키를 `systemd-creds --user`로 host+TPM2에 봉인한 `vault-key.cred`에 보관하므로, 사람 없이 재부팅해도 데몬이 저장소를 열 수 있고 디스크만 떼어 가서는 풀 수 없습니다.

```bash
python claude/bin/secret-vaultd.py --key-backend tpm2 --foreground
```

- 필요 조건: `systemd-analyze has-tpm2`가 `yes`여야 합니다. `partial`이고 `libtss2-rc.so.0`이 없다고 나오면 `sudo apt install libtss2-rc0t64`로 설치합니다.
- 처음 켤 때 기존 `master.key`나 Keyring 키가 있으면 TPM2로 옮겨 봉인을 확인한 뒤 이전 키를 지웁니다.
- 봉인을 풀지 못하면 키 파일로 물러서지 않고 기동을 멈춥니다. 저장소는 있는데 키가 없으면 새 키를 만들지 않습니다.
- **복구 주의**: TPM 초기화, 메인보드 교체, OS 재설치 뒤에는 저장소를 영영 열 수 없습니다. 원본 시크릿은 따로 보관해 다시 등록할 수 있게 해 둡니다.

#### 자동 기동 (systemd 사용자 유닛)

재부팅 뒤 로그인하지 않아도 데몬이 뜨게 하려면 설치 스크립트를 직접 실행합니다. root가 필요 없는 사용자 유닛(`~/.config/systemd/user/secret-vaultd.service`)을 만들고 `loginctl enable-linger`를 켭니다. 마스터 키 방식은 기본이 `tpm2`입니다.

```bash
# 바꾸지 않고 유닛 내용과 실행할 명령만 보기
python claude/bin/secret-vault-service.py install --dry-run

# 등록하고 바로 시작 (기존 master.key가 있으면 이때 TPM2로 옮겨진다)
python claude/bin/secret-vault-service.py install

# 상태 확인 / 해제
python claude/bin/secret-vault-service.py status
python claude/bin/secret-vault-service.py uninstall
```

- 유닛은 이 스크립트 옆의 `secret-vaultd.py`를 실행합니다. 다른 사본을 쓰려면 `--daemon <경로>`를 줍니다.
- 비정상 종료 시 5초 뒤 다시 띄웁니다(`Restart=on-failure`). 로그는 `journalctl --user -u secret-vaultd`로 봅니다.

### 5.2 시크릿 관리 CLI (`secret-vault`)

사용자(인간 개발자)가 터미널에서 직접 키를 안전하게 등록·조회·삭제합니다. 실제 시크릿 값은 터미널 화면에 절대 노출되지 않습니다.

```bash
# 1. 데몬 연결 상태 확인
python claude/bin/secret-vault.py status
# [OK] secret vault daemon is running (pid=1234, secrets=3, uptime=120s). socket=...

# 2. 문자열 API 키 등록 (터미널 숨김 입력)
python claude/bin/secret-vault.py set DEEPSEEK_API_KEY
# Input Value (Hidden): 
# [OK] 'DEEPSEEK_API_KEY' registered in OS Keyring.

# 3. 인증서/JSON 파일 등록 (Keyring 암호화 적재 후 원본 파일 안전 삭제 가능)
python claude/bin/secret-vault.py set-file GCP_SERVICE_ACCOUNT ~/Downloads/service-account.json
# [OK] 'GCP_SERVICE_ACCOUNT' file encrypted and registered. Original file can be removed.

# 4. 등록된 키 목록 확인 (키 이름과 타입만 확인 가능, 값은 미출력)
python claude/bin/secret-vault.py list
# NAME                             TYPE    
# DEEPSEEK_API_KEY                 string  
# GCP_SERVICE_ACCOUNT              file    

# 5. 키 삭제
python claude/bin/secret-vault.py delete DEEPSEEK_API_KEY
# [OK] 'DEEPSEEK_API_KEY' deleted.
```

### 5.3 격리 실행 러너 (`secret-run`)

에이전트나 스크립트는 시크릿을 직접 읽지 않고, `secret-run`을 통해 명령어를 실행합니다. 데몬이 명령어의 안전성을 검증한 후 자식 프로세스에만 시크릿을 주입합니다.

```bash
# 1. 완제품 CLI 도구 실행 (환경변수 안전 주입)
python claude/bin/secret-run.py gh pr create --title "작업 내용"

# 2. 허용된 공식/레포 스크립트 실행
python claude/bin/secret-run.py python path/to/my_script.py

# 3. 파일형 시크릿이 주입되는 도구 실행
python claude/bin/secret-run.py litestream replicate
```

#### ❌ 탈취 시도 차단 예시 (RCE 방어선 작동)
```bash
# 인라인 파이썬 코드 실행 시도 차단
python claude/bin/secret-run.py python -c "import os; print(os.environ)"
# [DENIED] 인라인 코드 실행(-c)은 허용되지 않는다

# 셸 인라인 코드 실행 시도 차단
python claude/bin/secret-run.py bash -c "echo $DEEPSEEK_API_KEY"
# [DENIED] 인라인 코드 실행(-c)은 허용되지 않는다

# 임시 폴더의 악성 스크립트 실행 차단
python claude/bin/secret-run.py python /tmp/steal.py
# [DENIED] 임시 폴더의 스크립트/실행 파일은 실행할 수 없다
```

### 5.4 공용 시크릿 모듈 연동

기존 Python 공용 모듈(`secrets_client.py`)은 `secret-run`에 의해 주입된 환경변수를 최우선으로 읽도록 하위 호환성을 유지합니다:

```python
import os

def get(key: str) -> str:
    # 1. secret-run에 의해 환경변수로 주입된 값 (최우선)
    env_val = os.environ.get(key.upper()) or os.environ.get(key)
    if env_val:
        return env_val

    raise RuntimeError(f"시크릿을 찾을 수 없습니다: {key}")
```

---

## 6. 에이전트 상호작용 프로토콜 (Missing Secret Card)

에이전트가 작업을 수행하다가 필요한 시크릿이 없거나 만료되었을 때, 임의로 에러를 내거나 파일을 검색하지 않고 사용자에게 정중히 입력을 요청하는 표준 템플릿입니다:

> [!IMPORTANT] 시크릿 등록 필요: `{KEY_NAME}`
> 
> 해당 작업을 수행하려면 **`{KEY_NAME}`** 시크릿이 필요합니다.
> - **용도**: `{description}`
> - **필요 도구**: `{used_by}`
> - **발급 위치**: [{service_name} 콘솔]({provider_url})
> 
> 터미널에서 아래 명령어를 실행하여 등록해 주세요:
> ```bash
> python claude/bin/secret-vault.py set {KEY_NAME}
> ```
> *(파일 형태인 경우: `python claude/bin/secret-vault.py set-file {KEY_NAME} <파일경로>`)*

---

## 7. 테스트 및 검증

프로젝트 루트에서 `unittest`를 통해 전체 테스트를 실행합니다:

```bash
# 전체 테스트 실행 (34개 이상 시나리오)
python -B -m unittest tests.test_secret_vault -v

# 개별 컴포넌트 단위 테스트
python -B -m unittest tests.test_secret_vault.SanitizerUnitTest -v
python -B -m unittest tests.test_secret_vault.StoreUnitTest -v
python -B -m unittest tests.test_secret_vault.PolicyUnitTest -v
```

### 테스트 검증 항목
- 관리자 CLI `set`, `list`, `delete`, `set-file` 기능 및 시크릿 값 미노출 보장
- 문자열 환경변수 자식 프로세스 격리 주입 검증
- 파일형 시크릿 RAM 생성 및 종료 후 shred/unlink 영구 파기 검증
- RCE 차단(`python -c`, `bash -c`, 임시 스크립트, `env` 래퍼 우회 등) 검증
- 스트림 실시간 출력 마스킹(청크 경계 분할 및 Base64 파생형 포함) 검증
- 데몬 코드가 스스로 서비스를 등록하지 않음, 설치 스크립트의 유닛 내용과 `--dry-run` 무변경 검증
- TPM2 마스터 키: 봉인 파일 0600, 기존 키 이전 후 삭제, 봉인 해제 실패 시 키 파일로 물러서지 않음, 키 없는 기존 저장소 재생성 거부

---

## 8. 설계 문서 및 참고 자료

- **[엔지니어링 상세 설계서](docs/secret-vault/secret-vault-daemon-design.md)**: 소켓 프로토콜, 키 라이프사이클, 에이전트 가이드 프로토콜 상세 사양
- **[기술 에세이: 《에이전트로부터 시크릿을 지키는 법》](docs/secret-vault/the-art-of-secret-defense.md)**: 7번의 대화를 통해 완성된 아키텍처 배경과 설계 결정 기록(ADR)
- **[코어 구현 계획서](docs/superpowers/plans/2026-11-09-secret-vault-core.md)**: 시크릿 볼트 코어 작업 태스크 및 단계별 검증 계획
- **[온라인 전자책](https://golony6449.github.io/secret-defense/)**: GitHub Pages에 출판된 공식 웹 문서

---

## 📄 라이선스

MIT License
