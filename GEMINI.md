# GEMINI.md

이 문서는 Gemini(Antigravity) 에이전트가 `secret-vault` 프로젝트에서 안전하고 일관되게 작업할 수 있도록 작성된 프로젝트 작업 지침 및 아키텍처 가이드입니다.

---

## 1. 개요 및 핵심 철학

`secret-vault`는 자율 AI 코딩 에이전트(Claude Code, Antigravity 등)가 `auto 모드`로 터미널과 파일을 제어하는 환경에서도 비밀번호(API 키, 토큰, 인증서)를 안전하게 보호하기 위해 개발된 **로컬 시크릿 볼트 데몬(`secret-vaultd`) & 격리 실행 러너(`secret-run`)**입니다.

기존의 "평문 시크릿 파일(`secrets.json`) + 수많은 정규식 가드 훅(`guard-hook.py`)" 구조가 지닌 디스크 평문 노출 위험과 일상적인 오탐(False Positive) 방해를 극복하고, 다음의 4대 보안 원칙을 실현합니다:

1. **디스크 평문 제로 (Zero Plaintext on Disk)**:
   - 디스크에 평문 시크릿 파일이 상시 존재하지 않습니다.
   - OS Keyring 및 AES-256 암호화 저장소(`0600`)를 활용하여 부팅 시 메모리(RAM)에만 시크릿을 유지합니다.
2. **3대 시크릿 주입 엔진**:
   - **문자열 환경변수 주입**: 프로세스 실행 시 해당 자식 프로세스의 `os.environ`에만 일시 주입합니다.
   - **인증서/JSON 파일 주입**: RAM 기반 가상 파일시스템(Linux `/dev/shm`, Windows temp, `0600`)에 실행 순간에만 생성하고 종료 즉시 **Shred & Unlink로 영구 소멸**시킵니다.
   - **로컬 인증 프록시**: 스크립트에 키를 넘기지 않고 로컬 프록시가 HTTP 헤더에 실제 키를 대리 주입합니다.
3. **임의 코드 실행(RCE) 원천 차단**:
   - 에이전트가 환경변수나 RAM 파일을 탈취하기 위해 `python -c`, `bash -c`, `sh -c`, `cmd.exe /c`, 임시 폴더 스크립트 실행 등을 시도할 경우 입구에서 즉시 거부합니다.
4. **실시간 출력 마스킹 (Sanitizer)**:
   - 자식 프로세스의 stdout/stderr 스트림을 실시간 감시하여 시크릿 패턴(청크 경계 분할 및 base64 파생 변종 포함) 감지 시 `[REDACTED_SECRET]`으로 자동 마스킹합니다.

---

## 2. 핵심 원칙 및 개발 규정

### 2.1 대화 및 문서 언어
- **모든 대화와 문서는 한국어로 작성**합니다. 짧은 진행 알림, 작업 완료 보고, 백그라운드 안내까지 사용자에게 보이는 모든 글은 예외 없이 한국어로 작성합니다.

### 2.2 명령어 실행 규정 (Antigravity 특화)
- **복합 셸 명령 연결 금지**: 세미콜론(`;`), `&&`, `||`, 파이프(`|`), 줄바꿈 등을 사용한 복합 명령 실행은 자동 승인(prefix-matching)을 무효화하여 사용자에게 권한 허용 팝업이 반복해서 뜨게 하므로 **절대 금지**합니다.
- `git`, `gh`, `python` 등 모든 명령어는 반드시 **개별 단일 명령 단위**로만 나누어 실행합니다.
- 파일 읽기/수정 시에는 `run_command` 대신 내장 도구(`read_file`, `write_file`, `edit_file`)를 사용하고, Windows 경로 인자(`Path`)에는 백슬래시(`\`) 절대 경로를 사용합니다.

### 2.3 시스템 서비스(systemd 등) 등록 금지
- 데몬은 **시스템 서비스(systemd 유닛, Windows 서비스)로 자동 등록하지 않습니다.**
- 테스트 하네스에서 임시 소켓/디렉토리로 직접 서브프로세스를 띄우거나, 사용자가 수동 포그라운드/백그라운드로 구동하는 경로만 유지합니다.

### 2.4 보안 및 시크릿 취급 원칙
- **시크릿 절대 커밋 금지**: 토큰, API 키, 마스터 키(`master.key`), 암호화 저장소(`*.enc`) 등은 절대로 git에 커밋하거나 외부에 노출하지 않습니다.
- 홈 폴더의 평문 시크릿 파일(`secrets.json` 등)은 어떤 방식으로든 직접 열거나 검색/복사하지 않습니다.
- 관리자 CLI(`secret-vault`)는 키 목록(`list`)을 출력할 때 오직 키 이름과 메타데이터만 표시하며, 실제 시크릿 값은 절대 노출하지 않습니다.

---

## 3. 변경 및 검증 규칙

- 코드를 바꾼 뒤에는 반드시 [5.4 단위 및 통합 테스트](#54-단위-및-통합-테스트-실행)의 전체 테스트를 실행해 모두 통과하는지 확인합니다.
- RCE 방어선, Sanitizer, 파일 권한(`0600`) 등 보안 정책을 바꾸는 변경에는 해당 동작을 검증하는 회귀 테스트를 함께 추가합니다.
- 테스트 픽스처에는 실제 시크릿 값을 쓰지 않고, 누가 봐도 가짜인 값만 사용합니다.

---

## 4. 컴포넌트 구성 및 아키텍처

```
+─────────────────────────────────────────────────────────────────────────────+
| [ 사용자 / 에이전트 (auto 모드) ]                                            |
|        │                                                                    |
|        ├─ (1) 시크릿 관리: python claude/bin/secret-vault.py <set|list|...> |
|        └─ (2) 격리 실행:   python claude/bin/secret-run.py <명령어...>       |
|                                                                             |
|                                    │ (IPC 요청)                             |
|                                    ▼                                        |
| [ IPC 통신 레이어 ]                                                         |
|   - Linux: Unix Domain Socket (/run/user/<UID>/secret-vault.sock, 0600)     |
|   - Windows Fallback: 127.0.0.1 TCP + 0600 소켓 토큰 파일                   |
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

### 4.1 핵심 파일 위치
- `claude/bin/secret-vaultd.py`: 볼트 데몬 코어 (소켓 서버, Keyring 연동, 프로세스 실행, Sanitizer)
- `claude/bin/secret-vault.py`: 관리자 CLI (`list`, `set`, `set-file`, `delete`, `status`)
- `claude/bin/secret-run.py`: 격리 실행 러너 (데몬 중계, 마스킹 스트림 출력, 종료 코드 동기화)
- `tests/test_secret_vault.py`: 코어 단위 및 통합 테스트 (34개 이상 시나리오)

---

## 5. 실행 및 테스트 명령어

### 5.1 데몬 구동
```bash
# 디버그 콘솔 포그라운드 수동 실행
python claude/bin/secret-vaultd.py --foreground

# 백그라운드 구동
python claude/bin/secret-vaultd.py

# 실행 중인 데몬 종료
python claude/bin/secret-vaultd.py --stop
```

### 5.2 시크릿 등록 및 관리 CLI
```bash
# 상태 확인
python claude/bin/secret-vault.py status

# 문자열 키 등록 (터미널 입력 시 마스킹)
python claude/bin/secret-vault.py set DEEPSEEK_API_KEY

# 파일형 키(인증서/JSON) 등록
python claude/bin/secret-vault.py set-file GCP_SERVICE_ACCOUNT path/to/service-account.json

# 등록된 키 목록 확인 (실제 값은 절대 출력되지 않음)
python claude/bin/secret-vault.py list

# 키 삭제
python claude/bin/secret-vault.py delete DEEPSEEK_API_KEY
```

### 5.3 격리 러너 실행
```bash
# 완제품 바이너리 실행 (환경변수 안전 주입)
python claude/bin/secret-run.py gh pr create --title "작업 내용"

# 허용된 공식/레포 스크립트 실행
python claude/bin/secret-run.py python path/to/my_script.py
```

### 5.4 단위 및 통합 테스트 실행
```bash
# 전체 테스트 실행
python -B -m unittest tests.test_secret_vault -v

# 개별 테스트 클래스 또는 메소드 실행
python -B -m unittest tests.test_secret_vault.SanitizerUnitTest -v
python -B -m unittest tests.test_secret_vault.StoreUnitTest -v
python -B -m unittest tests.test_secret_vault.PolicyUnitTest -v
```

> **플랫폼 주의사항**:
> - Linux 환경에서는 UDS(`AF_UNIX`)와 `/dev/shm` RAM 디스크 및 커널 레벨 `SO_PEERCRED` 신원 검증이 완벽하게 동작합니다.
> - Windows 환경에서는 AF_UNIX 파일 속성 및 비동기 소켓 핸들링에 따라 127.0.0.1 TCP 루프백 fallback 및 임시 토큰 메커니즘을 사용합니다. 에이전트 샌드박스 환경에서 네트워크 소켓 바인딩 테스트를 수행할 때는 필요 시 격리 모드를 주의 깊게 확인해야 합니다.

---

## 6. 설계 문서 및 참고 자료

- **[엔지니어링 상세 설계서](docs/secret-vault/secret-vault-daemon-design.md)**: UDS 프로토콜, 키 라이프사이클, 에이전트 인터랙션 프로토콜(Missing Secret Card) 상세 사양
- **[기술 에세이: 《에이전트로부터 시크릿을 지키는 법》](docs/secret-vault/the-art-of-secret-defense.md)**: 7번의 대화를 통해 완성된 아키텍처 배경과 설계 결정 기록(ADR)
- **[코어 구현 계획서](docs/superpowers/plans/2026-11-09-secret-vault-core.md)**: 시크릿 볼트 상세 태스크 및 검증 계획
- **[온라인 전자책](https://golony6449.github.io/secret-defense/)**: GitHub Pages에 출판된 공식 웹 문서
