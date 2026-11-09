# AGENTS.md

이 문서는 자율 AI 코딩 에이전트(Antigravity, Claude Code, DeepSeek 등)가 `secret-vault` 저장소에서 일관되고 안전하게 작업할 수 있도록 정의된 표준 가이드라인입니다.

---

## 1. 프로젝트 개요 및 핵심 철학

`secret-vault`는 자율 AI 에이전트가 `auto 모드`로 터미널과 파일을 제어하는 환경에서도 비밀번호(API 키, 토큰, 인증서)를 안전하게 보호하기 위해 개발된 **로컬 시크릿 볼트 데몬(`secret-vaultd`) & 격리 실행 러너(`secret-run`)** 프로젝트입니다.

이 프로젝트의 4대 핵심 보안 원칙을 항상 이해하고 준수해야 합니다:
1. **디스크 평문 제로 (Zero Plaintext on Disk)**: 디스크에 평문 시크릿 파일 상시 보관 금지 (OS Keyring + RAM 메모리 암호화).
2. **3대 시크릿 주입 엔진**: 문자열 환경변수 일시 주입, RAM 파일(`/dev/shm`, `0600`) 일시 생성 후 Shred & Unlink 영구 소멸, 로컬 인증 프록시.
3. **RCE(임의 코드 실행) 방어선**: `python -c`, `bash -c`, 임시 폴더 스크립트 실행 원천 거부.
4. **최후의 안전망 (Sanitizer)**: stdout/stderr 실시간 감시 및 시크릿 패턴 `[REDACTED_SECRET]` 자동 마스킹.

---

## 2. 에이전트 시크릿 취급 절대 원칙 (CRITICAL)

에이전트는 어떠한 경우에도 시크릿을 직접 탈취하거나 외부에 노출하지 않아야 합니다:

- **평문 시크릿 파일 열람/검색 절대 금지**:
  - 홈 폴더의 평문 시크릿 파일(`secrets.json` 등), 암호화 저장소(`vault.enc`), 마스터 키(`master.key`) 등 자격증명 관련 파일을 직접 열기, 검색, 복사하거나 스크립트를 통해 출력하려 하지 마십시오.
- **채팅창으로 시크릿 값 직접 요청 금지**:
  - 사용자에게 대화창이나 프롬프트로 API 키나 비밀번호 텍스트를 알려달라고 요구하지 마십시오.
  - 시크릿이 필요하거나 만료된 경우 반드시 아래 **[Missing Secret Card 프로토콜](#3-에이전트-상호작용-프로토콜-missing-secret-card)**을 사용하십시오.
- **관리자 CLI 출력 시 값 미노출 원칙**:
  - `python claude/bin/secret-vault.py list`는 키 이름과 타입만 확인하며, 어떠한 우회 수단으로도 값을 화면에 노출하려 하지 마십시오.

---

## 3. 에이전트 상호작용 프로토콜 (Missing Secret Card)

작업 수행 중 필요한 시크릿이 누락되었거나 데몬에 등록되지 않았을 경우, 임의로 작업을 중단하거나 실패 처리하지 말고 아래 Markdown Alert 형식으로 사용자에게 정중히 등록을 요청하십시오:

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

## 4. 명령어 실행 규정 (Antigravity 특화)

- **복합 셸 명령 연결 절대 금지**:
  - 세미콜론(`;`), `&&`, `||`, 파이프(`|`), 줄바꿈 등을 사용한 복합 명령 실행은 자동 승인(prefix-matching)을 무효화하여 사용자에게 권한 허용 팝업이 반복해서 뜨게 하므로 **절대 금지**합니다.
  - `git`, `gh`, `python` 등 모든 명령어는 반드시 **개별 단일 명령 단위**로만 나누어 실행합니다.
- **파일 입출력 도구**:
  - `run_command`(`cat`, `type`, `Get-Content` 등) 대신 에이전트 내장 도구(`read_file`, `write_file`, `edit_file`)를 사용합니다.
  - Windows 경로 인자(`Path`)에는 슬래시(`/`) 대신 반드시 백슬래시(`\`) 절대 경로를 사용합니다.

---

## 5. RCE 방어선 인식 및 러너 사용 규칙

`secret-run`을 통해 명령어를 실행할 때 데몬은 엄격한 보안 검증 레이어를 적용합니다:

- **차단되는 패턴 (에이전트가 실행 시도하지 말 것)**:
  - `python -c "..."` (인라인 인터프리터 실행)
  - `bash -c "..."`, `sh -c "..."`, `cmd.exe /c "..."`, `powershell -Command "..."`
  - `/tmp/*.py`, `%TEMP%/*.py` 등 임시 폴더 내 스크립트 실행
- **허용되는 패턴**:
  - 시스템 등록 바이너리: `gh`, `litestream`, `git` 등
  - 공식 스크립트 경로: `~/.claude/bin/*`
  - 현재 레포지토리 내의 스크립트: `python path/to/repo_script.py`

---

## 6. 시스템 서비스(systemd 등) 미등록 원칙

- 데몬(`secret-vaultd.py`)은 **시스템 서비스(systemd 유닛, Windows 서비스)로 자동 등록하지 않습니다.**
- 테스트 하네스에서 임시 소켓/디렉토리로 직접 서브프로세스를 띄우거나, 사용자가 수동 포그라운드/백그라운드로 구동하는 경로만 유지합니다.

---

## 7. 변경 및 검증 규칙

- 코드를 바꾼 뒤에는 반드시 [10. 테스트 실행 명령어](#10-테스트-실행-명령어)의 전체 테스트를 실행해 모두 통과하는지 확인합니다.
- RCE 방어선, Sanitizer, 파일 권한(`0600`) 등 보안 정책을 바꾸는 변경에는 해당 동작을 검증하는 회귀 테스트를 함께 추가합니다.
- 테스트 픽스처에는 실제 시크릿 값을 쓰지 않고, 누가 봐도 가짜인 값만 사용합니다.

---

## 8. 의사소통 및 문서 언어

- **모든 대화와 문서는 한국어로 작성**합니다.
- 짧은 진행 알림, 작업 완료 보고, 백그라운드 안내까지 사용자에게 보이는 모든 글은 예외 없이 한국어로 작성합니다. 맥락이 길어지거나 영어 도구 출력을 읽은 뒤에도 영어로 바꾸지 않습니다.

---

## 9. 주요 디렉토리 및 파일 맵

```
secret-vault/
├── claude/bin/
│   ├── secret-vaultd.py       # 볼트 데몬 코어 (소켓 서버, Keyring 연동, 프로세스 실행, Sanitizer)
│   ├── secret-vault.py        # 관리자 CLI (list, set, set-file, delete, status)
│   └── secret-run.py          # 격리 실행 러너 (RCE 검증 중계, 마스킹 스트림 출력)
├── tests/
│   └── test_secret_vault.py   # 코어 단위 및 통합 테스트 슈트 (34개 이상 시나리오)
├── docs/
│   ├── secret-vault/
│   │   ├── secret-vault-daemon-design.md  # 엔지니어링 상세 설계서
│   │   └── the-art-of-secret-defense.md   # 기술 에세이 및 아키텍처 결정 기록(ADR)
│   └── superpowers/plans/
│       └── 2026-11-09-secret-vault-core.md # 시크릿 볼트 구현 계획서
├── README.md                  # 사용자 가이드 및 빠른 시작
├── GEMINI.md                  # Antigravity/Gemini 전용 작업 지침서
└── AGENTS.md                  # 에이전트 공통 행동 수칙 (본 문서)
```

---

## 10. 테스트 실행 명령어

```bash
# 전체 테스트 실행
python -B -m unittest tests.test_secret_vault -v

# 개별 컴포넌트 단위 테스트
python -B -m unittest tests.test_secret_vault.SanitizerUnitTest -v
python -B -m unittest tests.test_secret_vault.StoreUnitTest -v
python -B -m unittest tests.test_secret_vault.PolicyUnitTest -v
```
