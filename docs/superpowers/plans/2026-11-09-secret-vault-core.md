# secret-vault 코어 데몬 & 격리 러너 구현 계획

> 작성일: 2026-11-09  
> 상태: 완료  
> 작성자: Antigravity  
> 검증: Automated Test Suite (unittest)

`docs/secret-vault/secret-vault-daemon-design.md` 설계서에 따라 로컬 시크릿 볼트 데몬, 관리자 CLI, 격리 러너 및 테스트를 구현한다.
**주의**: 시스템 서비스(systemd 유닛 등) 등록은 일체 수행하지 않으며, 수동 프로세스 구동 및 pytest/unittest 단위/통합 테스트로만 검증한다.

## 작업 파일

**Files:**
- Create: `claude/bin/secret-vault.py`
- Create: `claude/bin/secret-vaultd.py`
- Create: `claude/bin/secret-run.py`
- Create: `tests/test_secret_vault.py`

---

### Task 1: 볼트 데몬 (claude/bin/secret-vaultd.py)

UDS 소켓 서버 기반 데몬 프로세스로, 메모리에 시크릿을 보관하고 안전한 프로세스 실행 환경을 제공한다.

1. **소켓 및 IPC**:
   - 소켓 기본 경로: Linux `/run/user/<UID>/secret-vault.sock` (fallback `~/.claude/state/secret-vault.sock`), Windows `~/.claude/state/secret-vault.sock` (AF_UNIX 지원) 또는 옵션 `--socket <path>`.
   - 소켓 파일 퍼미션 `0600` (소유자 전용).
   - JSON 기반 요청/응답 프로토콜.
2. **시크릿 스토리지 및 키링 연동**:
   - 시크릿 저장소: Keyring 연동 (`keyring` 모듈 활용 또는 플랫폼별 암호화 키스토어, 없을 시 안전한 대칭키 암호화 로컬 저장소 fallback).
   - 데몬 기동 시 로드하여 메모리(RAM)에 보관.
   - 키 타입 구분: `string` (문자열 값), `file` (바이트/텍스트 파일 내용).
3. **관리자 API**:
   - `list`: 등록된 키 목록 및 메타데이터 반환 (값은 반환하지 않음).
   - `set`: 문자열 시크릿 저장.
   - `set-file`: 파일 내용 시크릿 저장.
   - `delete`: 키 삭제.
   - `status`: 데몬 상태 확인.
4. **보안 검증 레이어 (RCE 차단)**:
   - 실행 요청된 명령어 검증:
     - 차단 대상: `python -c`, `bash -c`, `sh -c`, `cmd.exe /c`, 임의의 임시 폴더 스크립트(`/tmp/*.py`, `%TEMP%/*.py`).
     - 허용 대상: 시스템 표준 바이너리(`gh`, `litestream`, `git` 등) 및 공식 스크립트 경로(`~/.claude/bin/*`, 레포 내 스크립트).
5. **2대 주입 엔진**:
   - 문자열 시크릿: 자식 프로세스의 환경변수(`env`)로 주입.
   - 파일형 시크릿: RAM 가상 디스크(Linux `/dev/shm/secret-vault/<UUID>.ext`, Windows tempdir, 권한 `0600`)에 일시 생성 후 환경변수에 경로 주입, 프로세스 종료 즉시 Shred/Unlink.
6. **최후의 안전망 (Sanitizer)**:
   - 자식 프로세스의 stdout/stderr를 실시간 스트리밍 감시하여 메모리에 보관 중인 문자열 시크릿 패턴이 나타나면 `[REDACTED_SECRET]`으로 마스킹 치환.
7. **CLI 옵션**:
   - `--socket <path>`: 소켓 경로 지정
   - `--foreground`: 포그라운드 실행 (로그 콘솔 출력, 테스트 및 수동 구동용)
   - `--stop`: 실행 중인 데몬 종료

---

### Task 2: 관리자 CLI (claude/bin/secret-vault.py)

사용자가 대화형 터미널에서 시크릿을 등록, 조회, 삭제하는 CLI 도구.

1. **명령어 인터페이스**:
   - `secret-vault list`: 등록된 키 목록 출력 (키 이름, 타입만 표시, 값은 절대 노출하지 않음).
   - `secret-vault set <KEY_NAME>`: 숨김 입력(`getpass.getpass`)으로 시크릿 값을 안전하게 입력받아 데몬에 등록.
   - `secret-vault set-file <KEY_NAME> <FILE_PATH>`: 지정된 파일의 내용을 읽어 데몬에 파일형 시크릿으로 등록.
   - `secret-vault delete <KEY_NAME>`: 키 삭제.
   - `secret-vault status`: 데몬 연결 상태 확인.
2. **옵션**:
   - `--socket <path>`: 커스텀 소켓 경로 전달.

---

### Task 3: 격리 러너 (claude/bin/secret-run.py)

에이전트나 사용자가 안전하게 명령어를 실행하기 위한 래퍼 CLI.

1. **사용법**:
   - `secret-run <command> [args...]`
   - 예: `secret-run gh pr create --title "..."`
2. **동작 방식**:
   - 데몬 소켓에 연결하여 실행 요청 (`cmd`, `args`, `cwd`, `env` 등).
   - 데몬이 프로세스를 실행하고 마스킹된 stdout/stderr 스트림을 러너에 전달.
   - 러너는 스트림을 자신의 stdout/stderr로 실시간 출력.
   - 프로세스 종료 시 종료 코드(exit code)를 받아 동일하게 종료(`sys.exit(rc)`).
3. **에러 핸들링**:
   - 데몬 미구동 시 친절한 안내 메시지 출력.
   - RCE 검증 거부 시 거부 사유 출력 및 비정상 종료.

---

### Task 4: 단위 및 통합 테스트 (tests/test_secret_vault.py)

`unittest` 기반 단위 및 통합 테스트 작성.

1. **테스트 픽스처**:
   - 임시 디렉토리 및 임시 소켓 경로를 생성하여 테스트 전용 `secret-vaultd` 인스턴스를 서브프로세스/백그라운드 스레드로 구동.
2. **관리자 CLI 테스트**:
   - `set`, `set-file`, `list`, `delete` 기능 동작 검증.
   - `list` 출력 결과에 실제 시크릿 문자열이 포함되지 않음을 검증.
3. **러너 및 주입 엔진 테스트**:
   - 문자열 시크릿 주입 검증: 허용된 파이썬 스크립트 실행 시 환경변수에 시크릿이 주입되는지 확인.
   - 파일형 시크릿 생명주기 검증: 실행 중에는 가상 디스크/임시 파일이 존재하고 실행 종료 후에는 삭제(파기)되었는지 확인.
4. **보안 검증 (RCE 차단) 테스트**:
   - `python -c "print(1)"` 등의 실행 요청이 데몬에 의해 거부되는지 확인.
5. **출력 마스킹 (Sanitizer) 테스트**:
   - 자식 프로세스가 의도적으로 시크릿 값을 stdout/stderr에 출력하려 할 때 `[REDACTED_SECRET]`으로 치환되어 마스킹되는지 검증.
6. **시스템 서비스 등록 금지 준수**:
   - systemd 등 OS 서비스 등록 없이 수동/테스트 하네스에서 온전히 동작함을 입증.
