#!/usr/bin/env python3
"""secret-vaultd — 로컬 시크릿 볼트 데몬.

설계서: docs/secret-vault/secret-vault-daemon-design.md

데몬은 같은 사용자만 접근 가능한 Unix 도메인 소켓(AF_UNIX)으로 관리 API와
격리 실행(run) API를 제공한다. 시크릿은 메모리에만 보관하고, 실행 요청마다
자식 프로세스에만 주입한다.

  * 문자열 시크릿: 자식 프로세스의 환경변수(os.environ)로만 주입한다.
  * 파일 시크릿: RAM 디스크(/dev/shm, Windows는 %TEMP%)에 0600으로 실행 순간에만
    만들고, 자식이 끝나면 Shred 후 Unlink 한다.
  * RCE 방어: `python -c`, `bash -c`, `sh -c`, `cmd.exe /c`, 임시 폴더의 스크립트
    실행 요청은 입구에서 거부한다. 시스템 표준 바이너리와 공식 스크립트 경로
    (`~/.claude/bin/*`, 현재 작업 폴더가 속한 레포의 스크립트)만 허용한다.
  * 최후 안전망: 자식의 stdout/stderr를 실시간으로 마스킹해 주입한 시크릿이
    그대로 나가면 `[REDACTED_SECRET]`으로 바꾼다.

주의(설계 한계): keyring 모듈을 쓸 수 없는 환경에서는 같은 사용자 홈 아래의
0600 키 파일(master.key)로 저장소를 암호화한다. 이 경우 같은 사용자 권한의
다른 프로세스가 키 파일을 읽을 수 있으므로, 1차 목표인 "평문 시크릿 파일 제거"와
"시크릿 주입 경로 단일화"는 달성하지만 OS Keyring 수준의 격리는 아니다.
헤드리스 서버는 `--key-backend tpm2`로 마스터 키를 host+TPM2에 봉인할 수 있다.
디스크만 떼어 가서는 풀 수 없지만, TPM 초기화·메인보드 교체 시에는 저장소를
복구할 수 없으므로 원본 시크릿을 따로 보관해야 한다.

수동 구동 예:
    python ~/.claude/bin/secret-vaultd.py --foreground
    python ~/.claude/bin/secret-vaultd.py --socket /tmp/sv.sock --stop

시스템 서비스(systemd 등) 등록은 하지 않는다. 테스트와 수동 구동만 지원한다.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

LOG = logging.getLogger("secret_vaultd")

APP_NAME = "secret-vault"
SOCKET_NAME = "secret-vault.sock"
STORE_VERSION = 1
VERSION = "1.0.0"
REDACTED = b"[REDACTED_SECRET]"
REDACTED_TEXT = "[REDACTED_SECRET]"
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_SECRET_BYTES = 8 * 1024 * 1024
SANITIZE_MAX_PATTERN = 8192
DERIVED_PATTERN_MIN = 6
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$")
EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,16}$")
KEY_BACKENDS = ("auto", "tpm2")
# TPM2 봉인 마스터 키 파일 이름과 systemd-creds 자격증명 이름(복호화 때 같아야 한다).
TPM2_CRED_FILE = "vault-key.cred"
TPM2_CRED_NAME = "secret-vault-master-key"
# Windows에서 os.open은 기본이 텍스트 모드라 \n이 \r\n으로 바뀐다. 키/시크릿
# 바이너리를 그대로 쓰려면 O_BINARY가 필요하다.
_BINARY_FLAG = getattr(os, "O_BINARY", 0)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("파일에 쓰지 못했다")
        view = view[written:]

# ---------------------------------------------------------------------------
# 경로
# ---------------------------------------------------------------------------


def default_state_dir() -> Path:
    return Path.home() / ".claude" / "state" / APP_NAME


def default_store_path() -> Path:
    return default_state_dir() / "vault.enc"


def default_socket_path() -> Path:
    """Linux는 /run/user/<uid>, 그 외/실패 시 상태 폴더 아래를 쓴다."""
    if os.name == "posix":
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if runtime:
            runtime_dir = Path(runtime)
            if runtime_dir.is_dir() and os.access(runtime_dir, os.W_OK):
                return runtime_dir / SOCKET_NAME
        try:
            run_user = Path(f"/run/user/{os.getuid()}")
        except AttributeError:
            run_user = None
        if run_user is not None and run_user.is_dir() and os.access(run_user, os.W_OK):
            return run_user / SOCKET_NAME
    return default_state_dir() / SOCKET_NAME


def default_tmp_root() -> Path:
    """파일형 시크릿을 만들 RAM 디스크(또는 임시 폴더) 루트."""
    if os.name == "posix":
        shm = Path("/dev/shm")
        if shm.is_dir() and os.access(shm, os.W_OK):
            return shm / APP_NAME
    return Path(tempfile.gettempdir()) / APP_NAME


def _supports_unix_socket() -> bool:
    return hasattr(socket, "AF_UNIX")


def _is_socket_file(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def _read_tcp_endpoint(path: Path) -> dict:
    """Windows 등 AF_UNIX가 없는 환경에서 소켓 경로 파일이 담은 접속 정보."""
    try:
        info = json.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        raise ConnectionError("시크릿 볼트 소켓 정보를 읽지 못했다") from None
    if not isinstance(info, dict) or info.get("transport") != "tcp":
        raise ConnectionError("시크릿 볼트 소켓 정보가 올바르지 않다")
    host = info.get("host")
    port = info.get("port")
    token = info.get("token")
    if host != "127.0.0.1" or not isinstance(port, int) or not (0 < port < 65536):
        raise ConnectionError("시크릿 볼트 소켓 주소가 올바르지 않다")
    if not isinstance(token, str) or not token:
        raise ConnectionError("시크릿 볼트 접속 토큰이 올바르지 않다")
    return {"host": host, "port": port, "token": token}


def open_client_connection(
    socket_path: Path | str, timeout: float | None = 15.0
) -> tuple[socket.socket, str | None]:
    """데몬에 접속한다. (소켓, TCP fallback 토큰)을 돌려준다.

    Unix 도메인 소켓이 있으면 그것을, 없으면(Windows 등) 0600 소켓 정보 파일에
    적힌 127.0.0.1 포트와 접속 토큰을 쓴다.
    """
    path = Path(socket_path)
    if _supports_unix_socket() and _is_socket_file(path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(str(path))
            return sock, None
        except OSError:
            sock.close()
            raise
    if not path.exists():
        raise FileNotFoundError(f"데몬 소켓이 없다: {path}")
    info = _read_tcp_endpoint(path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((info["host"], info["port"]))
        return sock, info["token"]
    except OSError:
        sock.close()
        raise


def _mkdir_private(path: Path) -> None:
    created = False
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
        created = True
    if created:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def _atomic_write(path: Path, data: bytes) -> None:
    """같은 폴더의 임시 파일에 쓴 뒤 바꿔치기한다."""
    _mkdir_private(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp_name, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 저장소 암호화
# ---------------------------------------------------------------------------


class StoreError(Exception):
    """저장소를 열거나 저장하지 못했다. 메시지에 시크릿 값은 넣지 않는다."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise StoreError("저장소 인코딩이 올바르지 않다") from None


def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    pos = 0
    while pos < len(data):
        block = hmac.new(key, b"E" + nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        chunk = data[pos : pos + len(block)]
        out[pos : pos + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, block))
        pos += len(block)
        counter += 1
    return bytes(out)


def _fernet_class():
    try:
        from cryptography.fernet import Fernet  # type: ignore

        return Fernet
    except Exception:  # pragma: no cover - 설치 환경에 따라 다르다
        return None


def _seal(key: bytes, plaintext: bytes) -> dict:
    fernet = _fernet_class()
    if fernet is not None:
        token = fernet(base64.urlsafe_b64encode(key)).encrypt(plaintext)
        return {"version": STORE_VERSION, "cipher": "fernet", "data": token.decode("ascii")}
    nonce = os.urandom(16)
    ciphertext = _keystream_xor(key, nonce, plaintext)
    tag = hmac.new(key, b"M" + nonce + ciphertext, hashlib.sha256).digest()
    return {
        "version": STORE_VERSION,
        "cipher": "hmac-ctr-hmac-sha256",
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
    }


def _open_envelope(key: bytes, envelope: dict) -> bytes:
    if not isinstance(envelope, dict):
        raise StoreError("저장소 형식이 올바르지 않다")
    cipher = envelope.get("cipher")
    if cipher == "fernet":
        fernet = _fernet_class()
        if fernet is None:
            raise StoreError("Fernet으로 암호화된 저장소인데 cryptography 모듈이 없다")
        try:
            return fernet(base64.urlsafe_b64encode(key)).decrypt(envelope["data"].encode("ascii"))
        except Exception:
            raise StoreError("저장소 복호화에 실패했다(키가 다르거나 손상됐다)") from None
    if cipher == "hmac-ctr-hmac-sha256":
        nonce = _b64d(envelope.get("nonce", ""))
        ciphertext = _b64d(envelope.get("ciphertext", ""))
        tag = _b64d(envelope.get("tag", ""))
        expected = hmac.new(key, b"M" + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise StoreError("저장소 무결성 검증에 실패했다(키가 다르거나 손상됐다)")
        return _keystream_xor(key, nonce, ciphertext)
    raise StoreError("알 수 없는 저장소 암호화 방식이다")


class KeyProvider:
    """마스터 키를 OS Keyring 또는 0600 키 파일에서 가져온다.

    key_backend="tpm2"면 마스터 키를 `systemd-creds --user`로 host+TPM2에 봉인한
    파일(vault-key.cred)에서만 꺼낸다. 이 경우 풀지 못하면 키 파일로 물러서지 않고
    실패한다(새 키를 만들면 기존 저장소를 영영 못 열게 된다).
    """

    def __init__(
        self,
        state_dir: Path,
        *,
        use_keyring: bool,
        key_backend: str = "auto",
        store_path: Path | None = None,
    ):
        if key_backend not in KEY_BACKENDS:
            raise StoreError(f"알 수 없는 마스터 키 방식이다: {key_backend}")
        self.state_dir = Path(state_dir)
        self.key_file = self.state_dir / "master.key"
        self.cred_file = self.state_dir / TPM2_CRED_FILE
        self.use_keyring = use_keyring
        self.key_backend = key_backend
        self.store_path = Path(store_path) if store_path is not None else None
        self._cached: bytes | None = None
        self._lock = threading.Lock()

    def get(self) -> bytes:
        with self._lock:
            if self._cached is not None:
                return self._cached
            if self.key_backend == "tpm2":
                key = self._from_tpm2()
            else:
                key = None
                if self.use_keyring:
                    key = self._from_keyring()
                if key is None:
                    key = self._from_file()
            self._cached = key
            return key

    def _run_creds(self, args: list[str], data: bytes) -> bytes:
        exe = shutil.which("systemd-creds")
        if exe is None:
            raise StoreError("systemd-creds를 찾지 못해 TPM2 마스터 키를 쓸 수 없다")
        try:
            proc = subprocess.run(
                [exe, "--user", *args],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StoreError(f"systemd-creds 실행에 실패했다 ({type(exc).__name__})") from None
        if proc.returncode != 0:
            raise StoreError(f"systemd-creds가 실패했다 (종료 코드 {proc.returncode})")
        return proc.stdout

    def _seal_tpm2(self, key: bytes) -> bytes:
        return self._run_creds(
            ["encrypt", "--with-key=host+tpm2", f"--name={TPM2_CRED_NAME}", "-", "-"], key
        )

    def _unseal_tpm2(self, blob: bytes) -> bytes:
        key = self._run_creds(["decrypt", f"--name={TPM2_CRED_NAME}", "-", "-"], blob)
        if len(key) < 32:
            raise StoreError("TPM2로 푼 마스터 키 길이가 올바르지 않다")
        return key

    def _from_tpm2(self) -> bytes:
        _mkdir_private(self.state_dir)
        try:
            blob = self.cred_file.read_bytes()
        except FileNotFoundError:
            blob = None
        except OSError as exc:
            raise StoreError(f"TPM2 마스터 키 파일을 읽지 못했다 ({type(exc).__name__})") from None
        if blob:
            return self._unseal_tpm2(blob)
        # 처음 TPM2로 바꿀 때: 기존 키가 있으면 옮기고, 없을 때만 새로 만든다.
        migrated_from = None
        key = None
        if self.use_keyring:
            key = self._from_keyring(create=False)
            if key is not None:
                migrated_from = "keyring"
        if key is None:
            key = self._read_key_file()
            if key is not None:
                migrated_from = "file"
        if key is None:
            if self.store_path is not None and self.store_path.exists():
                raise StoreError("저장소는 있는데 마스터 키를 찾지 못했다. 새 키를 만들지 않는다")
            key = os.urandom(32)
        sealed = self._seal_tpm2(key)
        if self._unseal_tpm2(sealed) != key:
            raise StoreError("TPM2 봉인 확인에 실패했다")
        try:
            _atomic_write(self.cred_file, sealed)
        except OSError as exc:
            raise StoreError(f"TPM2 마스터 키 파일을 쓰지 못했다 ({type(exc).__name__})") from None
        # 봉인을 확인한 뒤에만 이전 위치의 키를 지운다.
        if migrated_from == "file":
            try:
                self.key_file.unlink()
            except OSError as exc:
                LOG.warning("이전 마스터 키 파일을 지우지 못했다 (%s)", type(exc).__name__)
        elif migrated_from == "keyring":
            try:
                import keyring  # type: ignore

                keyring.delete_password(APP_NAME, "master-key")
            except Exception as exc:
                LOG.warning("OS Keyring의 이전 마스터 키를 지우지 못했다 (%s)", type(exc).__name__)
        if migrated_from:
            LOG.info("마스터 키를 TPM2 봉인으로 옮겼다 (이전 위치: %s)", migrated_from)
        return key

    def _read_key_file(self) -> bytes | None:
        try:
            data = self.key_file.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StoreError(f"마스터 키 파일을 읽지 못했다 ({type(exc).__name__})") from None
        if len(data) < 32:
            raise StoreError("마스터 키 파일이 올바르지 않다")
        return data

    def _from_keyring(self, *, create: bool = True) -> bytes | None:
        try:
            import keyring  # type: ignore

            stored = keyring.get_password(APP_NAME, "master-key")
            if stored:
                return _b64d(stored)
            if not create:
                return None
            generated = os.urandom(32)
            keyring.set_password(APP_NAME, "master-key", _b64e(generated))
            return generated
        except Exception as exc:  # 키링 백엔드가 없거나 잠겨 있을 수 있다
            LOG.warning("OS Keyring을 쓸 수 없어 키 파일로 대체한다 (%s)", type(exc).__name__)
            return None

    def _from_file(self) -> bytes:
        _mkdir_private(self.state_dir)
        try:
            data = self.key_file.read_bytes()
        except FileNotFoundError:
            data = b""
        except OSError as exc:
            raise StoreError(f"마스터 키 파일을 읽지 못했다 ({type(exc).__name__})") from None
        if data:
            if len(data) < 32:
                # 다른 프로세스가 키 파일을 만드는 중일 수 있어 잠깐 재시도한다.
                for _ in range(20):
                    time.sleep(0.05)
                    try:
                        data = self.key_file.read_bytes()
                    except OSError:
                        break
                    if len(data) >= 32:
                        return data
                raise StoreError("마스터 키 파일이 올바르지 않다")
            return data
        generated = os.urandom(32)
        try:
            fd = os.open(
                str(self.key_file),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG,
                0o600,
            )
        except FileExistsError:
            return self._from_file()
        except OSError as exc:
            raise StoreError(f"마스터 키 파일을 만들지 못했다 ({type(exc).__name__})") from None
        try:
            _write_all(fd, generated)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass
        return generated


def _validate_entry(name: str, entry: Any) -> dict:
    if not isinstance(entry, dict):
        raise StoreError("저장소 항목 형식이 올바르지 않다")
    kind = entry.get("type")
    value = entry.get("value")
    if kind not in {"string", "file"} or not isinstance(value, str):
        raise StoreError("저장소 항목 형식이 올바르지 않다")
    clean = {"type": kind, "value": value}
    if kind == "file":
        extension = entry.get("extension") or ".bin"
        clean["extension"] = extension if isinstance(extension, str) else ".bin"
    updated = entry.get("updated_at")
    if isinstance(updated, str):
        clean["updated_at"] = updated
    return clean


class VaultStore:
    """암호화된 로컬 저장소 파일. 값은 메모리에만 복호화해 둔다."""

    def __init__(self, path: Path, *, use_keyring: bool = False, key_backend: str = "auto"):
        self.path = Path(path)
        self._keys = KeyProvider(
            self.path.parent, use_keyring=use_keyring, key_backend=key_backend, store_path=self.path
        )
        self._lock = threading.RLock()
        self._data: dict[str, dict] | None = None

    def load(self) -> dict[str, dict]:
        with self._lock:
            if self._data is not None:
                return self._data
            try:
                raw = self.path.read_bytes()
            except FileNotFoundError:
                self._data = {}
                return self._data
            except OSError as exc:
                raise StoreError(f"저장소 파일을 읽지 못했다 ({type(exc).__name__})") from None
            if not raw.strip():
                self._data = {}
                return self._data
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise StoreError("저장소 파일이 올바른 JSON이 아니다") from None
            plaintext = _open_envelope(self._keys.get(), envelope)
            try:
                data = json.loads(plaintext.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise StoreError("복호화한 저장소 내용이 올바르지 않다") from None
            if not isinstance(data, dict):
                raise StoreError("저장소 최상위는 객체여야 한다")
            clean: dict[str, dict] = {}
            for name, entry in data.items():
                if not isinstance(name, str):
                    raise StoreError("저장소 키 이름이 올바르지 않다")
                clean[name] = _validate_entry(name, entry)
            self._data = clean
            return clean

    def save(self) -> None:
        with self._lock:
            if self._data is None:
                return
            payload = json.dumps(self._data, ensure_ascii=False, sort_keys=True).encode("utf-8")
            envelope = _seal(self._keys.get(), payload)
            try:
                _atomic_write(self.path, json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
            except OSError as exc:
                raise StoreError(f"저장소 파일을 쓰지 못했다 ({type(exc).__name__})") from None


class SecretVault:
    """메모리 볼트. 저장소에는 암호화해서 반영한다. 값은 list 응답에 넣지 않는다."""

    def __init__(self, store: VaultStore):
        self._store = store
        self._lock = threading.RLock()

    def list(self) -> list[dict]:
        with self._lock:
            data = self._store.load()
            rows = []
            for name in sorted(data):
                entry = data[name]
                row = {"name": name, "type": entry["type"]}
                if "updated_at" in entry:
                    row["updated_at"] = entry["updated_at"]
                rows.append(row)
            return rows

    def set_string(self, name: str, value: str) -> None:
        self._check_name(name)
        if not isinstance(value, str) or value == "":
            raise ValueError("시크릿 값이 비어 있다")
        if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ValueError("시크릿 값이 너무 크다")
        with self._lock:
            data = self._store.load()
            data[name] = {"type": "string", "value": value, "updated_at": _now()}
            self._store.save()

    def set_file(self, name: str, content: bytes, extension: str = ".bin") -> None:
        self._check_name(name)
        if not isinstance(content, (bytes, bytearray)):
            raise ValueError("파일 내용이 올바르지 않다")
        if len(content) > MAX_SECRET_BYTES:
            raise ValueError("파일 시크릿이 너무 크다")
        if not isinstance(extension, str) or not EXT_RE.match(extension):
            extension = ".bin"
        with self._lock:
            data = self._store.load()
            data[name] = {
                "type": "file",
                "value": _b64e(bytes(content)),
                "extension": extension,
                "updated_at": _now(),
            }
            self._store.save()

    def delete(self, name: str) -> bool:
        with self._lock:
            data = self._store.load()
            if name not in data:
                return False
            del data[name]
            self._store.save()
            return True

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            data = self._store.load()
            return {name: dict(entry) for name, entry in data.items()}

    @staticmethod
    def _check_name(name: str) -> None:
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ValueError("키 이름은 영문/숫자/._- 로 된 128자 이하여야 한다")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# 출력 마스킹(Sanitizer)
# ---------------------------------------------------------------------------


def secret_patterns(snapshot: dict[str, dict]) -> list[bytes]:
    """주입되는 시크릿에서 마스킹 패턴을 만든다. 원본·base64·텍스트 줄 단위."""
    patterns: set[bytes] = set()
    for entry in snapshot.values():
        if entry.get("type") == "string":
            raw = entry.get("value", "").encode("utf-8")
        else:
            try:
                raw = base64.b64decode(entry.get("value", ""), validate=True)
            except (ValueError, base64.binascii.Error):
                continue
        if not raw:
            continue
        patterns.add(raw)
        derived: list[bytes] = []
        if len(raw) >= 4:
            derived.append(base64.b64encode(raw))
            derived.append(base64.urlsafe_b64encode(raw).rstrip(b"="))
        if len(raw) <= SANITIZE_MAX_PATTERN:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                stripped = text.strip()
                if stripped:
                    derived.append(stripped.encode("utf-8"))
                    without_comma = stripped.rstrip(",").rstrip()
                    if without_comma and without_comma != stripped:
                        derived.append(without_comma.encode("utf-8"))
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        derived.append(line.encode("utf-8"))
                        without_comma = line.rstrip(",").rstrip()
                        if without_comma and without_comma != line:
                            derived.append(without_comma.encode("utf-8"))
        for pattern in derived:
            if len(pattern) >= DERIVED_PATTERN_MIN:
                patterns.add(pattern)
    return sorted(patterns, key=len, reverse=True)


class StreamSanitizer:
    """청크 경계에 걸친 시크릿도 놓치지 않도록 꼬리를 남겨 두고 치환한다."""

    def __init__(self, patterns: Iterable[bytes]):
        unique = sorted({bytes(p) for p in patterns if p}, key=len, reverse=True)
        self._patterns = unique
        self._regex = re.compile(b"|".join(re.escape(p) for p in unique)) if unique else None
        self._keep = max((len(p) for p in unique), default=0) - 1
        self._buf = b""

    def feed(self, chunk: bytes) -> bytes:
        if not self._regex:
            return chunk
        self._buf += chunk
        sanitized = self._regex.sub(REDACTED, self._buf)
        if len(sanitized) <= self._keep:
            self._buf = sanitized
            return b""
        emit = sanitized[: -self._keep] if self._keep else sanitized
        self._buf = sanitized[-self._keep :] if self._keep else b""
        return emit

    def flush(self) -> bytes:
        if not self._regex:
            rest, self._buf = self._buf, b""
            return rest
        rest = self._regex.sub(REDACTED, self._buf)
        self._buf = b""
        return rest


# ---------------------------------------------------------------------------
# 실행 정책(RCE 차단)
# ---------------------------------------------------------------------------


class CommandDenied(Exception):
    """실행 요청이 보안 정책에 걸렸다."""


_WRAPPERS = {"env", "nohup", "nice", "timeout", "stdbuf", "setsid", "xargs"}
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "fish"}
_MSG_INLINE = "인라인 코드 실행(-c)은 허용되지 않는다"
_MSG_TEMP = "임시 폴더의 스크립트/실행 파일은 실행할 수 없다"
_MSG_SCRIPT = "공식 스크립트 경로(~/.claude/bin 또는 현재 레포)가 아니다"


def _basename(cmd: str) -> str:
    return os.path.basename(cmd).lower()


def _norm(path: Any) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _under(path: Any, root: Any) -> bool:
    try:
        return os.path.commonpath([_norm(path), _norm(root)]) == _norm(root)
    except ValueError:  # 다른 드라이브(Windows)
        return False


def _temp_roots() -> list[str]:
    roots = []
    for raw in (tempfile.gettempdir(), "/tmp", "/var/tmp", "/dev/shm"):
        if raw:
            roots.append(_norm(raw))
    return roots


def _is_temp_path(path: Any) -> bool:
    return any(_under(path, root) for root in _temp_roots())


def _system_binary_roots() -> list[Path]:
    roots = [
        Path("/usr/bin"),
        Path("/bin"),
        Path("/usr/sbin"),
        Path("/sbin"),
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
        Path("/opt/homebrew/bin"),
        Path("/snap/bin"),
    ]
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if system_root:
        roots.append(Path(system_root) / "System32")
        roots.append(Path(system_root))
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        roots.append(Path(local_appdata) / "Programs")
        roots.append(Path(local_appdata) / "Microsoft" / "WindowsApps")
    return roots


def _claude_bin_dir() -> Path:
    return Path.home() / ".claude" / "bin"


def _repo_root(cwd: str) -> str | None:
    try:
        start = Path(cwd).resolve()
    except OSError:
        return None
    current = start
    for _ in range(30):
        if (current / ".git").exists():
            return _norm(current)
        if current.parent == current:
            break
        current = current.parent
    return None


def _is_trusted_interpreter(path: Any) -> bool:
    real = _norm(path)
    if real == _norm(sys.executable):
        return True
    roots = [sys.base_prefix, sys.prefix]
    roots += ["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin"]
    return any(_under(real, root) for root in roots if root)


def _is_allowed_binary(path: Any, cwd: str) -> bool:
    roots: list[Any] = _system_binary_roots() + [_claude_bin_dir()]
    repo = _repo_root(cwd)
    if repo:
        roots.append(repo)
    roots.append(sys.executable)
    return any(_under(path, root) for root in roots)


def _is_allowed_script(path: Any, cwd: str) -> bool:
    roots: list[Any] = [_claude_bin_dir()]
    repo = _repo_root(cwd)
    if repo:
        roots.append(repo)
    return any(_under(path, root) for root in roots)


def _resolve_executable(cmd: str, cwd: str) -> str:
    if os.path.isabs(cmd) or os.path.dirname(cmd):
        candidate = Path(cmd) if os.path.isabs(cmd) else Path(cwd) / cmd
        if not candidate.is_file():
            raise CommandDenied(f"실행 파일이 없다: {cmd}")
        return os.path.realpath(str(candidate))
    found = shutil.which(cmd)
    if not found:
        raise CommandDenied(f"PATH에서 실행 파일을 찾지 못했다: {cmd}")
    return os.path.realpath(found)


def _interpreter_family(name: str):
    stem = name[:-4] if name.endswith(".exe") else name
    if stem.startswith("python") or stem in {"py", "pypy", "pypy3"}:
        return "python"
    if stem in _SHELLS:
        return "shell"
    if stem == "cmd":
        return "cmd"
    if stem in {"powershell", "pwsh"}:
        return "powershell"
    if stem in {"node", "nodejs"}:
        return "node"
    if stem == "perl":
        return "perl"
    if stem == "ruby":
        return "ruby"
    if stem == "php":
        return "php"
    return None


_VALUE_FLAGS = {
    "python": {"-x", "-w", "-x", "-w", "--check-hash-based-pycs"},
    "shell": {"-o", "-O", "-W"},
    "powershell": {
        "-file",
        "-f",
        "-executionpolicy",
        "-ep",
        "-windowstyle",
        "-w",
        "-inputformat",
        "-outputformat",
        "-workingdirectory",
        "-wd",
        "-configurationname",
        "-version",
    },
    "node": {"-r", "--require", "--loader"},
    "perl": {"-i", "-m"},
    "ruby": {"-i", "-r"},
    "php": {"-c", "-d"},
}


def _deny_inline(family: str, args: Sequence[str]) -> None:
    lowered = [a.lower() for a in args]
    if family == "shell":
        for raw, low in zip(args, lowered):
            if raw == "--":
                break
            if raw == "-":
                raise CommandDenied("표준 입력에서 스크립트를 읽는 실행은 허용되지 않는다")
            if low == "-c" or (low.startswith("-") and not low.startswith("--") and "c" in low[1:]):
                raise CommandDenied(_MSG_INLINE)
    elif family == "python":
        for raw, low in zip(args, lowered):
            if raw == "-":
                raise CommandDenied("표준 입력에서 스크립트를 읽는 실행은 허용되지 않는다")
            if low == "-c" or (low.startswith("-c") and not low.startswith("--")):
                raise CommandDenied(_MSG_INLINE)
            if low == "-m" or (low.startswith("-m") and not low.startswith("--")):
                raise CommandDenied("모듈 실행(-m)은 허용되지 않는다")
    elif family == "cmd":
        for low in lowered:
            if low in {"/c", "/k"} or low.startswith("/c:") or low.startswith("/k:"):
                raise CommandDenied(_MSG_INLINE)
    elif family == "powershell":
        for low in lowered:
            if low in {"-c", "-command", "-e", "-ec", "-encodedcommand", "--eval"}:
                raise CommandDenied(_MSG_INLINE)
            if low.startswith("-command:") or low.startswith("-encodedcommand:"):
                raise CommandDenied(_MSG_INLINE)
    elif family in {"node", "perl", "ruby", "php"}:
        inline = {"node": {"-e", "--eval", "-p", "--print"}, "perl": {"-e", "-e"}, "ruby": {"-e"}, "php": {"-r"}}[family]
        for low in lowered:
            if low in inline:
                raise CommandDenied(_MSG_INLINE)


def _script_arg(family: str, args: Sequence[str]) -> str | None:
    value_flags = _VALUE_FLAGS.get(family, set())
    index = 0
    while index < len(args):
        arg = args[index]
        low = arg.lower()
        if arg == "--":
            index += 1
            break
        if family == "cmd" and arg.startswith("/"):
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            if low in value_flags and index + 1 < len(args):
                index += 2
            else:
                index += 1
            continue
        return arg
    return None


def _require_allowed_script(script: str, cwd: str) -> None:
    candidate = Path(script)
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    if not candidate.is_file():
        raise CommandDenied(f"스크립트 파일이 없다: {script}")
    real = os.path.realpath(str(candidate))
    if _is_temp_path(real):
        raise CommandDenied(_MSG_TEMP)
    if not _is_allowed_script(real, cwd):
        raise CommandDenied(_MSG_SCRIPT)


def _validate_interpreter(family: str, args: Sequence[str], cwd: str) -> None:
    _deny_inline(family, args)
    script = _script_arg(family, args)
    if script is None:
        raise CommandDenied("스크립트 경로 없는 대화형/인라인 실행은 허용되지 않는다")
    _require_allowed_script(script, cwd)


def _unwrap_wrapper(name: str, args: Sequence[str]) -> tuple[str, list[str]] | None:
    args = list(args)
    if name == "env":
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "--":
                index += 1
                break
            if arg in {"-i", "--ignore-environment", "-0", "--null"}:
                index += 1
                continue
            if arg in {"-u", "--unset"}:
                index += 2
                continue
            if arg.startswith("-u") and len(arg) > 2:
                index += 1
                continue
            if arg.startswith("--unset="):
                index += 1
                continue
            if not arg.startswith("-") and "=" in arg:
                index += 1
                continue
            break
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    if name == "nice":
        index = 0
        while index < len(args) and args[index].startswith("-"):
            if args[index] in {"-n", "--adjustment"}:
                index += 2
            else:
                index += 1
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    if name == "timeout":
        index = 0
        while index < len(args) and args[index].startswith("-"):
            if args[index] in {"-k", "--kill-after", "-s", "--signal"}:
                index += 2
            else:
                index += 1
        index += 1  # duration
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    if name == "stdbuf":
        index = 0
        while index < len(args) and args[index].startswith("-"):
            if args[index] in {"-i", "-o", "-e"}:
                index += 2
            else:
                index += 1
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    if name in {"nohup", "setsid"}:
        index = 0
        while index < len(args) and args[index].startswith("-"):
            index += 1
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    if name == "xargs":
        index = 0
        while index < len(args) and args[index].startswith("-"):
            if args[index] in {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"}:
                index += 2
            else:
                index += 1
        if index >= len(args):
            return None
        return args[index], args[index + 1 :]
    return None


def _resolve_cwd(cwd: str | None) -> str:
    if cwd is None:
        return os.getcwd()
    if not isinstance(cwd, str) or "\x00" in cwd or not cwd:
        raise CommandDenied("작업 폴더 경로가 올바르지 않다")
    path = Path(cwd)
    if not path.is_absolute():
        path = Path(os.getcwd()) / path
    if not path.is_dir():
        raise CommandDenied(f"작업 폴더가 없다: {cwd}")
    return os.path.realpath(str(path))


def _validate(cmd: str, args: list[str], cwd: str | None, depth: int) -> str:
    if depth > 5:
        raise CommandDenied("래퍼 명령이 너무 깊이 중첩되어 있다")
    if not isinstance(cmd, str) or not cmd.strip():
        raise CommandDenied("실행 명령이 비어 있다")
    if "\x00" in cmd:
        raise CommandDenied("실행 명령에 NUL 문자가 있다")
    for arg in args:
        if not isinstance(arg, str):
            raise CommandDenied("인자에 문자열이 아닌 값이 있다")
        if "\x00" in arg:
            raise CommandDenied("인자에 NUL 문자가 있다")
    workdir = _resolve_cwd(cwd)
    name = _basename(cmd)
    unwrapped = _unwrap_wrapper(name, args) if name in _WRAPPERS else None
    if unwrapped is not None:
        return _validate(unwrapped[0], list(unwrapped[1]), workdir, depth + 1)
    resolved = _resolve_executable(cmd, workdir)
    if _is_temp_path(resolved):
        raise CommandDenied(_MSG_TEMP)
    family = _interpreter_family(name)
    if family:
        if not _is_trusted_interpreter(resolved):
            raise CommandDenied(f"신뢰할 수 없는 인터프리터 경로다: {resolved}")
        _validate_interpreter(family, args, workdir)
        return resolved
    if not _is_allowed_binary(resolved, workdir):
        raise CommandDenied(f"허용되지 않은 실행 파일 경로다: {resolved}")
    return resolved


def validate_command(cmd: str, args: Sequence[str], cwd: str | None = None) -> str:
    """실행 요청을 검증하고 실행할 실제 경로를 돌려준다. 거부하면 CommandDenied."""
    return _validate(cmd, list(args), cwd, 0)


def _validate_extra_env(extra: Any) -> dict[str, str]:
    if extra is None:
        return {}
    if not isinstance(extra, dict) or len(extra) > 64:
        raise CommandDenied("env 값이 올바르지 않다")
    clean: dict[str, str] = {}
    for key, value in extra.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise CommandDenied("env 값이 올바르지 않다")
        if not key or "=" in key or "\x00" in key or "\x00" in value or len(value) > 65536:
            raise CommandDenied("env 값이 올바르지 않다")
        clean[key] = value
    return clean


# ---------------------------------------------------------------------------
# 주입 엔진
# ---------------------------------------------------------------------------


class Injection:
    def __init__(self):
        self.env: dict[str, str] = {}
        self.patterns: list[bytes] = []
        self.temp_files: list[Path] = []
        self.temp_dirs: list[Path] = []


def build_injection(snapshot: dict[str, dict], tmp_root: Path) -> Injection:
    injection = Injection()
    injection.patterns = secret_patterns(snapshot)
    run_dir: Path | None = None
    for name in sorted(snapshot):
        entry = snapshot[name]
        if entry.get("type") == "string":
            injection.env[name] = entry.get("value", "")
            continue
        try:
            raw = base64.b64decode(entry.get("value", ""), validate=True)
        except (ValueError, base64.binascii.Error):
            raise ValueError(f"파일 시크릿을 읽지 못했다: {name}") from None
        if run_dir is None:
            _mkdir_private(tmp_root)
            run_dir = Path(tempfile.mkdtemp(prefix=f"run-{uuid.uuid4().hex[:8]}-", dir=str(tmp_root)))
            try:
                os.chmod(run_dir, 0o700)
            except OSError:
                pass
            injection.temp_dirs.append(run_dir)
        extension = entry.get("extension") or ".bin"
        if not EXT_RE.match(extension):
            extension = ".bin"
        file_path = run_dir / f"{uuid.uuid4().hex}{extension}"
        fd = os.open(
            str(file_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG,
            0o600,
        )
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
        injection.temp_files.append(file_path)
        injection.env[name] = str(file_path)
    return injection


def _shred_file(path: Path) -> None:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    except OSError:
        size = 0
    try:
        with open(path, "r+b", buffering=0) as handle:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 65536)
                handle.write(b"\x00" * chunk)
                remaining -= chunk
            handle.flush()
            os.fsync(handle.fileno())
            handle.truncate(0)
    except FileNotFoundError:
        return
    except OSError as exc:
        LOG.warning("임시 시크릿 파일을 덮어쓰지 못했다: %s (%s)", path.name, type(exc).__name__)
    for _ in range(40):
        try:
            path.unlink()
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.05)
    LOG.error("임시 시크릿 파일을 지우지 못했다: %s", path)


def cleanup_injection(injection: Injection) -> None:
    for path in injection.temp_files:
        _shred_file(path)
    for directory in injection.temp_dirs:
        for _ in range(20):
            try:
                directory.rmdir()
                break
            except FileNotFoundError:
                break
            except OSError:
                try:
                    for child in directory.iterdir():
                        _shred_file(child)
                except OSError:
                    pass
                time.sleep(0.05)
        else:
            LOG.error("임시 시크릿 폴더를 지우지 못했다: %s", directory)
    injection.temp_files.clear()
    injection.temp_dirs.clear()


# ---------------------------------------------------------------------------
# 소켓 서버
# ---------------------------------------------------------------------------


def send_request(socket_path: Path | str, payload: dict, timeout: float = 15.0) -> dict:
    """관리용 단일 요청/응답. CLI와 테스트가 함께 쓴다."""
    sock, token = open_client_connection(socket_path, timeout=timeout)
    body = dict(payload)
    if token is not None:
        body["token"] = token
    try:
        sock.sendall(json.dumps(body, ensure_ascii=False).encode("utf-8") + b"\n")
        with sock.makefile("rb") as reader:
            line = reader.readline(MAX_REQUEST_BYTES + 1)
    finally:
        sock.close()
    if not line:
        raise ConnectionError("데몬이 응답하지 않았다")
    try:
        return json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ConnectionError("데몬 응답을 해석하지 못했다") from None


def daemon_reachable(socket_path: Path | str) -> bool:
    try:
        response = send_request(socket_path, {"op": "status"}, timeout=2.0)
    except (OSError, ConnectionError, ValueError):
        return False
    return bool(response.get("ok"))


class _Sender:
    def __init__(self, conn: socket.socket):
        self._conn = conn
        self._lock = threading.Lock()

    def send(self, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
        with self._lock:
            self._conn.sendall(data)


class _RunContext:
    def __init__(self, proc: subprocess.Popen):
        self.proc = proc

    def terminate(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                self.proc.kill()
            except OSError:
                pass


class SecretVaultDaemon:
    def __init__(
        self,
        socket_path: Path,
        store_path: Path,
        tmp_root: Path,
        *,
        use_keyring: bool,
        key_backend: str = "auto",
    ):
        self.socket_path = Path(socket_path)
        self.tmp_root = Path(tmp_root)
        self.vault = SecretVault(
            VaultStore(Path(store_path), use_keyring=use_keyring, key_backend=key_backend)
        )
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._bound = False
        self._token: str | None = None
        self._runs: set[_RunContext] = set()
        self._injections: set[Injection] = set()
        self._runs_lock = threading.Lock()
        self._started = time.time()
        # 시작 시점에 저장소를 미리 열어 손상을 조기에 발견한다.
        self.vault.list()

    # --- 수명주기 ---------------------------------------------------------

    def serve_forever(self) -> None:
        _mkdir_private(self.socket_path.parent)
        if self.socket_path.exists():
            if daemon_reachable(self.socket_path):
                raise StoreError(f"이미 데몬이 실행 중이다: {self.socket_path}")
            try:
                self.socket_path.unlink()
            except OSError as exc:
                raise StoreError(f"오래된 소켓 파일을 지우지 못했다 ({type(exc).__name__})") from None
        if _supports_unix_socket():
            encoded = os.fsencode(str(self.socket_path))
            if len(encoded) >= 104:
                raise StoreError(
                    "소켓 경로가 너무 길다"
                    f"({len(encoded)}바이트). --socket으로 더 짧은 경로를 지정하라: {self.socket_path}"
                )
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            # AF_UNIX가 없는 Windows 빌드용 fallback: 127.0.0.1 임의 포트 + 0600
            # 정보 파일(접속 토큰 포함). 소켓 경로 파일은 그대로 --socket으로 받는다.
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._token = secrets.token_urlsafe(32)
        try:
            if _supports_unix_socket():
                server.bind(str(self.socket_path))
                self._bound = True
                try:
                    os.chmod(self.socket_path, 0o600)
                except OSError:
                    pass
            else:
                server.bind(("127.0.0.1", 0))
                self._bound = True
                port = int(server.getsockname()[1])
                info = {
                    "transport": "tcp",
                    "host": "127.0.0.1",
                    "port": port,
                    "token": self._token,
                }
                _atomic_write(self.socket_path, json.dumps(info).encode("utf-8"))
            server.listen(16)
            server.settimeout(0.5)
            self._server = server
            LOG.info("시크릿 볼트 데몬이 시작됐다. socket=%s pid=%d", self.socket_path, os.getpid())
            while not self._stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._client, args=(conn,), daemon=True).start()
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._shutdown()
            LOG.info("시크릿 볼트 데몬이 종료됐다.")

    def stop(self) -> None:
        self._stop.set()

    def _shutdown(self) -> None:
        with self._runs_lock:
            runs = list(self._runs)
            injections = list(self._injections)
        for context in runs:
            context.terminate()
        for injection in injections:
            cleanup_injection(injection)
        if self._bound:
            try:
                if self.socket_path.exists():
                    self.socket_path.unlink()
            except OSError as exc:
                LOG.warning("소켓 파일을 지우지 못했다 (%s)", type(exc).__name__)

    # --- 연결 처리 --------------------------------------------------------

    def _peer_allowed(self, conn: socket.socket) -> bool:
        if self._token is not None:  # TCP loopback fallback은 파일 권한 + 토큰으로 인증한다.
            return True
        if not hasattr(socket, "SO_PEERCRED") or not sys.platform.startswith("linux"):
            return True
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
        except OSError:
            return False
        return uid == os.getuid()

    def _token_ok(self, request: dict) -> bool:
        if self._token is None:
            return True
        supplied = request.get("token")
        return isinstance(supplied, str) and hmac.compare_digest(supplied, self._token)

    def _client(self, conn: socket.socket) -> None:
        try:
            if not self._peer_allowed(conn):
                LOG.warning("다른 사용자(uid)의 소켓 연결을 거부했다.")
                return
            read_sock = conn.makefile("rb")
            try:
                line = read_sock.readline(MAX_REQUEST_BYTES + 1)
            finally:
                read_sock.close()
            if not line:
                return
            if len(line) > MAX_REQUEST_BYTES:
                _Sender(conn).send({"ok": False, "error": "요청이 너무 크다"})
                return
            try:
                request = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                _Sender(conn).send({"ok": False, "error": "요청 JSON이 올바르지 않다"})
                return
            if not isinstance(request, dict):
                _Sender(conn).send({"ok": False, "error": "요청은 JSON 객체여야 한다"})
                return
            if not self._token_ok(request):
                LOG.warning("접속 토큰이 맞지 않는 연결을 거부했다.")
                _Sender(conn).send({"ok": False, "error": "인증 실패"})
                return
            self._dispatch(conn, request)
        except (OSError, ConnectionError) as exc:
            LOG.debug("클라이언트 연결이 끊겼다 (%s)", type(exc).__name__)
        except Exception as exc:  # 데몬 스레드가 조용히 죽지 않게 기록만 한다
            LOG.exception("클라이언트 요청 처리 중 예상하지 못한 오류 (%s)", type(exc).__name__)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, conn: socket.socket, request: dict) -> None:
        sender = _Sender(conn)
        op = request.get("op")
        try:
            if op == "status":
                sender.send(
                    {
                        "ok": True,
                        "version": VERSION,
                        "pid": os.getpid(),
                        "uptime": round(time.time() - self._started, 1),
                        "secrets": len(self.vault.list()),
                    }
                )
            elif op == "list":
                sender.send({"ok": True, "secrets": self.vault.list()})
            elif op == "set":
                name = request.get("name")
                value = request.get("value")
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError("name/value는 문자열이어야 한다")
                self.vault.set_string(name, value)
                sender.send({"ok": True})
            elif op == "set-file":
                name = request.get("name")
                encoded = request.get("content")
                extension = request.get("extension") or ".bin"
                if not isinstance(name, str) or not isinstance(encoded, str):
                    raise ValueError("name/content는 문자열이어야 한다")
                try:
                    content = base64.b64decode(encoded.encode("ascii"), validate=True)
                except (ValueError, UnicodeEncodeError):
                    raise ValueError("content가 올바른 base64가 아니다") from None
                self.vault.set_file(name, content, extension if isinstance(extension, str) else ".bin")
                sender.send({"ok": True})
            elif op == "delete":
                name = request.get("name")
                if not isinstance(name, str):
                    raise ValueError("name은 문자열이어야 한다")
                existed = self.vault.delete(name)
                sender.send({"ok": True, "existed": existed})
            elif op == "stop":
                sender.send({"ok": True})
                self.stop()
            elif op == "run":
                self._handle_run(conn, sender, request)
            else:
                sender.send({"ok": False, "error": f"알 수 없는 op다: {op!r}"})
        except CommandDenied as exc:
            sender.send({"ok": False, "error": str(exc), "denied": True})
        except (ValueError, KeyError) as exc:
            sender.send({"ok": False, "error": str(exc) or type(exc).__name__})
        except StoreError as exc:
            sender.send({"ok": False, "error": str(exc)})
        except OSError as exc:
            sender.send({"ok": False, "error": f"데몬 처리 중 오류: {type(exc).__name__}"})

    # --- 격리 실행 --------------------------------------------------------

    def _handle_run(self, conn: socket.socket, sender: _Sender, request: dict) -> None:
        cmd = request.get("cmd")
        args = request.get("args") or []
        if not isinstance(args, list):
            raise ValueError("args는 배열이어야 한다")
        extra_env = _validate_extra_env(request.get("env"))
        cwd = request.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("cwd는 문자열이어야 한다")
        try:
            resolved = validate_command(cmd, args, cwd)
        except CommandDenied as exc:
            sender.send({"type": "error", "code": "denied", "message": str(exc)})
            sender.send({"type": "exit", "code": 126})
            return
        workdir = _resolve_cwd(cwd)
        try:
            injection = build_injection(self.vault.snapshot(), self.tmp_root)
        except (ValueError, OSError) as exc:
            sender.send({"type": "error", "code": "injection", "message": f"시크릿 주입 준비 실패: {type(exc).__name__}"})
            sender.send({"type": "exit", "code": 126})
            return
        env = os.environ.copy()
        env.update(extra_env)
        env.update(injection.env)
        try:
            proc = subprocess.Popen(
                [resolved, *args],
                cwd=workdir,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            cleanup_injection(injection)
            sender.send({"type": "error", "code": "spawn", "message": f"프로세스를 시작하지 못했다: {type(exc).__name__}"})
            sender.send({"type": "exit", "code": 126})
            return
        context = _RunContext(proc)
        with self._runs_lock:
            self._runs.add(context)
        try:
            sender.send({"type": "start", "pid": proc.pid})
            with self._runs_lock:
                self._injections.add(injection)
            out_thread = threading.Thread(
                target=self._pump,
                args=(proc.stdout, sender, "stdout", StreamSanitizer(injection.patterns), context),
                daemon=True,
            )
            err_thread = threading.Thread(
                target=self._pump,
                args=(proc.stderr, sender, "stderr", StreamSanitizer(injection.patterns), context),
                daemon=True,
            )
            out_thread.start()
            err_thread.start()
            code = proc.wait()
            out_thread.join(timeout=15)
            err_thread.join(timeout=15)
            cleanup_injection(injection)
            try:
                sender.send({"type": "exit", "code": code})
            except OSError:
                pass
            LOG.info("격리 실행 종료: %s (exit=%s)", _basename(str(cmd)), code)
        finally:
            with self._runs_lock:
                self._runs.discard(context)
                self._injections.discard(injection)
            try:
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
            except OSError:
                pass

    def _pump(self, pipe, sender: _Sender, kind: str, sanitizer: StreamSanitizer, context: _RunContext) -> None:
        if pipe is None:
            return
        try:
            while True:
                chunk = pipe.read1(65536)
                if not chunk:
                    break
                safe = sanitizer.feed(chunk)
                if safe:
                    sender.send({"type": kind, "data": _b64e(safe)})
            tail = sanitizer.flush()
            if tail:
                sender.send({"type": kind, "data": _b64e(tail)})
        except (OSError, ValueError):
            context.terminate()
        finally:
            try:
                pipe.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def stop_daemon(socket_path: Path) -> int:
    try:
        response = send_request(socket_path, {"op": "stop"}, timeout=5.0)
    except (OSError, ConnectionError):
        print(f"실행 중인 시크릿 볼트 데몬이 없다: {socket_path}", file=sys.stderr)
        return 1
    if not response.get("ok"):
        print(f"데몬 종료 요청이 거부됐다: {response.get('error')}", file=sys.stderr)
        return 1
    for _ in range(100):
        if not Path(socket_path).exists():
            print(f"[OK] 시크릿 볼트 데몬을 종료했다. socket={socket_path}")
            return 0
        time.sleep(0.05)
    print(f"[WARN] 종료 요청은 보냈지만 소켓 파일이 남아 있다: {socket_path}", file=sys.stderr)
    return 1


def _spawn_background(argv: list[str], log_path: Path) -> int:
    _mkdir_private(log_path.parent)
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--foreground", *argv]
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        creationflags = 0
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        kwargs["creationflags"] = creationflags
    with open(log_path, "ab") as log_handle:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            close_fds=True,
            **kwargs,
        )
    return proc.pid


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="로컬 시크릿 볼트 데몬 (수동/테스트 구동 전용, 시스템 서비스 등록 없음)",
    )
    parser.add_argument("--socket", default=str(default_socket_path()), help="Unix 도메인 소켓 경로")
    parser.add_argument("--store", default=None, help="암호화 저장소 파일 경로 (기본: ~/.claude/state/secret-vault/vault.enc)")
    parser.add_argument("--tmp-dir", default=None, help="파일형 시크릿 임시 생성 폴더 (기본: /dev/shm/secret-vault 또는 %%TEMP%%/secret-vault)")
    parser.add_argument(
        "--key-backend",
        choices=KEY_BACKENDS,
        default="auto",
        help="마스터 키 보관 방식. auto: OS Keyring, 안 되면 0600 키 파일. tpm2: systemd-creds로 host+TPM2에 봉인 (무인 재부팅용)",
    )
    parser.add_argument("--foreground", action="store_true", help="포그라운드에서 실행하고 로그를 콘솔로 낸다")
    parser.add_argument("--stop", action="store_true", help="실행 중인 데몬을 종료한다")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    socket_path = Path(args.socket)
    if args.stop:
        return stop_daemon(socket_path)
    store_path = Path(args.store) if args.store else default_store_path()
    tmp_root = Path(args.tmp_dir) if args.tmp_dir else default_tmp_root()
    use_keyring = args.store is None
    if not args.foreground:
        forward = ["--socket", str(socket_path)]
        if args.store:
            forward += ["--store", str(store_path)]
        if args.tmp_dir:
            forward += ["--tmp-dir", str(tmp_root)]
        if args.key_backend != "auto":
            forward += ["--key-backend", args.key_backend]
        pid = _spawn_background(forward, default_state_dir() / "daemon.log")
        print(f"[OK] 시크릿 볼트 데몬을 백그라운드로 시작했다. pid={pid} socket={socket_path}")
        return 0
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        daemon = SecretVaultDaemon(
            socket_path, store_path, tmp_root, use_keyring=use_keyring, key_backend=args.key_backend
        )
    except StoreError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 5

    def _handle_signal(_signum, _frame):
        daemon.stop()

    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _handle_signal)
            except (ValueError, OSError):
                pass
    try:
        daemon.serve_forever()
    except StoreError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        daemon.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
