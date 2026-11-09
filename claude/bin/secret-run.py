#!/usr/bin/env python3
"""secret-run — 시크릿 볼트 격리 러너.

에이전트나 사용자가 시크릿을 직접 다루지 않고 명령을 실행하는 래퍼.

    secret-run gh pr create --title "..."
    secret-run litestream replicate
    secret-run python path/to/script.py --task task-123

데몬이 명령을 검증(RCE 차단)한 뒤 자식 프로세스에만 시크릿을 주입하고,
출력은 마스킹해서 돌려준다. 데몬이 떠 있지 않으면 실행하지 않는다.
수동 구동:
    python claude/bin/secret-vaultd.py --foreground
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

USAGE = "사용법: secret-run [--socket <경로>] <명령> [인자...]"


def _load_core():
    path = Path(__file__).resolve().with_name("secret-vaultd.py")
    spec = importlib.util.spec_from_file_location("secret_vaultd_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"공용 모듈을 불러오지 못했다: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()


def _parse_argv(argv: list[str]) -> tuple[Path, list[str]]:
    socket_arg: str | None = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in {"-h", "--help"}:
            print(USAGE)
            raise SystemExit(0)
        if arg == "--socket":
            if index + 1 >= len(argv):
                print("--socket 뒤에 경로가 필요합니다.", file=sys.stderr)
                raise SystemExit(2)
            socket_arg = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--socket="):
            socket_arg = arg.split("=", 1)[1]
            index += 1
            continue
        if arg == "--":
            index += 1
            break
        break
    command = argv[index:]
    if not command:
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)
    socket_path = Path(
        socket_arg or os.environ.get("SECRET_VAULT_SOCKET") or core.default_socket_path()
    )
    return socket_path, command


def _write(stream, data: bytes) -> None:
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:  # 테스트에서 StringIO로 바꿔치기한 경우
        stream.write(data.decode("utf-8", errors="replace"))
        stream.flush()


def main(argv: list[str] | None = None) -> int:
    socket_path, command = _parse_argv(list(sys.argv[1:] if argv is None else argv))
    request = {
        "op": "run",
        "cmd": command[0],
        "args": command[1:],
        "cwd": os.getcwd(),
        "env": {},
    }
    try:
        sock, token = core.open_client_connection(socket_path, timeout=None)
    except (OSError, ConnectionError) as exc:
        print(
            "시크릿 볼트 데몬에 연결할 수 없습니다: "
            f"{socket_path} ({type(exc).__name__})\n"
            "데몬을 실행하세요: python ~/.claude/bin/secret-vaultd.py --foreground",
            file=sys.stderr,
        )
        return 2
    if token is not None:
        request["token"] = token
    try:
        sock.sendall(json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n")
        reader = sock.makefile("rb")
        fallback_code = 126
        while True:
            line = reader.readline(core.MAX_REQUEST_BYTES + 1)
            if not line:
                print("[ERROR] 데몬과의 연결이 종료됐다(종료 코드를 받지 못했다).", file=sys.stderr)
                return 2
            try:
                event = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                print("[ERROR] 데몬 응답을 해석하지 못했다.", file=sys.stderr)
                return 2
            kind = event.get("type")
            if kind == "stdout":
                _write(sys.stdout, base64.b64decode(event.get("data", "")))
            elif kind == "stderr":
                _write(sys.stderr, base64.b64decode(event.get("data", "")))
            elif kind == "error":
                message = event.get("message") or "실행이 거부됐다."
                print(f"[DENIED] {message}" if event.get("code") == "denied" else f"[ERROR] {message}", file=sys.stderr)
                fallback_code = 126 if event.get("code") == "denied" else 1
            elif kind == "exit":
                try:
                    return int(event.get("code", fallback_code))
                except (TypeError, ValueError):
                    return fallback_code
            elif event.get("ok") is False:
                print(f"[ERROR] {event.get('error')}", file=sys.stderr)
                return 1
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
