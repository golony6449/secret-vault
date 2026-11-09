#!/usr/bin/env python3
"""secret-vault — 관리자 CLI.

사용자가 터미널에서 직접 시크릿을 등록·조회·삭제한다. 값은 화면에 절대
출력하지 않으며, `set`은 getpass로 가려서 입력받는다.

    secret-vault list
    secret-vault set DEEPSEEK_API_KEY
    secret-vault set-file GCP_SERVICE_ACCOUNT ~/Downloads/service-account.json
    secret-vault delete OLD_API_KEY
    secret-vault status

데몬이 떠 있지 않으면 실행하지 않는다. 수동 구동:
    python claude/bin/secret-vaultd.py --foreground
"""

from __future__ import annotations

import argparse
import base64
import getpass
import importlib.util
import os
import sys
from pathlib import Path

MAX_FILE_BYTES = 8 * 1024 * 1024


def _load_core():
    path = Path(__file__).resolve().with_name("secret-vaultd.py")
    spec = importlib.util.spec_from_file_location("secret_vaultd_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"공용 모듈을 불러오지 못했다: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()


def _socket_path(args) -> Path:
    if args.socket:
        return Path(args.socket)
    env_socket = os.environ.get("SECRET_VAULT_SOCKET")
    if env_socket:
        return Path(env_socket)
    return Path(core.default_socket_path())


def _request(socket_path: Path, payload: dict, *, timeout: float = 60.0) -> dict:
    try:
        return core.send_request(socket_path, payload, timeout=timeout)
    except (OSError, ConnectionError) as exc:
        raise SystemExit(
            "시크릿 볼트 데몬에 연결할 수 없습니다: "
            f"{socket_path} ({type(exc).__name__})\n"
            "데몬을 실행하세요: python ~/.claude/bin/secret-vaultd.py --foreground"
        ) from None


def _fail(response: dict) -> None:
    print(f"[ERROR] {response.get('error') or '데몬이 요청을 처리하지 못했다.'}", file=sys.stderr)
    raise SystemExit(1)


def cmd_list(args) -> int:
    response = _request(_socket_path(args), {"op": "list"})
    if not response.get("ok"):
        _fail(response)
    secrets = response.get("secrets") or []
    if not secrets:
        print("등록된 시크릿이 없습니다.")
        return 0
    print(f"{'NAME':<32} {'TYPE':<8}")
    for item in secrets:
        name = str(item.get("name", ""))
        kind = str(item.get("type", ""))
        print(f"{name:<32} {kind:<8}")
    return 0


def _read_secret_value() -> str:
    """TTY에서는 getpass로 가려서 입력받는다.

    파이프/리다이렉션(stdin이 TTY가 아님)은 화면 에코 자체가 없으므로 한 줄을
    그대로 읽는다. Windows getpass는 파이프 입력을 무시하고 콘솔을 기다리기
    때문에 테스트·자동화에서는 이 경로가 필요하다.
    """
    stdin = sys.stdin
    try:
        interactive = stdin is not None and stdin.isatty()
    except (ValueError, OSError):
        interactive = False
    if interactive:
        return getpass.getpass("Input Value (Hidden): ")
    if stdin is None:
        return ""
    return stdin.readline().rstrip("\r\n")


def cmd_set(args) -> int:
    value = _read_secret_value()
    if value == "":
        print("[ERROR] 빈 값은 등록할 수 없습니다.", file=sys.stderr)
        return 1
    response = _request(_socket_path(args), {"op": "set", "name": args.key, "value": value})
    if not response.get("ok"):
        _fail(response)
    print(f"[OK] '{args.key}' registered in OS Keyring.")
    return 0


def cmd_set_file(args) -> int:
    path = Path(args.file_path).expanduser()
    try:
        content = path.read_bytes()
    except OSError as exc:
        print(f"[ERROR] 파일을 읽지 못했습니다: {path} ({type(exc).__name__})", file=sys.stderr)
        return 1
    if len(content) > MAX_FILE_BYTES:
        print(f"[ERROR] 파일이 너무 큽니다(최대 {MAX_FILE_BYTES}바이트).", file=sys.stderr)
        return 1
    extension = path.suffix if path.suffix else ".bin"
    response = _request(
        _socket_path(args),
        {
            "op": "set-file",
            "name": args.key,
            "content": base64.b64encode(content).decode("ascii"),
            "extension": extension,
        },
    )
    if not response.get("ok"):
        _fail(response)
    print(f"[OK] '{args.key}' file encrypted and registered. Original file can be removed.")
    return 0


def cmd_delete(args) -> int:
    response = _request(_socket_path(args), {"op": "delete", "name": args.key})
    if not response.get("ok"):
        _fail(response)
    if response.get("existed"):
        print(f"[OK] '{args.key}' deleted.")
    else:
        print(f"[INFO] '{args.key}' is not registered.")
    return 0


def cmd_status(args) -> int:
    socket_path = _socket_path(args)
    response = _request(socket_path, {"op": "status"}, timeout=5.0)
    if not response.get("ok"):
        _fail(response)
    print(
        "[OK] secret vault daemon is running "
        f"(pid={response.get('pid')}, secrets={response.get('secrets')}, "
        f"uptime={response.get('uptime')}s). socket={socket_path}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="로컬 시크릿 볼트 관리자 CLI (값은 화면에 출력하지 않는다)",
    )
    parser.add_argument("--socket", default=None, help="데몬 소켓 경로 (기본: 플랫폼 기본 경로)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="등록된 키 이름과 타입만 출력한다").set_defaults(func=cmd_list)

    set_parser = sub.add_parser("set", help="문자열 시크릿을 숨김 입력으로 등록한다")
    set_parser.add_argument("key")
    set_parser.set_defaults(func=cmd_set)

    file_parser = sub.add_parser("set-file", help="파일 내용을 시크릿으로 등록한다")
    file_parser.add_argument("key")
    file_parser.add_argument("file_path")
    file_parser.set_defaults(func=cmd_set_file)

    delete_parser = sub.add_parser("delete", help="키를 삭제한다")
    delete_parser.add_argument("key")
    delete_parser.set_defaults(func=cmd_delete)

    sub.add_parser("status", help="데몬 연결 상태를 확인한다").set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
