#!/usr/bin/env python3
"""secret-vault-service — 시크릿 볼트 데몬을 systemd 사용자 유닛으로 등록/해제한다.

데몬(secret-vaultd.py)은 스스로 서비스를 등록하지 않는다. 재부팅 뒤 자동 기동이
필요한 사용자가 이 스크립트를 직접 실행할 때만 등록한다.

  * 사용자 유닛(~/.config/systemd/user/secret-vaultd.service)만 쓴다. root가 필요 없다.
  * `loginctl enable-linger`로 로그인하지 않아도 부팅 때 사용자 매니저가 뜨게 한다.
  * 기본 마스터 키 방식은 tpm2다(무인 재부팅용). `--key-backend auto`로 바꿀 수 있다.

사용 예:
    python claude/bin/secret-vault-service.py install --dry-run
    python claude/bin/secret-vault-service.py install
    python claude/bin/secret-vault-service.py status
    python claude/bin/secret-vault-service.py uninstall
"""

from __future__ import annotations

import argparse
import getpass
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

UNIT_NAME = "secret-vaultd.service"
KEY_BACKENDS = ("auto", "tpm2")


def default_daemon_path() -> Path:
    return Path(__file__).resolve().with_name("secret-vaultd.py")


def user_unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def render_unit(python: str, daemon: Path, key_backend: str) -> str:
    if key_backend not in KEY_BACKENDS:
        raise ValueError(f"알 수 없는 마스터 키 방식이다: {key_backend}")
    exec_start = shlex.join([python, "-B", str(daemon), "--foreground", "--key-backend", key_backend])
    return (
        "[Unit]\n"
        "Description=secret-vault 로컬 시크릿 볼트 데몬\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "UMask=0077\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _run(args: list[str], *, dry_run: bool) -> int:
    print("$ " + shlex.join(args))
    if dry_run:
        return 0
    return subprocess.run(args, check=False).returncode


def install(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        print("[ERROR] systemd 사용자 유닛 등록은 리눅스에서만 지원한다", file=sys.stderr)
        return 2
    daemon = Path(args.daemon).resolve() if args.daemon else default_daemon_path()
    if not daemon.is_file():
        print(f"[ERROR] 데몬 스크립트를 찾지 못했다: {daemon}", file=sys.stderr)
        return 2
    unit_text = render_unit(args.python, daemon, args.key_backend)
    unit_path = user_unit_dir() / UNIT_NAME
    print(f"# {unit_path}")
    print(unit_text)
    if not args.dry_run:
        unit_path.parent.mkdir(parents=True, exist_ok=True)
        unit_path.write_text(unit_text, encoding="utf-8")
    steps = [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", UNIT_NAME],
        ["loginctl", "enable-linger", getpass.getuser()],
    ]
    for step in steps:
        code = _run(step, dry_run=args.dry_run)
        if code != 0:
            print(f"[ERROR] 명령이 실패했다 (종료 코드 {code})", file=sys.stderr)
            return 1
    if args.dry_run:
        print("[DRY-RUN] 아무것도 바꾸지 않았다.")
    else:
        print(f"[OK] {UNIT_NAME}를 등록하고 시작했다. 재부팅 뒤에도 자동으로 뜬다.")
    return 0


def uninstall(args: argparse.Namespace) -> int:
    unit_path = user_unit_dir() / UNIT_NAME
    _run(["systemctl", "--user", "disable", "--now", UNIT_NAME], dry_run=args.dry_run)
    if unit_path.exists() and not args.dry_run:
        unit_path.unlink()
    print(f"# 삭제: {unit_path}")
    code = _run(["systemctl", "--user", "daemon-reload"], dry_run=args.dry_run)
    # linger는 다른 사용자 서비스도 쓸 수 있어 끄지 않는다.
    print("[OK] 유닛을 해제했다. linger는 그대로 둔다 (끄려면: loginctl disable-linger).")
    return code


def status(_args: argparse.Namespace) -> int:
    if shutil.which("systemctl") is None:
        print("[ERROR] systemctl을 찾지 못했다", file=sys.stderr)
        return 2
    return subprocess.run(["systemctl", "--user", "status", "--no-pager", UNIT_NAME], check=False).returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="시크릿 볼트 데몬 systemd 사용자 유닛 등록/해제")
    sub = parser.add_subparsers(dest="command", required=True)
    p_install = sub.add_parser("install", help="사용자 유닛을 등록하고 시작한다")
    p_install.add_argument("--key-backend", choices=KEY_BACKENDS, default="tpm2", help="마스터 키 방식 (기본: tpm2)")
    p_install.add_argument("--python", default=sys.executable, help="데몬을 돌릴 파이썬 경로 (기본: 지금 파이썬)")
    p_install.add_argument("--daemon", default=None, help="secret-vaultd.py 경로 (기본: 이 스크립트 옆)")
    p_install.add_argument("--dry-run", action="store_true", help="바꾸지 않고 유닛 내용과 실행할 명령만 보인다")
    p_install.set_defaults(func=install)
    p_uninstall = sub.add_parser("uninstall", help="사용자 유닛을 멈추고 지운다")
    p_uninstall.add_argument("--dry-run", action="store_true", help="바꾸지 않고 실행할 명령만 보인다")
    p_uninstall.set_defaults(func=uninstall)
    p_status = sub.add_parser("status", help="사용자 유닛 상태를 보인다")
    p_status.set_defaults(func=status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
