#!/usr/bin/env python3
"""tools.py — 시크릿 볼트 TUI (등록·제거).

실행 중인 데몬(secret-vaultd)에 소켓으로 붙어 키 목록을 보여 주고, 시크릿을
등록·덮어쓰기·제거한다. 값은 화면에 절대 그리지 않는다(입력 중에도 표시하지 않음).

    python tools.py
    python tools.py --socket /path/to/secret-vault.sock

조작: ↑/↓ 이동, a 문자열 등록, f 파일 등록, d 제거, r 새로고침, q 종료
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import os
import sys
from pathlib import Path
from typing import Protocol, Sequence

ADMIN_PATH = Path(__file__).resolve().parent / "claude" / "bin" / "secret-vault.py"


def _load_admin():
    spec = importlib.util.spec_from_file_location("secret_vault_admin", ADMIN_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"관리자 CLI 모듈을 불러오지 못했다: {ADMIN_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


admin = _load_admin()


class VaultError(Exception):
    """데몬 연결 실패나 요청 거부. 메시지는 사용자에게 그대로 보여 준다."""


class VaultClient:
    def __init__(self, socket_path: Path):
        self.socket_path = Path(socket_path)

    def _request(self, payload: dict) -> dict:
        try:
            response = admin.core.send_request(self.socket_path, payload, timeout=60.0)
        except (OSError, ConnectionError) as exc:
            raise VaultError(f"데몬에 연결할 수 없습니다: {self.socket_path} ({type(exc).__name__})") from None
        if not response.get("ok"):
            raise VaultError(str(response.get("error") or "데몬이 요청을 처리하지 못했습니다."))
        return response

    def list(self) -> list[dict]:
        return list(self._request({"op": "list"}).get("secrets") or [])

    def set_string(self, name: str, value: str) -> None:
        self._request({"op": "set", "name": name, "value": value})

    def set_file(self, name: str, content: bytes, extension: str) -> None:
        self._request(
            {
                "op": "set-file",
                "name": name,
                "content": base64.b64encode(content).decode("ascii"),
                "extension": extension,
            }
        )

    def delete(self, name: str) -> bool:
        return bool(self._request({"op": "delete", "name": name}).get("existed"))


class Prompter(Protocol):
    def ask_text(self, prompt: str) -> str | None: ...
    def ask_secret(self, prompt: str) -> str | None: ...
    def confirm(self, prompt: str) -> bool: ...


# --- 화면과 무관한 동작 (시험 대상) ------------------------------------------------

def register(client: VaultClient, ui: Prompter, *, kind: str) -> str:
    """키 이름을 받고, 이미 있으면 덮어쓸지 물은 뒤 값을 받아 등록한다."""
    name = (ui.ask_text("키 이름: ") or "").strip()
    if not name:
        return "등록을 취소했습니다."
    existing = {str(row.get("name")) for row in client.list()}
    overwrite = name in existing
    if overwrite and not ui.confirm(f"'{name}': 이미 등록된 키 입니다. 덮어 쓰시겠습니까? (y/N)"):
        return "등록을 취소했습니다."
    if kind == "file":
        raw_path = (ui.ask_text("파일 경로: ") or "").strip()
        if not raw_path:
            return "등록을 취소했습니다."
        path = Path(raw_path).expanduser()
        try:
            content = path.read_bytes()
        except OSError as exc:
            return f"파일을 읽지 못했습니다: {path} ({type(exc).__name__})"
        if len(content) > admin.MAX_FILE_BYTES:
            return f"파일이 너무 큽니다(최대 {admin.MAX_FILE_BYTES}바이트)."
        client.set_file(name, content, path.suffix or ".bin")
    else:
        value = ui.ask_secret("값 (입력해도 화면에 보이지 않습니다, Esc 취소): ")
        if value is None:
            return "등록을 취소했습니다."
        if value == "":
            return "빈 값은 등록할 수 없습니다."
        client.set_string(name, value)
    return f"'{name}'을(를) {'덮어썼습니다' if overwrite else '등록했습니다'}."


def remove(client: VaultClient, ui: Prompter, name: str | None) -> str:
    if not name:
        return "제거할 키가 없습니다."
    if not ui.confirm(f"'{name}'을(를) 제거하시겠습니까? (y/N)"):
        return "제거를 취소했습니다."
    if client.delete(name):
        return f"'{name}'을(를) 제거했습니다."
    return f"'{name}'은(는) 이미 없습니다."


# --- curses 화면 -----------------------------------------------------------------

HELP = "↑/↓ 이동  a 등록  f 파일 등록  d 제거  r 새로고침  q 종료"


class CursesUI:
    def __init__(self, stdscr, client: VaultClient):
        import curses

        self.curses = curses
        self.stdscr = stdscr
        self.client = client
        self.rows: list[dict] = []
        self.selected = 0
        self.status = ""

    # 그리기
    def _put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        height, width = self.stdscr.getmaxyx()
        if 0 <= y < height and width > x:
            try:
                self.stdscr.addnstr(y, x, text, width - x - 1, attr)
            except self.curses.error:
                pass

    def refresh_rows(self) -> None:
        try:
            self.rows = sorted(self.client.list(), key=lambda row: str(row.get("name")))
        except VaultError as exc:
            self.rows = []
            self.status = str(exc)
        self.selected = max(0, min(self.selected, len(self.rows) - 1))

    def draw(self) -> None:
        curses = self.curses
        self.stdscr.erase()
        height, _ = self.stdscr.getmaxyx()
        self._put(0, 0, f"시크릿 볼트 — {self.client.socket_path}", curses.A_BOLD)
        self._put(1, 0, f"{'이름':<34}{'타입':<8}", curses.A_UNDERLINE)
        if not self.rows:
            self._put(2, 0, "(등록된 시크릿이 없습니다)")
        list_height = max(1, height - 5)
        top = max(0, self.selected - list_height + 1)
        for offset, row in enumerate(self.rows[top : top + list_height]):
            index = top + offset
            attr = curses.A_REVERSE if index == self.selected else 0
            self._put(2 + offset, 0, f"{str(row.get('name')):<34}{str(row.get('type')):<8}", attr)
        self._put(height - 2, 0, self.status)
        self._put(height - 1, 0, HELP, curses.A_DIM)
        self.stdscr.refresh()

    def _prompt_line(self, prompt: str) -> int:
        height, _ = self.stdscr.getmaxyx()
        y = height - 2
        self.stdscr.move(y, 0)
        self.stdscr.clrtoeol()
        self._put(y, 0, prompt, self.curses.A_BOLD)
        return y

    def _read_line(self, prompt: str, *, hidden: bool) -> str | None:
        """한 줄 입력. hidden이면 아무것도 그리지 않는다. Esc면 None."""
        curses = self.curses
        y = self._prompt_line(prompt)
        x = min(len(prompt) + 1, self.stdscr.getmaxyx()[1] - 1)
        chars: list[str] = []
        curses.curs_set(1)
        try:
            while True:
                if not hidden:
                    self.stdscr.move(y, x)
                    self.stdscr.clrtoeol()
                    self._put(y, x, "".join(chars))
                self.stdscr.refresh()
                ch = self.stdscr.get_wch()
                if ch in ("\n", "\r") or ch == curses.KEY_ENTER:
                    return "".join(chars)
                if ch == "\x1b":
                    return None
                if ch in ("\b", "\x7f", curses.KEY_BACKSPACE):
                    if chars:
                        chars.pop()
                    continue
                if isinstance(ch, str) and ch.isprintable():
                    chars.append(ch)
        finally:
            curses.curs_set(0)

    def ask_text(self, prompt: str) -> str | None:
        return self._read_line(prompt, hidden=False)

    def ask_secret(self, prompt: str) -> str | None:
        return self._read_line(prompt, hidden=True)

    def confirm(self, prompt: str) -> bool:
        self._prompt_line(prompt)
        self.stdscr.refresh()
        ch = self.stdscr.get_wch()
        return ch in ("y", "Y")

    def run(self) -> None:
        curses = self.curses
        curses.curs_set(0)
        self.stdscr.keypad(True)
        self.refresh_rows()
        while True:
            self.draw()
            ch = self.stdscr.get_wch()
            if ch in ("q", "Q"):
                return
            if ch in (curses.KEY_UP, "k"):
                self.selected = max(0, self.selected - 1)
            elif ch in (curses.KEY_DOWN, "j"):
                self.selected = min(max(0, len(self.rows) - 1), self.selected + 1)
            elif ch in ("r", "R"):
                self.status = ""
                self.refresh_rows()
            elif ch in ("a", "A", "f", "F", "d", "D", curses.KEY_DC):
                try:
                    if ch in ("d", "D", curses.KEY_DC):
                        name = str(self.rows[self.selected].get("name")) if self.rows else None
                        self.status = remove(self.client, self, name)
                    else:
                        self.status = register(self.client, self, kind="file" if ch in ("f", "F") else "string")
                except VaultError as exc:
                    self.status = f"[오류] {exc}"
                self.refresh_rows()


def _socket_path(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    env_socket = os.environ.get("SECRET_VAULT_SOCKET")
    if env_socket:
        return Path(env_socket)
    return Path(admin.core.default_socket_path())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="시크릿 볼트 TUI (등록·제거, 값은 화면에 표시하지 않음)")
    parser.add_argument("--socket", default=None, help="데몬 소켓 경로 (기본: 플랫폼 기본 경로)")
    args = parser.parse_args(argv)
    try:
        import curses
    except ImportError:
        print("[ERROR] curses를 쓸 수 없습니다. Windows는 `pip install windows-curses`가 필요합니다.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("[ERROR] 터미널에서 직접 실행해야 합니다.", file=sys.stderr)
        return 2
    # Esc 취소가 1초씩 늦지 않게 한다(curses 기본 대기 1000ms).
    os.environ.setdefault("ESCDELAY", "25")
    client = VaultClient(_socket_path(args.socket))
    try:
        client.list()
    except VaultError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    curses.wrapper(lambda stdscr: CursesUI(stdscr, client).run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
