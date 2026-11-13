# secret-vault 시험. 실행: python -B -m unittest tests.test_secret_vault -v
"""시크릿 볼트 코어 단위/통합 시험.

시스템 서비스(systemd 등)는 등록하지 않는다. 데몬을 테스트 하네스가 직접
서브프로세스로 띄워 수동 구동 경로만 검증한다.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "claude" / "bin"
DAEMON = BIN / "secret-vaultd.py"
ADMIN = BIN / "secret-vault.py"
RUNNER = BIN / "secret-run.py"
PROBE_ROOT = REPO / ".ds-tmp" / "secret-vault-tests"


def load_core():
    spec = importlib.util.spec_from_file_location("secret_vaultd_under_test", DAEMON)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load_core()


def child_env() -> dict:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_process(args, **kwargs):
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    kwargs.setdefault("env", child_env())
    kwargs.setdefault("timeout", 60)
    return subprocess.run(args, **kwargs)


class SanitizerUnitTest(unittest.TestCase):
    def test_split_secret_across_chunks_is_masked(self):
        sanitizer = core.StreamSanitizer([b"abcdef123456"])
        output = b""
        for chunk in (b"xxabc", b"def123456yy", b"zz"):
            output += sanitizer.feed(chunk)
        output += sanitizer.flush()
        self.assertEqual(output, b"xx[REDACTED_SECRET]yyzz")

    def test_secret_fully_inside_chunk_is_masked(self):
        sanitizer = core.StreamSanitizer([b"token-value-1234"])
        output = sanitizer.feed(b"prefix token-value-1234 suffix") + sanitizer.flush()
        self.assertNotIn(b"token-value-1234", output)
        self.assertIn(b"[REDACTED_SECRET]", output)

    def test_short_chunk_streaming_is_lossless_without_patterns(self):
        sanitizer = core.StreamSanitizer([])
        self.assertEqual(sanitizer.feed(b"hello"), b"hello")
        self.assertEqual(sanitizer.flush(), b"")

    def test_base64_variant_is_masked(self):
        snapshot = {"MY_TOKEN": {"type": "string", "value": "plain-secret-value-1"}}
        encoded = base64.b64encode(b"plain-secret-value-1")
        sanitizer = core.StreamSanitizer(core.secret_patterns(snapshot))
        output = sanitizer.feed(b"value=" + encoded + b"\n") + sanitizer.flush()
        self.assertNotIn(encoded, output)
        self.assertIn(b"[REDACTED_SECRET]", output)

    def test_file_secret_lines_are_masked(self):
        content = b'{\n  "private_key": "-----BEGIN PRIVATE KEY-----",\n  "x": 1\n}\n'
        snapshot = {"CERT": {"type": "file", "value": base64.b64encode(content).decode("ascii")}}
        sanitizer = core.StreamSanitizer(core.secret_patterns(snapshot))
        output = sanitizer.feed(b'  "private_key": "-----BEGIN PRIVATE KEY-----"\n') + sanitizer.flush()
        self.assertNotIn(b"BEGIN PRIVATE KEY", output)
        self.assertIn(b"[REDACTED_SECRET]", output)


class StoreUnitTest(unittest.TestCase):
    def test_store_is_encrypted_at_rest_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            vault = core.SecretVault(core.VaultStore(path, use_keyring=False))
            vault.set_string("MY_KEY", "very-secret-value-123")
            raw = path.read_bytes()
            self.assertNotIn(b"very-secret-value-123", raw)
            self.assertNotIn(b"MY_KEY", raw)
            reopened = core.SecretVault(core.VaultStore(path, use_keyring=False))
            self.assertEqual(reopened.snapshot()["MY_KEY"]["value"], "very-secret-value-123")
            self.assertEqual([row["name"] for row in reopened.list()], ["MY_KEY"])
            self.assertTrue((Path(tmp) / "master.key").exists())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual((Path(tmp) / "master.key").stat().st_mode & 0o777, 0o600)

    def test_file_secret_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            vault = core.SecretVault(core.VaultStore(path, use_keyring=False))
            vault.set_file("GCP_KEY", b'{"type": "service_account"}', ".json")
            entry = vault.snapshot()["GCP_KEY"]
            self.assertEqual(entry["type"], "file")
            self.assertEqual(entry["extension"], ".json")
            self.assertEqual(base64.b64decode(entry["value"]), b'{"type": "service_account"}')

    def test_invalid_name_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = core.SecretVault(core.VaultStore(Path(tmp) / "v.enc", use_keyring=False))
            for bad in ("", "../escape", "has space", "a" * 200, "1starts_with_digit"):
                with self.assertRaises(ValueError):
                    vault.set_string(bad, "value")
            vault.set_string("GOOD_NAME_1", "value")
            self.assertTrue(vault.delete("GOOD_NAME_1"))
            self.assertFalse(vault.delete("GOOD_NAME_1"))

    def test_corrupt_store_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            path.write_bytes(b"this is not a vault")
            with self.assertRaises(core.StoreError):
                core.VaultStore(path, use_keyring=False).load()


class FakeCreds:
    """systemd-creds 대역. 봉인 결과에 평문 키가 보이지 않게 뒤집고 표식을 붙인다."""

    PREFIX = b"FAKE-TPM2-SEALED:"

    def __init__(self, *, fail_decrypt: bool = False):
        self.fail_decrypt = fail_decrypt
        self.calls: list[list[str]] = []

    def __call__(self, provider, args, data):
        self.calls.append(list(args))
        if f"--name={core.TPM2_CRED_NAME}" not in args:
            raise core.StoreError("자격증명 이름이 빠졌다")
        if args[0] == "encrypt":
            if "--with-key=host+tpm2" not in args:
                raise core.StoreError("host+tpm2 봉인이 아니다")
            return self.PREFIX + bytes(b ^ 0xFF for b in data)
        if args[0] == "decrypt":
            if self.fail_decrypt or not data.startswith(self.PREFIX):
                raise core.StoreError("systemd-creds가 실패했다 (종료 코드 1)")
            return bytes(b ^ 0xFF for b in data[len(self.PREFIX):])
        raise AssertionError(args)


class Tpm2KeyBackendTest(unittest.TestCase):
    def _patch(self, fake):
        patcher = mock.patch.object(core.KeyProvider, "_run_creds", autospec=True, side_effect=fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_new_vault_seals_key_and_writes_no_key_file(self):
        fake = FakeCreds()
        self._patch(fake)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            vault = core.SecretVault(core.VaultStore(path, key_backend="tpm2"))
            vault.set_string("FAKE_TOKEN", "fake-tpm2-value-123")
            cred = Path(tmp) / core.TPM2_CRED_FILE
            self.assertTrue(cred.exists())
            self.assertFalse((Path(tmp) / "master.key").exists())
            if os.name == "posix":
                self.assertEqual(cred.stat().st_mode & 0o777, 0o600)
            reopened = core.SecretVault(core.VaultStore(path, key_backend="tpm2"))
            self.assertEqual(reopened.snapshot()["FAKE_TOKEN"]["value"], "fake-tpm2-value-123")
            self.assertIn(["decrypt", f"--name={core.TPM2_CRED_NAME}", "-", "-"], fake.calls)

    def test_existing_key_file_is_migrated_then_removed(self):
        self._patch(FakeCreds())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            core.SecretVault(core.VaultStore(path)).set_string("FAKE_OLD", "fake-old-value")
            self.assertTrue((Path(tmp) / "master.key").exists())
            migrated = core.SecretVault(core.VaultStore(path, key_backend="tpm2"))
            self.assertEqual(migrated.snapshot()["FAKE_OLD"]["value"], "fake-old-value")
            self.assertFalse((Path(tmp) / "master.key").exists())
            self.assertTrue((Path(tmp) / core.TPM2_CRED_FILE).exists())

    def test_unseal_failure_does_not_fall_back_to_key_file(self):
        self._patch(FakeCreds(fail_decrypt=True))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            (Path(tmp) / core.TPM2_CRED_FILE).write_bytes(FakeCreds.PREFIX + b"\x00" * 32)
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(core.StoreError):
                core.VaultStore(path, key_backend="tpm2").load()
            self.assertFalse((Path(tmp) / "master.key").exists())

    def test_existing_store_without_any_key_is_not_rekeyed(self):
        fake = FakeCreds()
        self._patch(fake)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vault.enc"
            path.write_text('{"v": 1}', encoding="utf-8")
            with self.assertRaises(core.StoreError):
                core.VaultStore(path, key_backend="tpm2").load()
            self.assertFalse((Path(tmp) / core.TPM2_CRED_FILE).exists())
            self.assertEqual(fake.calls, [])

    def test_missing_systemd_creds_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(core.shutil, "which", return_value=None):
            with self.assertRaises(core.StoreError):
                core.SecretVault(core.VaultStore(Path(tmp) / "vault.enc", key_backend="tpm2")).set_string(
                    "FAKE_B", "fake-b"
                )

    def test_unknown_backend_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(core.StoreError):
                core.VaultStore(Path(tmp) / "vault.enc", key_backend="plain")


class PolicyUnitTest(unittest.TestCase):
    def setUp(self):
        self.probe_dirs: list[Path] = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for path in self.probe_dirs:
            shutil.rmtree(path, ignore_errors=True)

    def make_probe(self, body: str) -> Path:
        root = PROBE_ROOT / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        self.probe_dirs.append(root)
        script = root / "probe.py"
        script.write_text(body, encoding="utf-8")
        return script

    def test_python_inline_code_is_denied(self):
        with self.assertRaises(core.CommandDenied):
            core.validate_command(sys.executable, ["-c", "print(1)"], str(REPO))
        with self.assertRaises(core.CommandDenied):
            core.validate_command(sys.executable, ["-m", "http.server"], str(REPO))
        with self.assertRaises(core.CommandDenied):
            core.validate_command(sys.executable, [], str(REPO))

    def test_shell_inline_code_is_denied(self):
        for shell in ("sh", "bash"):
            if shutil.which(shell) is None:
                continue
            with self.assertRaises(core.CommandDenied, msg=shell):
                core.validate_command(shell, ["-c", "echo hi"], str(REPO))
            with self.assertRaises(core.CommandDenied, msg=shell + " -lc"):
                core.validate_command(shell, ["-lc", "echo hi"], str(REPO))

    def test_env_wrapper_cannot_bypass_policy(self):
        if shutil.which("env") is None:
            self.skipTest("env 바이너리가 PATH에 없다")
        with self.assertRaises(core.CommandDenied):
            core.validate_command("env", [sys.executable, "-c", "print(1)"], str(REPO))

    def test_temp_script_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "evil.py"
            script.write_text("print('nope')\n", encoding="utf-8")
            with self.assertRaises(core.CommandDenied):
                core.validate_command(sys.executable, [str(script)], tmp)
            with self.assertRaises(core.CommandDenied):
                core.validate_command(str(script), [], tmp)

    def test_repo_script_and_claude_bin_script_are_allowed(self):
        probe = self.make_probe("print('ok')\n")
        resolved = core.validate_command(sys.executable, [str(probe)], str(REPO))
        self.assertTrue(os.path.isabs(resolved))
        # ~/.claude/bin 허용: 실제 홈 폴더 대신 가짜 bin 폴더를 끼우고,
        # 레포 밖 작업 폴더에서 실행해 bin 경로 규칙만으로 허용되는지 본다.
        tool = self.make_probe("print('tool')\n")
        original = core._claude_bin_dir
        core._claude_bin_dir = lambda: tool.parent
        self.addCleanup(setattr, core, "_claude_bin_dir", original)
        with tempfile.TemporaryDirectory() as outside:
            allowed = core.validate_command(sys.executable, [str(tool)], outside)
        self.assertTrue(os.path.isabs(allowed))

    def test_script_outside_allowed_roots_is_denied(self):
        probe = self.make_probe("print('no')\n")
        with tempfile.TemporaryDirectory() as tmp:
            # 작업 폴더가 레포가 아니면 레포 스크립트도 허용되지 않는다.
            with self.assertRaises(core.CommandDenied):
                core.validate_command(sys.executable, [str(probe)], tmp)


class DaemonCase(unittest.TestCase):
    """테스트마다 임시 소켓/저장소로 데몬을 직접 띄운다(시스템 서비스 없음)."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="svtest-"))
        self.socket_path = self.base / "sv.sock"
        self.store_path = self.base / "vault.enc"
        self.tmp_dir = self.base / "run-tmp"
        self.log_path = self.base / "daemon.log"
        self.probe_dirs: list[Path] = []
        self.log_handle = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(DAEMON),
                "--foreground",
                "--socket",
                str(self.socket_path),
                "--store",
                str(self.store_path),
                "--tmp-dir",
                str(self.tmp_dir),
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log_handle,
            stderr=self.log_handle,
            cwd=str(REPO),
            env=child_env(),
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if core.daemon_reachable(self.socket_path):
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        self.fail("테스트용 데몬이 뜨지 않았다.\n" + self.daemon_log())

    def tearDown(self):
        try:
            core.send_request(self.socket_path, {"op": "stop"}, timeout=2.0)
        except (OSError, ConnectionError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        try:
            self.log_handle.close()
        except OSError:
            pass
        for path in self.probe_dirs:
            shutil.rmtree(path, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)

    def daemon_log(self) -> str:
        try:
            self.log_handle.flush()
        except ValueError:
            pass
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")[-6000:]
        except OSError:
            return "(로그 없음)"

    def admin(self, *args, input=None):
        return run_process(
            [sys.executable, "-B", str(ADMIN), "--socket", str(self.socket_path), *args],
            input=input,
            cwd=str(REPO),
        )

    def runner(self, *args, cwd=None, timeout=60):
        return run_process(
            [sys.executable, "-B", str(RUNNER), "--socket", str(self.socket_path), *args],
            cwd=str(cwd or REPO),
            timeout=timeout,
        )

    def make_probe(self, body: str) -> Path:
        root = PROBE_ROOT / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        self.probe_dirs.append(root)
        script = root / "probe.py"
        script.write_text(body, encoding="utf-8")
        return script

    def request(self, payload: dict, timeout: float = 15.0) -> dict:
        return core.send_request(self.socket_path, payload, timeout=timeout)

    # --- 공통 헬퍼 -------------------------------------------------------

    def set_string(self, name: str, value: str):
        result = self.admin("set", name, input=value + "\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("[OK]", result.stdout)
        self.assertNotIn(value, result.stdout)
        self.assertNotIn(value, result.stderr)
        return result

    def run_probe(self, script: Path):
        result = self.runner(sys.executable, str(script))
        return result


class AdminAndInjectionTest(DaemonCase):
    def test_status(self):
        result = self.admin("status")
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("running", result.stdout)
        self.assertIn(str(self.socket_path), result.stdout)

    def test_set_list_delete_flow_never_leaks_value(self):
        secret = "sup3r-secret-value-123"
        self.set_string("SV_TEST_STRING", secret)

        listing = self.admin("list")
        self.assertEqual(listing.returncode, 0, msg=listing.stderr)
        self.assertIn("SV_TEST_STRING", listing.stdout)
        self.assertIn("string", listing.stdout)
        self.assertNotIn(secret, listing.stdout)

        payload = self.request({"op": "list"})
        self.assertTrue(payload.get("ok"))
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("value", serialized)

        probe = self.make_probe(
            "import os\n"
            "value = os.environ.get('SV_TEST_STRING', '')\n"
            "print('MATCH' if value == 'sup3r-secret-value-123' else 'MISS')\n"
        )
        injected = self.run_probe(probe)
        self.assertEqual(injected.returncode, 0, msg=injected.stderr + self.daemon_log())
        self.assertIn("MATCH", injected.stdout)
        self.assertNotIn(secret, injected.stdout)
        self.assertNotIn(secret, injected.stderr)

        deleted = self.admin("delete", "SV_TEST_STRING")
        self.assertEqual(deleted.returncode, 0, msg=deleted.stderr)
        self.assertIn("[OK]", deleted.stdout)
        self.assertNotIn("SV_TEST_STRING", self.admin("list").stdout)

        missing = self.run_probe(probe)
        self.assertEqual(missing.returncode, 0, msg=missing.stderr)
        self.assertIn("MISS", missing.stdout)

    def test_string_secret_is_injected_only_to_child_env(self):
        secret = "env-only-secret-777"
        self.set_string("SV_ENV_ONLY", secret)
        probe = self.make_probe(
            "import os, sys\n"
            "print('HAS' if os.environ.get('SV_ENV_ONLY') == 'env-only-secret-777' else 'NONE')\n"
            "print('OWN_ENV_HAS' if 'SV_ENV_ONLY' in os.environ else 'NO')\n"
        )
        result = self.run_probe(probe)
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("HAS", result.stdout)
        self.assertIn("OWN_ENV_HAS", result.stdout)
        # 데몬 로그에는 시크릿 값이 남지 않는다.
        self.assertNotIn(secret, self.daemon_log())

    def test_file_secret_lifecycle_and_shredding(self):
        content = (
            b'{"type": "service_account",\n'
            b' "private_key": "-----BEGIN PRIVATE KEY-----abcdefg\\n-----END PRIVATE KEY-----\\n",\n'
            b' "client_email": "svc@example.invalid"\n}'
        )
        source = self.base / "service-account.json"
        source.write_bytes(content)
        result = self.admin("set-file", "SV_TEST_FILE", str(source))
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("[OK]", result.stdout)
        self.assertIn("SV_TEST_FILE", self.admin("list").stdout)

        probe = self.make_probe(
            "import os\n"
            "path = os.environ.get('SV_TEST_FILE', '')\n"
            "print('PATH=' + path)\n"
            "if not path or not os.path.exists(path):\n"
            "    print('MISSING')\n"
            "    raise SystemExit(0)\n"
            "with open(path, 'rb') as handle:\n"
            "    data = handle.read()\n"
            "print('CONTENT_MATCH' if data == "
            + repr(content)
            + " else 'CONTENT_DIFF')\n"
            "if os.name == 'posix':\n"
            "    print('MODE=%o' % (os.stat(path).st_mode & 0o777))\n"
        )
        first = self.run_probe(probe)
        self.assertEqual(first.returncode, 0, msg=first.stderr + self.daemon_log())
        self.assertIn("CONTENT_MATCH", first.stdout)
        self.assertNotIn("MISSING", first.stdout)
        if os.name == "posix":
            self.assertIn("MODE=600", first.stdout)
        temp_path = None
        for line in first.stdout.splitlines():
            if line.startswith("PATH="):
                temp_path = Path(line.split("=", 1)[1])
        self.assertIsNotNone(temp_path, msg=first.stdout)
        self.assertFalse(temp_path.exists(), "실행 종료 뒤 임시 파일이 남아 있다")
        self.assertFalse(any(self.tmp_dir.glob("run-*")), "실행 뒤 임시 폴더가 남아 있다")

        second = self.run_probe(probe)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        for line in second.stdout.splitlines():
            if line.startswith("PATH="):
                self.assertNotEqual(Path(line.split("=", 1)[1]), temp_path)

    def test_stdout_and_stderr_are_masked(self):
        secret = "mask-me-please-9876"
        self.set_string("SV_MASK", secret)
        probe = self.make_probe(
            "import os, sys\n"
            "value = os.environ.get('SV_MASK', '')\n"
            "sys.stdout.write('OUT=' + value + '\\n')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('ERR=' + value + '\\n')\n"
            "sys.stderr.flush()\n"
        )
        result = self.run_probe(probe)
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("[REDACTED_SECRET]", result.stdout)
        self.assertIn("[REDACTED_SECRET]", result.stderr)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_empty_vault_injects_nothing(self):
        probe = self.make_probe(
            "import os\n"
            "print('CLEAN' if 'SV_ANY' not in os.environ else 'DIRTY')\n"
        )
        result = self.run_probe(probe)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("CLEAN", result.stdout)


class RceDenialTest(DaemonCase):
    def assert_denied(self, result):
        self.assertEqual(result.returncode, 126, msg=result.stderr + self.daemon_log())
        self.assertIn("[DENIED]", result.stderr)

    def test_python_inline_code_is_denied(self):
        result = self.runner(sys.executable, "-c", "print('SHOULD_NOT_RUN')")
        self.assert_denied(result)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_python_module_execution_is_denied(self):
        result = self.runner(sys.executable, "-m", "http.server", "--help")
        self.assert_denied(result)

    def test_temp_script_is_denied(self):
        script = self.base / "evil.py"
        script.write_text("print('TEMP_SCRIPT_RAN')\n", encoding="utf-8")
        result = self.runner(sys.executable, str(script), cwd=self.base)
        self.assert_denied(result)
        self.assertNotIn("TEMP_SCRIPT_RAN", result.stdout)

    def test_shell_inline_code_is_denied(self):
        if os.name == "nt":
            result = self.runner("cmd.exe", "/c", "echo SHELL_RAN")
        else:
            shell = shutil.which("sh") or "/bin/sh"
            result = self.runner(shell, "-c", "echo SHELL_RAN")
        self.assert_denied(result)
        self.assertNotIn("SHELL_RAN\n", result.stdout)

    def test_unknown_binary_is_denied(self):
        result = self.runner("definitely-not-a-real-binary-test-xyz")
        self.assert_denied(result)

    def test_script_outside_allowed_roots_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "outside.py"
            script.write_text("print('OUTSIDE_RAN')\n", encoding="utf-8")
            result = self.runner(sys.executable, str(script), cwd=tmp)
            self.assert_denied(result)
            self.assertNotIn("OUTSIDE_RAN", result.stdout)

    def test_allowed_script_with_argument_runs(self):
        probe = self.make_probe(
            "import sys\n"
            "print('ARGV=' + ','.join(sys.argv[1:]))\n"
        )
        result = self.runner(sys.executable, str(probe), "one", "two")
        self.assertEqual(result.returncode, 0, msg=result.stderr + self.daemon_log())
        self.assertIn("ARGV=one,two", result.stdout)


class DaemonLifecycleTest(DaemonCase):
    def test_daemon_stops_via_cli_request_without_service_manager(self):
        result = run_process(
            [sys.executable, "-B", str(DAEMON), "--socket", str(self.socket_path), "--stop"],
            cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("[OK]", result.stdout)
        deadline = time.time() + 10
        while time.time() < deadline and self.proc.poll() is None:
            time.sleep(0.05)
        self.assertIsNotNone(self.proc.poll(), "데몬이 종료 요청으로 끝나지 않았다")
        self.assertFalse(self.socket_path.exists(), "소켓 파일이 남아 있다")

    def test_second_daemon_on_same_socket_is_rejected(self):
        second = run_process(
            [
                sys.executable,
                "-B",
                str(DAEMON),
                "--foreground",
                "--socket",
                str(self.socket_path),
                "--store",
                str(self.base / "second.enc"),
                "--tmp-dir",
                str(self.base / "second-tmp"),
            ],
            cwd=str(REPO),
            timeout=30,
        )
        self.assertEqual(second.returncode, 5, msg=second.stdout + second.stderr)
        self.assertIn("이미 데몬이 실행 중", second.stderr)

    def test_unknown_op_is_rejected(self):
        response = self.request({"op": "rm -rf /"})
        self.assertFalse(response.get("ok"))
        self.assertIn("알 수 없는 op", response.get("error", ""))

    def test_invalid_key_name_is_rejected(self):
        response = self.request({"op": "set", "name": "../escape", "value": "x"})
        self.assertFalse(response.get("ok"))

    def test_malformed_json_is_rejected(self):
        sock, _token = core.open_client_connection(self.socket_path, timeout=5)
        try:
            sock.sendall(b"not-json\n")
            line = sock.makefile("rb").readline()
        finally:
            sock.close()
        response = json.loads(line.decode("utf-8"))
        self.assertFalse(response.get("ok"))

    def test_daemon_does_not_register_system_services(self):
        source = DAEMON.read_text(encoding="utf-8")
        for marker in ("systemctl", "systemd-analyze", "sc create", "New-Service"):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
