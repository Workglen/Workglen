#!/usr/bin/env python3
"""Exercise password recovery through the real, offline Admin installer.

Uses private temporary installations and a supplied native executable. No
services, public CA requests, package managers or database connections are run.
"""
import argparse
import errno
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time
import unittest


parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
args = parser.parse_args()
BINARY = Path(args.binary).resolve()
SOURCE = Path(__file__).resolve().parents[1]
LOCAL = "local-synthetic-password-2026"
GATEWAY = "gateway-synthetic-password-2026"
LOCAL_PROMPT = "Local Admin password (12+ characters): "
GATEWAY_PROMPT = "Gateway recovery administrator password (12+ characters): "
REPEAT = "Repeat password: "


class PasswordFlow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workglen-password-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.local = self.root / "Local Admin"
        self.bundle = self.root / "Gateway Bundle"
        self.secrets = [LOCAL, GATEWAY]
        self.command = ["bash", str(SOURCE / "install.sh"), "admin",
                        "--binary", str(BINARY), "--home", str(self.local),
                        "--bundle", str(self.bundle), "--gateway-host", "gateway.example.test",
                        "--domain", "example.test", "--email", "admin@example.test",
                        "--agree-to-terms"]

    def password_file(self, name, secret):
        path = self.root / name
        path.write_text(secret)
        path.chmod(0o600)
        self.secrets.append(secret)
        return str(path)

    def check_result(self, result, success):
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, output)
        for secret in self.secrets:
            self.assertNotIn(secret, output)
        if success:
            self.assertIn("Local Admin installed.", output)
            self.assertIn("Pairing bundle:", output)
            self.assertEqual(output.count("Preparing local Admin at"), 1)
            self.assertIn("gateway.example.test", (self.bundle / "config.json").read_text())
            for path in [self.local / "etc/admin.hash", self.bundle / "admin.hash"]:
                self.assertTrue(path.read_text().startswith("$argon2id$"))
                self.assertEqual(path.stat().st_mode & 0o077, 0)
        else:
            self.assertFalse(self.local.exists())
            self.assertFalse(self.bundle.exists())
        return output

    def run_flow(self, passwords=(), flags=(), success=True):
        # Interactive setup first asks for TLS mode and the optional PostgreSQL file.
        prefix = "" if "--non-interactive" in flags else "\n\n"
        result = subprocess.run(self.command + list(flags),
                                input=prefix + "".join(value + "\n" for value in passwords),
                                capture_output=True, text=True, timeout=30)
        return self.check_result(result, success)

    def test_equal_passwords_retry_only_gateway_until_distinct(self):
        output = self.run_flow([LOCAL, LOCAL, LOCAL, LOCAL, LOCAL, LOCAL, GATEWAY, GATEWAY])
        self.assertEqual(output.count(LOCAL_PROMPT), 1)
        self.assertEqual(output.count(GATEWAY_PROMPT), 3)
        self.assertEqual(output.count("Use different local Admin and gateway recovery passwords"), 2)

    def test_confirmation_and_short_password_recover(self):
        short = "short-123"
        self.secrets.append(short)
        output = self.run_flow([LOCAL, GATEWAY, short, short, LOCAL, LOCAL, GATEWAY, GATEWAY])
        self.assertIn("Passwords do not match", output)
        self.assertIn("Use a password of 12..1024 characters", output)
        self.assertEqual(output.count(LOCAL_PROMPT), 3)

    def test_long_and_multiline_password_recover(self):
        long = "synthetic-long-" + "x" * 1024
        carriage = "synthetic-carriage\rreturn"
        self.secrets.extend([long, carriage])
        output = self.run_flow([LOCAL, LOCAL, long, long, carriage, carriage, GATEWAY, GATEWAY])
        self.assertIn("Use a password of 12..1024 characters", output)
        self.assertIn("Password must be a single line", output)
        self.assertEqual(output.count(GATEWAY_PROMPT), 3)

    def test_local_file_kept_when_gateway_retried(self):
        path = self.password_file("local.password", LOCAL)
        output = self.run_flow([LOCAL, LOCAL, GATEWAY, GATEWAY], ["--password-file", path])
        self.assertNotIn(LOCAL_PROMPT, output)
        self.assertEqual(output.count(GATEWAY_PROMPT), 2)
        self.assertEqual(Path(path).read_text(), LOCAL)

    def test_gateway_file_kept_when_local_retried(self):
        path = self.password_file("gateway.password", GATEWAY)
        output = self.run_flow([GATEWAY, GATEWAY, LOCAL, LOCAL], ["--gateway-password-file", path])
        self.assertNotIn(GATEWAY_PROMPT, output)
        self.assertEqual(output.count(LOCAL_PROMPT), 2)
        self.assertEqual(Path(path).read_text(), GATEWAY)

    def test_equal_files_fail_without_reprompting(self):
        path = self.password_file("same.password", LOCAL)
        for mode in [[], ["--non-interactive"]]:
            with self.subTest(mode=mode):
                output = self.run_flow(flags=[*mode, "--password-file", path,
                                              "--gateway-password-file", path], success=False)
                self.assertIn("update the supplied password files", output)
                self.assertNotIn(LOCAL_PROMPT, output)
                self.assertNotIn(GATEWAY_PROMPT, output)
                self.assertEqual(Path(path).read_text(), LOCAL)

    def test_invalid_file_fails_without_reprompting(self):
        path = self.password_file("short.password", "short-123")
        output = self.run_flow(flags=["--password-file", path], success=False)
        self.assertIn("Local Admin: Use a password of 12..1024 characters", output)
        self.assertNotIn(LOCAL_PROMPT, output)

    def test_noninteractive_missing_file_fails(self):
        output = self.run_flow(flags=["--non-interactive"], success=False)
        self.assertIn("Local Admin password file is required", output)
        self.assertNotIn(LOCAL_PROMPT, output)

    def test_noninteractive_valid_files_complete(self):
        local = self.password_file("local.password", LOCAL)
        gateway = self.password_file("gateway.password", GATEWAY)
        output = self.run_flow(flags=["--non-interactive", "--password-file", local,
                                      "--gateway-password-file", gateway])
        self.assertNotIn(LOCAL_PROMPT, output)
        self.assertNotIn(GATEWAY_PROMPT, output)

    def test_end_of_input_stops_without_partial_installation(self):
        for values in [[], [LOCAL], [LOCAL, GATEWAY], [LOCAL, LOCAL, LOCAL, LOCAL]]:
            with self.subTest(entered_lines=len(values)):
                output = self.run_flow(values, success=False)
                self.assertIn("Input ended", output)

    def terminal_flow(self, interrupt=False):
        master, slave = pty.openpty()
        child = subprocess.Popen(self.command, stdin=slave, stdout=slave, stderr=slave,
                                 start_new_session=True)
        output = bytearray()
        cursor = 0

        def read_until(prompt):
            nonlocal cursor
            token = prompt.encode()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                index = output.find(token, cursor)
                if index >= 0:
                    cursor = index + len(token)
                    return
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
            self.fail("Installer did not reach expected terminal prompt")

        def answer(prompt, value, secret=False):
            read_until(prompt)
            if secret:
                deadline = time.monotonic() + 2
                while termios.tcgetattr(slave)[3] & termios.ECHO:
                    self.assertLess(time.monotonic(), deadline, "Password input echoed")
                    time.sleep(0.005)
            os.write(master, value.encode() + b"\n")

        try:
            answer("Certificate mode [letsencrypt]: ", "")
            answer("(Enter to configure later): ", "")
            for prompt, value in [(LOCAL_PROMPT, LOCAL), (REPEAT, LOCAL),
                                  (GATEWAY_PROMPT, LOCAL), (REPEAT, LOCAL)]:
                answer(prompt, value, secret=True)
            if interrupt:
                read_until(GATEWAY_PROMPT)
                os.killpg(child.pid, signal.SIGINT)
                child.wait(timeout=5)
                result = subprocess.CompletedProcess(self.command, child.returncode,
                                                     output.decode(), "")
                self.check_result(result, False)
            else:
                answer(GATEWAY_PROMPT, GATEWAY, secret=True)
                answer(REPEAT, GATEWAY, secret=True)
                read_until("Gateway mail acceptance remains paused")
                child.wait(timeout=5)
                result = subprocess.CompletedProcess(self.command, child.returncode,
                                                     output.decode(), "")
                self.check_result(result, True)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            os.close(master)
            os.close(slave)

    def test_terminal_retries_keep_passwords_hidden(self):
        self.terminal_flow()

    def test_interrupt_during_retry_stops_without_partial_installation(self):
        self.terminal_flow(interrupt=True)


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)
