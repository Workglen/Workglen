#!/usr/bin/env python3
"""Installer build-flow regression with fake tools; no downloads or compilation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
STUB = """#!/bin/sh
if [ "${0##*/}" = uname ]; then
  if [ "$1" = -s ]; then printf '%s\\n' "${WORKGLEN_TEST_OS:-Linux}"; else printf 'x86_64\\n'; fi
  exit 0
fi
printf '%s|%s|%s|%s\\n' "${0##*/}" "$*" "$RUSTUP_AUTO_INSTALL" "$RUSTUP_TOOLCHAIN" >> "$WORKGLEN_TEST_LOG"
case "${0##*/}" in
  rustc)
    [ "${WORKGLEN_TEST_PRIVILEGED:-0}" = 0 ] || exit 98
    if [ -f "$WORKGLEN_TEST_READY" ]; then printf 'rustc 1.99.1 (fixture)\\n';
    else
      [ "${WORKGLEN_TEST_RUST_MISSING:-0}" = 0 ] || exit 1
      printf '%s\\n' "rustc ${WORKGLEN_TEST_RUST_VERSION:-1.99.1} (fixture)"
    fi;;
  cargo)
    [ "${WORKGLEN_TEST_PRIVILEGED:-0}" = 0 ] || exit 98
    case "$1" in
      fetch) exit "${WORKGLEN_TEST_FETCH_EXIT:-0}";;
      build) exit "${WORKGLEN_TEST_BUILD_EXIT:-0}";;
      *) exit 99;;
    esac;;
  id) printf '%s\\n' "${WORKGLEN_TEST_UID:-1000}";;
  rustup)
    [ "${WORKGLEN_TEST_PRIVILEGED:-0}" = 0 ] || exit 98
    printf '%s|%s\\n' "$RUSTUP_DIST_SERVER" "$RUSTUP_UPDATE_ROOT" >> "$WORKGLEN_TEST_ORIGINS"
    [ "${WORKGLEN_TEST_INSTALL_EXIT:-0}" = 0 ] || exit "$WORKGLEN_TEST_INSTALL_EXIT"
    : > "$WORKGLEN_TEST_READY"
    for tool in cargo rustc; do cp "$WORKGLEN_TEST_STUB" "$CARGO_HOME/bin/$tool"; chmod 700 "$CARGO_HOME/bin/$tool"; done;;
  curl)
    printf '%s|%s\\n' "$RUSTUP_DIST_SERVER" "$RUSTUP_UPDATE_ROOT" >> "$WORKGLEN_TEST_ORIGINS"
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --output ]; then output=$2; shift; fi
      shift
    done
    cp "$WORKGLEN_TEST_INIT" "$output"
    exit "${WORKGLEN_TEST_DOWNLOAD_EXIT:-0}";;
  dpkg-query|rpm)
    for package do :; done
    if [ ! -f "$WORKGLEN_TEST_OS_READY" ]; then
      case " ${WORKGLEN_TEST_MISSING_PACKAGES:-} " in *" $package "*) exit 1;; esac
    fi
    if [ "${0##*/}" = dpkg-query ]; then printf 'install ok installed'; fi;;
  sudo)
    [ "${WORKGLEN_TEST_SUDO_EXIT:-0}" = 0 ] || exit "$WORKGLEN_TEST_SUDO_EXIT"
    [ "$1" != -n ] || shift
    [ "$1" = -- ] || exit 97
    shift
    case "$1" in env|dnf) ;; *) exit 96;; esac
    export WORKGLEN_TEST_PRIVILEGED=1
    exec "$@";;
  apt-get|dnf)
    [ "${WORKGLEN_TEST_PRIVILEGED:-0}" = 1 ] || exit 95
    if [ "$1" = update ]; then exit "${WORKGLEN_TEST_UPDATE_EXIT:-0}"; fi
    [ "$1" = install ] || exit 94
    [ "${WORKGLEN_TEST_PACKAGE_EXIT:-0}" = 0 ] || exit "$WORKGLEN_TEST_PACKAGE_EXIT"
    [ "${WORKGLEN_TEST_PACKAGE_NOOP:-0}" = 0 ] || exit 0
    : > "$WORKGLEN_TEST_OS_READY"
    for tool in cc c++ make curl unzip; do
      cp "$WORKGLEN_TEST_STUB" "$WORKGLEN_TEST_BIN/$tool"; chmod 700 "$WORKGLEN_TEST_BIN/$tool"
    done;;
  xcode-select)
    if [ "$1" = --install ]; then
      [ "${WORKGLEN_TEST_APPLE_INSTALL_EXIT:-0}" = 0 ] || exit "$WORKGLEN_TEST_APPLE_INSTALL_EXIT"
      [ "${WORKGLEN_TEST_APPLE_PENDING:-0}" = 0 ] || exit 0
      : > "$WORKGLEN_TEST_OS_READY"
    else
      [ -f "$WORKGLEN_TEST_OS_READY" ] || [ "${WORKGLEN_TEST_APPLE_MISSING:-0}" = 0 ] || exit 1
      printf '/mock/AppleTools\\n'
    fi;;
  xcrun)
    [ -f "$WORKGLEN_TEST_OS_READY" ] || [ "${WORKGLEN_TEST_APPLE_MISSING:-0}" = 0 ] || exit 1
    printf '/mock/AppleTools\\n';;
esac
"""
INIT = """#!/bin/sh
printf '%s|%s|%s|%s\\n' rustup-init "$*" "$RUSTUP_AUTO_INSTALL" "$RUSTUP_TOOLCHAIN" >> "$WORKGLEN_TEST_LOG"
[ "${WORKGLEN_TEST_INIT_EXIT:-0}" = 0 ] || exit "$WORKGLEN_TEST_INIT_EXIT"
mkdir -p "$CARGO_HOME/bin"
cp "$WORKGLEN_TEST_STUB" "$CARGO_HOME/bin/rustup"
chmod 700 "$CARGO_HOME/bin/rustup"
"""


class BuildFlow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workglen-build-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cargo_home = self.root / "cargo home"
        (self.cargo_home / "bin").mkdir(parents=True)
        self.log = self.root / "calls"
        self.origins = self.root / "origins"
        (self.root / "stub").write_text(STUB)
        (self.root / "init").write_text(INIT)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("WORKGLEN_TEST_")}
        # Package managers, sudo, Apple setup, Rustup, Cargo and curl are all fake.
        for tool in ("bash", "sh", "mktemp", "rm", "cp", "chmod", "mkdir", "env"):
            (self.bin / tool).symlink_to(shutil.which(tool))
        self.env.update(PATH=str(self.bin), CARGO_HOME=str(self.cargo_home),
                        TMPDIR=str(self.root), WORKGLEN_TEST_STUB=str(self.root / "stub"),
                        WORKGLEN_TEST_INIT=str(self.root / "init"),
                        WORKGLEN_TEST_READY=str(self.root / "ready"),
                        WORKGLEN_TEST_OS_READY=str(self.root / "os-ready"),
                        WORKGLEN_TEST_BIN=str(self.bin),
                        WORKGLEN_TEST_ORIGINS=str(self.origins),
                        WORKGLEN_TEST_LOG=str(self.log), RUSTUP_AUTO_INSTALL="1",
                        RUSTUP_TOOLCHAIN="unexpected-override",
                        RUSTUP_DIST_SERVER="https://unwanted.invalid",
                        RUSTUP_UPDATE_ROOT="https://unwanted.invalid")
        for name in ("rustc", "cargo", "cc", "c++", "make", "curl", "unzip", "id", "uname",
                     "apt-get", "dpkg-query", "sudo", "xcode-select", "xcrun"):
            path = self.bin / name
            path.write_text(STUB)
            path.chmod(0o700)

    def invoke(self, *args, **environment):
        result = subprocess.run(["bash", str(SOURCE / "install.sh"), *args],
                                cwd=self.root, env=dict(self.env, **environment),
                                text=True, capture_output=True, timeout=15)
        self.output = result.stdout + result.stderr
        self.calls = self.log.read_text().splitlines() if self.log.exists() else []
        for call in self.calls:
            self.assertTrue(call.endswith("|0|1.99.1"), call)
        if self.origins.exists():
            self.assertTrue(all(line == "https://static.rust-lang.org|https://static.rust-lang.org/rustup"
                                for line in self.origins.read_text().splitlines()))
        self.assertEqual(list(self.root.glob("workglen-rust.*")), [])
        return result.returncode

    def cargo_calls(self):
        return [line.split("|")[1] for line in self.calls if line.startswith("cargo|")]

    def setup_calls(self):
        return [line for line in self.calls if line.startswith(("sudo|", "apt-get|", "dnf|", "curl|", "rustup|", "rustup-init|", "cargo|"))
                or line.startswith("xcode-select|--install|")]

    def package_calls(self):
        return [line.split("|")[1] for line in self.calls if line.startswith(("apt-get|", "dnf|"))]

    def test_default_build_fetches_before_offline_compilation(self):
        self.assertEqual(self.invoke("build"), 0, self.output)
        self.assertEqual(self.cargo_calls(), ["fetch --locked", "build --release --offline --locked --jobs 1"])

    def test_explicit_fetch_still_works(self):
        self.assertEqual(self.invoke("build", "--fetch"), 0, self.output)
        self.assertEqual(self.cargo_calls()[0], "fetch --locked")

    def test_offline_build_never_fetches_online(self):
        self.assertEqual(self.invoke("build", "--offline"), 0, self.output)
        self.assertEqual(self.cargo_calls(), ["fetch --offline --locked", "build --release --offline --locked --jobs 1"])

    def test_empty_offline_cache_stops_with_recovery_command(self):
        self.assertNotEqual(self.invoke("build", "--offline", WORKGLEN_TEST_FETCH_EXIT="101"), 0)
        self.assertEqual(self.cargo_calls(), ["fetch --offline --locked"])
        self.assertIn("Run bash install.sh build with network access", self.output)

    def test_failed_download_stops_before_compilation(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_FETCH_EXIT="101"), 0)
        self.assertEqual(self.cargo_calls(), ["fetch --locked"])
        self.assertIn("Dependency download failed", self.output)

    def test_missing_toolchain_offline_stops_before_setup_or_fetch(self):
        self.assertNotEqual(self.invoke("build", "--offline", WORKGLEN_TEST_RUST_MISSING="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertFalse(any(line.startswith("curl|") for line in self.calls))
        self.assertIn("Offline mode downloads nothing", self.output)

    def test_wrong_compiler_offline_stops_before_fetch(self):
        self.assertNotEqual(self.invoke("build", "--offline", WORKGLEN_TEST_RUST_VERSION="1.98.0"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("Rust/Cargo 1.99.1 is missing or unavailable", self.output)

    def test_compilation_failure_is_not_reported_as_success(self):
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_BUILD_EXIT="42"), 42)
        self.assertNotIn("Built target/release/workglen", self.output)
        self.assertNotIn("Dependency download failed", self.output)
        self.assertIn("SIGKILL/signal 9", self.output)
        self.assertIn("one possible cause", self.output)
        self.assertIn("keep the target cache", self.output)
        self.assertEqual(self.cargo_calls(), ["fetch --locked", "build --release --offline --locked --jobs 1"])
        self.assertFalse(any(line.startswith("sudo|") for line in self.calls))

    def test_conflicting_modes_fail_before_tools(self):
        self.assertNotEqual(self.invoke("build", "--fetch", "--offline"), 0)
        self.assertEqual(self.calls, [])

    def test_check_reports_missing_toolchain_without_fetch(self):
        self.assertEqual(self.invoke("check", WORKGLEN_TEST_RUST_MISSING="1"), 0, self.output)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("Pinned Rust/Cargo 1.99.1 is not ready", self.output)
        self.assertIn("bash install.sh build", self.output)

    def remove_rust(self):
        for name in ("cargo", "rustc"):
            (self.bin / name).unlink()

    def test_fresh_install_bootstraps_then_fetches_and_builds(self):
        self.remove_rust()
        self.assertEqual(self.invoke("build"), 0, self.output)
        names = [line.split("|")[0] for line in self.calls]
        self.assertLess(names.index("curl"), names.index("rustup-init"))
        self.assertLess(names.index("rustup"), names.index("cargo"))
        self.assertIn("rustup-init|-y --no-modify-path --profile minimal --default-toolchain none|0|1.99.1", self.calls)
        self.assertIn("rustup|toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy --no-self-update|0|1.99.1", self.calls)
        download = next(line for line in self.calls if line.startswith("curl|"))
        self.assertIn("--proto =https --proto-redir =https --tlsv1.2 --fail", download)
        self.assertIn("https://sh.rustup.rs|", download)
        self.assertEqual(self.cargo_calls(), ["fetch --locked", "build --release --offline --locked --jobs 1"])

    def test_existing_rustup_installs_missing_pinned_toolchain(self):
        path = self.cargo_home / "bin/rustup"
        path.write_text(STUB); path.chmod(0o700)
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_RUST_MISSING="1"), 0, self.output)
        self.assertFalse(any(line.startswith("curl|") for line in self.calls))
        self.assertTrue(any(line.startswith("rustup|toolchain install 1.99.1 ") for line in self.calls))

    def test_cached_tools_outside_path_are_reused(self):
        for tool in ("cargo", "rustc"):
            (self.bin / tool).rename(self.cargo_home / "bin" / tool)
        self.assertEqual(self.invoke("build"), 0, self.output)
        self.assertFalse(any(line.startswith(("curl|", "rustup|")) for line in self.calls))

    def test_failed_download_never_executes_partial_script(self):
        self.remove_rust()
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_DOWNLOAD_EXIT="22"), 0)
        self.assertFalse(any(line.startswith(("rustup-init|", "rustup|", "cargo|")) for line in self.calls))
        self.assertIn("No downloaded script was executed", self.output)

    def test_failed_rustup_install_stops(self):
        self.remove_rust()
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_INIT_EXIT="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("Rustup installation failed", self.output)

    def test_failed_toolchain_install_stops(self):
        self.remove_rust()
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_INSTALL_EXIT="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("Rust toolchain installation failed", self.output)

    def test_root_cannot_bootstrap_rust(self):
        self.remove_rust()
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_UID="0"), 0)
        self.assertFalse(any(line.startswith("curl|") for line in self.calls))
        self.assertIn("without sudo", self.output)

    def test_missing_compiler_is_installed_before_rust_setup(self):
        (self.bin / "cc").unlink()
        self.remove_rust()
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="build-essential"), 0, self.output)
        self.assertEqual(self.package_calls(), ["update", "install -y --no-install-recommends --no-remove --no-upgrade build-essential"])
        names = [line.split("|")[0] for line in self.calls]
        self.assertLess(names.index("apt-get"), names.index("curl"))

    def test_missing_cargo_offline_never_bootstraps(self):
        self.remove_rust()
        self.assertNotEqual(self.invoke("build", "--offline"), 0)
        self.assertEqual(self.setup_calls(), [])
        self.assertIn("Offline mode downloads nothing", self.output)

    def test_ubuntu_installs_all_missing_prerequisites(self):
        for tool in ("cc", "c++", "make", "curl", "unzip"):
            (self.bin / tool).unlink()
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="build-essential curl ca-certificates unzip"), 0, self.output)
        self.assertEqual(self.package_calls(), ["update", "install -y --no-install-recommends --no-remove --no-upgrade build-essential curl ca-certificates unzip"])
        self.assertEqual(sum(line.startswith("sudo|") for line in self.calls), 2)

    def test_existing_packages_need_no_sudo(self):
        (self.bin / "sudo").unlink()
        self.assertEqual(self.invoke("build"), 0, self.output)
        self.assertEqual(self.package_calls(), [])

    def test_offline_missing_packages_never_run_installers(self):
        self.assertNotEqual(self.invoke("build", "--offline", WORKGLEN_TEST_MISSING_PACKAGES="ca-certificates"), 0)
        self.assertEqual(self.setup_calls(), [])
        self.assertIn("Missing system prerequisites", self.output)

    def test_check_lists_missing_packages_without_installing(self):
        self.assertEqual(self.invoke("check", WORKGLEN_TEST_MISSING_PACKAGES="curl unzip"), 0, self.output)
        self.assertEqual(self.setup_calls(), [])
        self.assertIn("Build will install system packages: curl unzip", self.output)

    def test_missing_sudo_stops_before_download(self):
        (self.bin / "sudo").unlink()
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl"), 0)
        self.assertEqual(self.setup_calls(), [])
        self.assertIn("needs sudo", self.output)

    def test_denied_sudo_stops_before_rust_or_cargo(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl", WORKGLEN_TEST_SUDO_EXIT="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertEqual(self.package_calls(), [])

    def test_failed_repository_update_stops_before_install(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl", WORKGLEN_TEST_UPDATE_EXIT="100"), 0)
        self.assertEqual(self.package_calls(), ["update"])
        self.assertEqual(self.cargo_calls(), [])

    def test_failed_package_install_stops_before_cargo(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl", WORKGLEN_TEST_PACKAGE_EXIT="100"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("System package setup failed", self.output)

    def test_unsuccessful_package_setup_is_detected_even_on_exit_zero(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl", WORKGLEN_TEST_PACKAGE_NOOP="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("still unavailable", self.output)

    def test_noninteractive_sudo_never_prompts(self):
        self.assertEqual(self.invoke("build", "--non-interactive", WORKGLEN_TEST_MISSING_PACKAGES="curl"), 0, self.output)
        calls = [line for line in self.calls if line.startswith("sudo|")]
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(line.startswith("sudo|-n -- ") for line in calls))

    def use_dnf(self):
        for tool in ("apt-get", "dpkg-query"):
            (self.bin / tool).unlink()
        for tool in ("dnf", "rpm"):
            path = self.bin / tool; path.write_text(STUB); path.chmod(0o700)

    def test_dnf_installs_missing_tools_and_reuses_minimal_curl(self):
        self.use_dnf()
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="gcc gcc-c++ make curl ca-certificates unzip"), 0, self.output)
        self.assertEqual(self.package_calls(), ["install -y gcc gcc-c++ make ca-certificates unzip"])

    def test_dnf_installs_curl_when_missing(self):
        self.use_dnf()
        (self.bin / "curl").unlink()
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl"), 0, self.output)
        self.assertEqual(self.package_calls(), ["install -y curl"])

    def test_macos_opens_tools_installer_and_resumes_when_ready(self):
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_OS="Darwin", WORKGLEN_TEST_APPLE_MISSING="1"), 0, self.output)
        self.assertIn("xcode-select|--install|0|1.99.1", self.calls)
        self.assertEqual(self.package_calls(), [])
        self.assertFalse(any(line.startswith("sudo|") for line in self.calls))

    def test_macos_offline_never_starts_tools_installer(self):
        self.assertNotEqual(self.invoke("build", "--offline", WORKGLEN_TEST_OS="Darwin", WORKGLEN_TEST_APPLE_MISSING="1"), 0)
        self.assertEqual(self.setup_calls(), [])

    def test_macos_headless_install_explains_required_interaction(self):
        self.assertNotEqual(self.invoke("build", "--non-interactive", WORKGLEN_TEST_OS="Darwin",
                                       WORKGLEN_TEST_APPLE_MISSING="1", WORKGLEN_TEST_APPLE_PENDING="1"), 0)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("needs desktop interaction", self.output)

    def test_macos_install_failure_stops_before_rust(self):
        self.assertNotEqual(self.invoke("build", WORKGLEN_TEST_OS="Darwin",
                                       WORKGLEN_TEST_APPLE_MISSING="1", WORKGLEN_TEST_APPLE_INSTALL_EXIT="1"), 0)
        self.assertEqual(self.cargo_calls(), [])

    def test_unknown_linux_missing_tools_has_no_install_side_effects(self):
        for tool in ("apt-get", "dpkg-query", "cc"):
            (self.bin / tool).unlink()
        self.assertNotEqual(self.invoke("build"), 0)
        self.assertEqual(self.setup_calls(), [])
        self.assertIn("supports APT and DNF", self.output)

    def test_repeated_build_reuses_installed_system_packages(self):
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl"), 0, self.output)
        self.log.unlink()
        self.assertEqual(self.invoke("build", WORKGLEN_TEST_MISSING_PACKAGES="curl"), 0, self.output)
        self.assertEqual(self.package_calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
