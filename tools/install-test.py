#!/usr/bin/env python3
"""Synthetic installer + split-process regression. No public CA/SMTP/host changes."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import tomllib
import uuid

p = argparse.ArgumentParser()
p.add_argument("--binary", required=True)
p.add_argument("--work", required=True)
p.add_argument("--browser", action="store_true")
args = p.parse_args()
source = Path(__file__).resolve().parents[1]
binary = str(Path(args.binary).resolve())
work = Path(args.work).resolve()
work.mkdir(mode=0o700)  # Never reuse fixtures or installations.
checks, children, occupied = [], [], []
local_password = "local-fixture-password-2026"
recovery_password = "gateway-fixture-password-2026"


def run(command, ok=True, **kw):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=90, **kw)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"Unexpected exit {result.returncode}: {result.stdout}\n{result.stderr}")
    assert local_password not in result.stdout + result.stderr
    assert recovery_password not in result.stdout + result.stderr
    return result


def put(name, data):
    path = work / name
    path.write_text(data)
    path.chmod(0o600)
    return path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def passed(message):
    checks.append(message)
    print("PASS " + message, flush=True)


def start(name, command):
    with (work / (name + ".log")).open("w") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log)
    children.append(child)
    return child


class Api:
    def __init__(self, port, ca):
        self.port, self.ca, self.csrf, self.cookie = port, ca, "", ""

    def call(self, path, data=None, ok=True):
        ctx = ssl.create_default_context(cafile=str(self.ca))
        c = http.client.HTTPSConnection("localhost", self.port, context=ctx, timeout=15)
        headers = {"Origin": f"https://localhost:{self.port}", "Cookie": self.cookie,
                   "X-CSRF-Token": self.csrf, "Content-Type": "application/json"}
        try:
            c.request("GET" if data is None else "POST", path,
                      body=None if data is None else json.dumps(data), headers=headers)
            r = c.getresponse()
            if r.getheader("set-cookie"):
                self.cookie = r.getheader("set-cookie").split(";")[0]
            body = json.loads(r.read())
            assert (r.status == 200) == ok, (r.status, body)
            return body
        finally:
            c.close()

    def login(self, password):
        self.csrf = self.call("/api/login", {"username": "admin", "password": password})["csrf"]


def wait_port(port, process):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        assert process.poll() is None, "Service exited; inspect fixture logs"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("Service did not listen")


try:
    pw = put("local.password", local_password)
    recovery = put("gateway.password", recovery_password)
    dsn = put("postgres.dsn", "host=127.0.0.1 port=1 user=workglen dbname=workglen password=fixture-db-secret")
    cert, leaf, key = work / "gateway.pem", work / "gateway-leaf.pem", work / "gateway.key"
    ca, ca_key, csr, extensions = (work / name for name in
                                   ["gateway-ca.pem", "gateway-ca.key", "gateway.csr", "gateway.ext"])
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=Workglen fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
         "-addext", "authorityKeyIdentifier=keyid:always", "-keyout", ca_key, "-out", ca])
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-subj", "/CN=gateway.example.test", "-keyout", key, "-out", csr])
    extensions.write_text("subjectAltName=DNS:gateway.example.test,DNS:localhost,IP:127.0.0.1\n"
                          "basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n"
                          "subjectKeyIdentifier=hash\n"
                          "authorityKeyIdentifier=keyid,issuer\n")
    run(["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
         "-CAcreateserial", "-days", "2", "-extfile", extensions, "-out", leaf])
    cert.write_bytes(leaf.read_bytes() + ca.read_bytes())
    key.chmod(0o600); ca_key.chmod(0o600)
    # The independent peer certificate above may use OpenSSL. All installation
    # and application operations below must work with that command unavailable.
    trapdir = work / "blocked-commands"
    trapdir.mkdir(mode=0o700)
    marker = work / "openssl-was-called"
    blocked = trapdir / "openssl"
    blocked.write_text('#!/bin/sh\nprintf invoked > "' + str(marker) + '"\nexit 89\n')
    blocked.chmod(0o700)
    os.environ["PATH"] = str(trapdir) + os.pathsep + os.environ["PATH"]
    local, bundle = work / "Local Admin", work / "Gateway Bundle"
    web_port, cli_port, gateway_port, smtp_port = (free_port() for _ in range(4))
    command = ["bash", source / "install.sh", "admin", "--non-interactive", "--binary", binary,
               "--home", local, "--bundle", bundle, "--gateway-host", "gateway.example.test",
               "--domain", "example.test", "--password-file", pw, "--gateway-password-file", recovery,
               "--web-port", web_port, "--cli-port", cli_port, "--gateway-port", gateway_port,
               "--smtp-port", smtp_port, "--tls", "manual", "--cert", cert, "--key", key,
               "--postgres-dsn-file", dsn]
    run(command)
    cfg = local / "etc/admin.toml"
    parsed = tomllib.loads(cfg.read_text())
    gateway = json.loads((bundle / "config.json").read_text())
    assert parsed["admin_only"] and parsed["accounting"]["transport"] == "local"
    assert not (local / "etc/local-ca-key.pem").exists()
    private_key_pems = sorted(
        path.name
        for path in (local / "etc").iterdir()
        if path.is_file() and b"PRIVATE KEY" in path.read_bytes()
    )
    assert private_key_pems == ["local-key.pem"]
    admin_key = Path(parsed["admin_storage_key_file"])
    assert admin_key == local / "etc/admin-storage.key"
    assert admin_key.stat().st_mode & 0o077 == 0
    admin_db = local / "data/admin.redb"
    assert admin_db.read_bytes()[:8] == b"WGCRYPT1"
    assert b"local-admin" not in admin_db.read_bytes()
    assert not (local / "data/mail.redb").exists()
    assert parsed["replication"]["cluster_id"] == gateway["workspace"]
    assert (local / "etc/gateway-control.key").read_bytes() == (bundle / "control.key").read_bytes()
    assert gateway["trusted_admin"] == {
        "permissions": ["read", "rules.write", "rules.test"],
        "domains": ["*"],
        "mailboxes": ["*"],
    }
    assert len(base64.b64decode((local / "etc/feed.key").read_text())) == 32
    assert not (bundle / "storage.key").exists()
    assert not (bundle / "admin-storage.key").exists()
    for path in bundle.rglob("*"):
        if path.is_file():
            assert path.stat().st_mode & 0o077 == 0
            assert "fixture-db-secret" not in path.read_text()
    assert "postgres.dsn" not in [x.name for x in bundle.iterdir()]
    assert all((local / "docs" / doc).is_file() for doc in ["START-HERE.md", "ARCHITECTURE.md", "DOCUMENTATION.md", "MAC-ADMIN-LIGHTSAIL.md"])
    passed("private pairing uses a narrow gateway ceiling and excludes local database/admin secrets")
    wrong_key = work / "wrong-admin.key"
    run([binary, "security-generate-key", wrong_key])
    wrong_config = put("wrong-admin-key.toml", cfg.read_text().replace(str(admin_key), str(wrong_key)))
    run([binary, "init", wrong_config], ok=False)
    passed("encrypted Admin store rejects the wrong key and never creates a plaintext mail database")
    before = hashlib.sha256(cfg.read_bytes()).digest()
    run(command, ok=False)
    assert hashlib.sha256(cfg.read_bytes()).digest() == before
    passed("repeat installation refuses to overwrite configuration and keys")
    bad = put("public-admin.toml", cfg.read_text().replace(f'listen = "127.0.0.1:{web_port}"', f'listen = "0.0.0.0:{web_port}"'))
    run([binary, "check", bad], ok=False)
    bad.write_text(cfg.read_text().replace('admin_only = true', 'admin_only = false'))
    run([binary, "admin-serve", bad], ok=False)
    passed("local Admin requires loopback HTTPS and an explicit admin-only configuration")

    # ACME preparation is offline: it has not started a service or created an account.
    byok = put("supplied.key", "a1" * 32 + "\n")
    second = ["bash", source / "install.sh", "admin", "--non-interactive", "--binary", binary,
              "--home", work / "Second Admin", "--bundle", work / "Second Bundle",
              "--gateway-host", "gateway.example.test", "--domain", "example.test",
              "--password-file", pw, "--gateway-password-file", recovery,
              "--email", "admin@example.test", "--storage-key-file", byok]
    run(second, ok=False)
    assert not (work / "Second Admin").exists()
    run(second + ["--agree-to-terms"])
    acme_cfg = json.loads((work / "Second Bundle/config.json").read_text())
    assert acme_cfg["acme"]["agree_to_terms"] and not acme_cfg["acme"]["staging"]
    assert (work / "Second Bundle/storage.key").read_bytes() == byok.read_bytes()
    assert not list((work / "Second Bundle").rglob("account.key"))
    passed("ACME requires explicit agreement and prepares offline; BYOK stays in the selected gateway bundle")

    invalid = list(second)
    invalid[invalid.index("--home") + 1] = work / "Invalid Admin"
    invalid[invalid.index("--bundle") + 1] = work / "Invalid Bundle"
    invalid[invalid.index("--gateway-host") + 1] = 'bad.test"\nmalicious = true'
    run(invalid, ok=False)
    assert not (work / "Invalid Admin").exists()
    link = work / "password-link"
    link.symlink_to(pw)
    invalid = list(second)
    invalid[invalid.index("--home") + 1] = work / "Link Admin"
    invalid[invalid.index("--bundle") + 1] = work / "Link Bundle"
    invalid[invalid.index("--password-file") + 1] = link
    run(invalid + ["--agree-to-terms"], ok=False)
    assert not (work / "Link Admin").exists()
    passed("configuration injection and linked password files are refused before installation")

    stage = work / "Staged Linux"
    stage_cmd = ["bash", source / "install.sh", "gateway", "--bundle", bundle, "--binary", binary, "--destdir", stage]
    run(stage_cmd + ["--start"], ok=False)
    assert not stage.exists()
    run(stage_cmd)
    assert (stage / "etc/workglen-security/config.json").read_bytes() == (bundle / "config.json").read_bytes()
    assert (stage / "etc/systemd/system/workglen-security.service").is_file()
    assert (stage / "etc/systemd/system/workglen-security-scanner.service").is_file()
    assert not (stage / "etc/workglen-security/storage.key").exists()
    assert not list(stage.rglob("*.redb"))
    run(stage_cmd, ok=False)
    passed("Linux staging preserves private files and creates no service, database or storage key")

    # Relocate installation-owned paths and the synthetic DNS origin to loopback.
    ghome = work / "Running Gateway"
    ghome.mkdir(mode=0o700)
    gateway.update(data_dir=str(ghome / "data"), storage_key_file=str(ghome / "storage.key"),
                   control_key_file=str(bundle / "control.key"), tls_cert=str(cert), tls_key=str(key),
                   hostname="localhost", origin=f"https://localhost:{gateway_port}",
                   smtp_listen=["127.0.0.1", smtp_port], https_listen=["127.0.0.1", gateway_port])
    gcfg = put("running-gateway.json", json.dumps(gateway))
    run([binary, "security-generate-key", gateway["storage_key_file"]])
    run([binary, "security-check", gcfg])
    run([binary, "security-init", gcfg, "admin", bundle / "admin.hash"])
    gp = start("gateway", [binary, "security-serve", str(gcfg)])
    wait_port(gateway_port, gp)
    text = cfg.read_text().replace(f"https://gateway.example.test:{gateway_port}", f"https://localhost:{gateway_port}")
    # Occupy Mail ports: Admin must remain healthy without attempting to bind them.
    for field in ["smtp_listen", "submission_listen", "imap_listen"]:
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen(); occupied.append(sock)
        text = text.replace(f'{field} = "127.0.0.1:0"', f'{field} = "127.0.0.1:{sock.getsockname()[1]}"')
    cfg.write_text(text)
    ap = start("admin", ["bash", str(local / "run-admin.sh")])
    wait_port(web_port, ap)
    admin = Api(web_port, local / "etc/local-cert.pem")
    admin.login(local_password)
    overview = admin.call("/api/overview")
    assert overview["admin_only"] and not overview["modules"]["mail_enabled"]
    assert not overview["modules"]["webmail_enabled"]
    assert json.loads(run([binary, "status", cfg]).stdout)["admin_only"]
    backup_path = Path(run([binary, "backup", cfg]).stdout.strip())
    assert backup_path.read_bytes()[:8] == b"WGCRYPT1"
    assert b"local-admin" not in backup_path.read_bytes()
    passed("online Admin backup is an encrypted logical copy")
    run([binary, "module-enable", cfg, "mail"], ok=False)
    passed("native Admin serves HTTPS/CLI with Mail disabled and never binds occupied SMTP/IMAP ports")
    result = admin.call("/api/security", {"instance": gateway["instance"], "command": {"action": "status", "request_id": str(uuid.uuid4()), "data": {}}})
    assert result["workspace"] == gateway["workspace"] and result["storage_encryption"]["enabled"]
    assert not result["enabled"]
    passed("generated pairing performs verified TLS and narrow authenticated gateway status")
    if args.browser:
        browser_cfg = put("browser.json", json.dumps({"url": f"https://localhost:{web_port}", "password": local_password, "work": str(work)}))
        run([os.environ["CODEX_PRIMARY_RUNTIME_NODE"], source / "tools/install-browser.cjs", browser_cfg])
        passed("browser displays local Admin profile, remote gateway and no mail-enable controls")
    ap.terminate(); ap.wait(timeout=10)
    restored_data = work / "Restored Admin Data"
    restored_config = put(
        "restored-admin.toml",
        cfg.read_text().replace(str(local / "data"), str(restored_data)),
    )
    run([binary, "admin-restore", restored_config, backup_path])
    assert (restored_data / "admin.redb").read_bytes()[:8] == b"WGCRYPT1"
    assert not (restored_data / "mail.redb").exists()
    run([binary, "init", restored_config])
    run([binary, "admin-restore", restored_config, backup_path], ok=False)
    passed("fresh-only Admin restore authenticates an encrypted backup and refuses overwrite")
    direct = Api(gateway_port, cert); direct.login(recovery_password)
    assert direct.call("/api/command", {"action": "status", "request_id": str(uuid.uuid4()), "data": {}})["instance"] == gateway["instance"]
    passed("gateway recovery access and gateway process survive local Admin shutdown")
    assert not marker.exists(), "Installer/runtime attempted OpenSSL"
    passed("installer and native application complete with the OpenSSL command blocked")
    report = {"passed": len(checks), "checks": checks, "platform": "Linux local fixtures; not macOS or live Lightsail validation"}
    (work / "installer-results.json").write_text(json.dumps(report, indent=2) + "\n")
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()
    for sock in occupied:
        sock.close()
