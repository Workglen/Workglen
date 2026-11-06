#!/usr/bin/env python3
"""Regression tests for the fail-closed source packager."""

import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile


SCRIPT = pathlib.Path(__file__).with_name("package-source.py")
SPEC = importlib.util.spec_from_file_location("package_source", SCRIPT)
PACKAGE_SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE_SOURCE)


class PackageSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / ".gitignore").write_text(
            "/target/\n/tmp/\n.DS_Store\n*.pem\n*.key\n/test-output/\n",
            encoding="utf-8",
        )
        (self.root / ".DS_Store").write_text("metadata", encoding="utf-8")
        (self.root / "tmp").mkdir()
        (self.root / "tmp" / "x").write_text("temporary", encoding="utf-8")
        (self.root / ".env.example").write_text("NAME=value\n", encoding="utf-8")
        public = self.root / "vendor" / "pratique" / "roots"
        public.mkdir(parents=True)
        (public / "mozilla.pem").write_text("PUBLIC TEST MATERIAL\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("source\n", encoding="utf-8")
        self.archive = self.base / "source.zip"

    def tearDown(self):
        self.temporary.cleanup()

    def test_secret_refusal_does_not_change_manifests(self):
        (self.root / ".env").write_text("SECRET=value\n", encoding="utf-8")
        (self.root / "a.key").write_text("private", encoding="utf-8")
        (self.root / "SOURCE-SHA256").write_text("old text\n", encoding="utf-8")
        (self.root / "SOURCE-SHA256.json").write_text("old json\n", encoding="utf-8")

        with self.assertRaisesRegex(PACKAGE_SOURCE.PackagingError, "secret-like"):
            PACKAGE_SOURCE.package(self.root, self.archive)

        self.assertEqual((self.root / "SOURCE-SHA256").read_text(), "old text\n")
        self.assertEqual((self.root / "SOURCE-SHA256.json").read_text(), "old json\n")
        self.assertFalse(self.archive.exists())

    def test_safe_package_excludes_local_files_and_keeps_public_material(self):
        summary = PACKAGE_SOURCE.package(self.root, self.archive)
        self.assertEqual(summary["integrity"], "passed")
        with zipfile.ZipFile(self.archive) as source:
            names = set(source.namelist())
        self.assertNotIn("workglen/.gitignore", names)
        self.assertNotIn("workglen/.DS_Store", names)
        self.assertNotIn("workglen/tmp/x", names)
        self.assertIn("workglen/.env.example", names)
        self.assertIn("workglen/vendor/pratique/roots/mozilla.pem", names)

    def test_check_rejects_excluded_path(self):
        content = b"ignored\n"
        digest = hashlib.sha256(content).hexdigest()
        manifest = {".gitignore": digest}
        with zipfile.ZipFile(self.archive, "w") as output:
            output.writestr("workglen/.gitignore", content)
            output.writestr(
                "workglen/SOURCE-SHA256.json", json.dumps(manifest, indent=2) + "\n"
            )
            output.writestr(
                "workglen/SOURCE-SHA256", f"{digest}  .gitignore\n"
            )
        with self.assertRaisesRegex(PACKAGE_SOURCE.PackagingError, "excluded path"):
            PACKAGE_SOURCE.check_archive(self.archive)

    @unittest.skipUnless(shutil.which("git"), "git is required for candidate tests")
    def test_git_checkout_refuses_untracked_without_explicit_option(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "add", ".gitignore", "tracked.txt"],
            check=True,
        )
        (self.root / "new.txt").write_text("untracked\n", encoding="utf-8")

        with self.assertRaisesRegex(PACKAGE_SOURCE.PackagingError, "untracked"):
            PACKAGE_SOURCE.package(self.root, self.archive)
        self.assertFalse((self.root / "SOURCE-SHA256").exists())

        PACKAGE_SOURCE.package(self.root, self.archive, include_untracked=True)
        with zipfile.ZipFile(self.archive) as source:
            self.assertIn("workglen/new.txt", source.namelist())


if __name__ == "__main__":
    unittest.main()
