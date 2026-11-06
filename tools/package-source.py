#!/usr/bin/env python3
"""Package source with SHA-256 manifests, or verify an existing source ZIP."""

import argparse
import fnmatch
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import zipfile


ARCHIVE_PREFIX = "workglen/"
MANIFEST_NAMES = {"SOURCE-SHA256", "SOURCE-SHA256.json"}
EXCLUDED_FILE_NAMES = {".gitignore", ".DS_Store"}
EXCLUDED_DIRECTORY_NAMES = {".git", "__pycache__", "tmp", "test-output"}
EXCLUDED_PREFIXES = {("validation", "f4-f5-f8-local")}
SECRET_SUFFIXES = {
    ".key",
    ".p12",
    ".password",
    ".pem",
    ".pfx",
    ".redb",
    ".dsn",
    ".token",
}
ALLOWED_PUBLIC_MATERIAL = {
    "vendor/pratique/roots/mozilla.pem",
    "vendor/pratique/tests/data/inter_p256.pem",
    "vendor/pratique/tests/data/leaf_p384.pem",
    "vendor/pratique/tests/data/root_rsa.pem",
}


class PackagingError(Exception):
    """A source package is unsafe or fails its integrity checks."""


def _relative_path(value):
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise PackagingError(f"unsafe path: {value}")
    return path


def _is_excluded(path, include_manifests=False):
    parts = path.parts
    if not include_manifests and path.name in MANIFEST_NAMES:
        return True
    if path.name in EXCLUDED_FILE_NAMES or path.name.endswith(".pyc"):
        return True
    for part in parts[:-1]:
        if (
            part in EXCLUDED_DIRECTORY_NAMES
            or part == "target"
            or part.startswith("target-")
        ):
            return True
    return any(parts[: len(prefix)] == prefix for prefix in EXCLUDED_PREFIXES)


def _is_secret(path):
    name = path.name.lower()
    normalized = path.as_posix()
    if normalized in ALLOWED_PUBLIC_MATERIAL:
        return False
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if name.startswith("id_rsa") or name.startswith("id_ed25519"):
        return True
    return any(name.endswith(suffix) for suffix in SECRET_SUFFIXES)


def _read_ignore_patterns(root):
    ignore = root / ".gitignore"
    if not ignore.is_file():
        return []
    patterns = []
    for raw in ignore.read_text(encoding="utf-8").splitlines():
        pattern = raw.strip()
        if pattern and not pattern.startswith("#"):
            patterns.append(pattern)
    return patterns


def _glob_matches(path, pattern):
    """Match the ordinary path/glob forms used by Workglen's root .gitignore."""
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:]
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]
    directory_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if not pattern:
        return False, negated

    if directory_only:
        values = [
            "/".join(path.parts[:index]) for index in range(1, len(path.parts))
        ]
    elif "/" not in pattern:
        values = list(path.parts)
    else:
        values = [path.as_posix()]

    if anchored:
        matches = any(fnmatch.fnmatchcase(value, pattern) for value in values)
    elif "/" in pattern:
        matches = any(
            fnmatch.fnmatchcase("/".join(path.parts[index:]), pattern)
            for index in range(len(path.parts))
        )
    else:
        matches = any(fnmatch.fnmatchcase(value, pattern) for value in values)
    return matches, negated


def _is_ignored_without_git(path, patterns):
    if path.as_posix() in ALLOWED_PUBLIC_MATERIAL:
        return False
    ignored = False
    for pattern in patterns:
        matches, negated = _glob_matches(path, pattern)
        if matches:
            ignored = not negated
    return ignored


def _git_paths(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        _relative_path(value.decode("utf-8"))
        for value in result.stdout.split(b"\0")
        if value
    }


def _walk_paths(root):
    patterns = _read_ignore_patterns(root)
    paths = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = pathlib.Path(directory)
        kept_directories = []
        for name in directory_names:
            relative = _relative_path((current / name).relative_to(root).as_posix())
            marker = pathlib.PurePosixPath(relative, "placeholder")
            if not _is_excluded(marker):
                kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in file_names:
            disk_path = current / name
            relative = _relative_path(disk_path.relative_to(root).as_posix())
            if _is_excluded(relative) or _is_ignored_without_git(relative, patterns):
                continue
            if disk_path.is_symlink() or not disk_path.is_file():
                raise PackagingError(f"refusing non-regular source path: {relative}")
            paths.append(relative)
    return set(paths)


def _candidate_paths(root, include_untracked):
    if (root / ".git").exists():
        try:
            tracked = _git_paths(root, "--cached")
            untracked = {
                path
                for path in _git_paths(root, "--others", "--exclude-standard")
                if not _is_excluded(path)
            }
        except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
            raise PackagingError(f"could not enumerate Git source paths: {error}") from error
        if untracked and not include_untracked:
            listing = "\n".join(f"  {path}" for path in sorted(untracked))
            raise PackagingError(
                "refusing untracked source paths; commit them or use "
                f"--include-untracked:\n{listing}"
            )
        candidates = tracked | (untracked if include_untracked else set())
    else:
        candidates = _walk_paths(root)

    result = []
    for relative in sorted(candidates):
        if _is_excluded(relative):
            continue
        disk_path = root / relative
        if disk_path.is_symlink() or not disk_path.is_file():
            raise PackagingError(f"refusing missing or non-regular source path: {relative}")
        result.append(relative)
    return result


def _secret_paths(paths):
    return [path for path in paths if _is_secret(path)]


def _atomic_write(path, content):
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def package(root, archive, include_untracked=False):
    root = root.resolve()
    archive = archive.resolve()
    try:
        archive.relative_to(root)
    except ValueError:
        pass
    else:
        raise PackagingError("use an output path outside the source directory")

    paths = _candidate_paths(root, include_untracked)
    secrets = _secret_paths(paths)
    if secrets:
        listing = "\n".join(f"  {path}" for path in secrets)
        raise PackagingError(f"refusing secret-like source paths:\n{listing}")

    manifest = {
        path.as_posix(): hashlib.sha256((root / path).read_bytes()).hexdigest()
        for path in paths
    }
    json_manifest = json.dumps(manifest, indent=2) + "\n"
    text_manifest = "".join(f"{digest}  {name}\n" for name, digest in manifest.items())
    _atomic_write(root / "SOURCE-SHA256.json", json_manifest)
    _atomic_write(root / "SOURCE-SHA256", text_manifest)

    archive.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{archive.name}.", dir=archive.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(
            temporary_name, "w", zipfile.ZIP_DEFLATED, compresslevel=9
        ) as output:
            for relative in paths:
                output.write(root / relative, ARCHIVE_PREFIX + relative.as_posix())
            output.write(root / "SOURCE-SHA256", ARCHIVE_PREFIX + "SOURCE-SHA256")
            output.write(
                root / "SOURCE-SHA256.json", ARCHIVE_PREFIX + "SOURCE-SHA256.json"
            )
        check_archive(pathlib.Path(temporary_name))
        os.replace(temporary_name, archive)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return archive_summary(archive)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackagingError(f"duplicate manifest path: {key}")
        result[key] = value
    return result


def check_archive(archive):
    archive = archive.resolve()
    try:
        source = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as error:
        raise PackagingError(f"invalid ZIP: {error}") from error
    with source:
        corrupt = source.testzip()
        if corrupt is not None:
            raise PackagingError(f"ZIP CRC mismatch: {corrupt}")
        names = source.namelist()
        if len(names) != len(set(names)):
            raise PackagingError("duplicate ZIP paths")
        for name in names:
            if not name.startswith(ARCHIVE_PREFIX):
                raise PackagingError(f"unexpected ZIP path: {name}")
            relative = _relative_path(name[len(ARCHIVE_PREFIX) :])
            if relative.name not in MANIFEST_NAMES and _is_excluded(relative):
                raise PackagingError(f"excluded path in ZIP: {relative}")
            if relative.name not in MANIFEST_NAMES and _is_secret(relative):
                raise PackagingError(f"secret-like path in ZIP: {relative}")

        try:
            manifest = json.loads(
                source.read(ARCHIVE_PREFIX + "SOURCE-SHA256.json"),
                object_pairs_hook=_json_object,
            )
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PackagingError(f"invalid JSON manifest: {error}") from error
        if not isinstance(manifest, dict):
            raise PackagingError("JSON manifest must be an object")

        expected = {
            ARCHIVE_PREFIX + name for name in manifest
        } | {ARCHIVE_PREFIX + name for name in MANIFEST_NAMES}
        if set(names) != expected:
            raise PackagingError("ZIP membership differs from manifest")
        for name, digest in manifest.items():
            relative = _relative_path(name)
            if relative.name in MANIFEST_NAMES or _is_excluded(relative):
                raise PackagingError(f"excluded manifest path: {relative}")
            if _is_secret(relative):
                raise PackagingError(f"secret-like manifest path: {relative}")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise PackagingError(f"invalid source hash: {relative}")
            actual = hashlib.sha256(source.read(ARCHIVE_PREFIX + name)).hexdigest()
            if actual != digest:
                raise PackagingError(f"source hash mismatch: {relative}")
        expected_text = "".join(
            f"{digest}  {name}\n" for name, digest in manifest.items()
        ).encode()
        if source.read(ARCHIVE_PREFIX + "SOURCE-SHA256") != expected_text:
            raise PackagingError("text manifest differs from JSON manifest")
    return archive_summary(archive)


def archive_summary(archive):
    with zipfile.ZipFile(archive) as source:
        file_count = len(source.namelist())
    return {
        "archive": str(archive),
        "files": file_count,
        "bytes": archive.stat().st_size,
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "integrity": "passed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--output", type=pathlib.Path)
    operation.add_argument("--check", type=pathlib.Path)
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="include untracked, non-ignored files when packaging a Git checkout",
    )
    arguments = parser.parse_args()
    if arguments.check and arguments.include_untracked:
        parser.error("--include-untracked is only valid with --output")
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        if arguments.output:
            summary = package(root, arguments.output, arguments.include_untracked)
        else:
            summary = check_archive(arguments.check)
    except PackagingError as error:
        parser.exit(1, f"package-source: {error}\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
