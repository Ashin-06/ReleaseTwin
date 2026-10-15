"""Bounded artifact inventories. Uploaded code is never executed or extracted."""

import hashlib
import io
import os
import stat
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 4 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_ENTRIES = 1000


def safe_name(name):
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 512
        or "\\" in name
        or "\x00" in name
    ):
        raise ValueError("Invalid artifact path")
    if (
        any(ord(c) < 32 or ord(c) == 127 for c in name)
        or name.startswith("/")
        or any(p in ("", ".", "..") for p in name.split("/"))
    ):
        raise ValueError(f"Unsafe artifact path: {name!r}")
    if unicodedata.normalize("NFC", name) != name:
        raise ValueError("Artifact paths must use NFC Unicode normalization")
    for part in name.split("/"):
        if any(c in part for c in '<>:"|?*') or part.endswith((" ", ".")):
            raise ValueError(f"Nonportable artifact path: {name!r}")
        stem = part.split(".")[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or stem in {
            f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)
        }:
            raise ValueError(f"Reserved artifact filename: {name!r}")
    return str(PurePosixPath(name))


def _validate_paths(files, directories=()):
    seen = {}
    for path in [*files, *directories]:
        parts = path.split("/")
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            is_file = count == len(parts) and path in files
            folded = prefix.casefold()
            if folded in seen:
                previous, was_file = seen[folded]
                if previous != prefix:
                    raise ValueError(
                        f"Case-colliding artifact paths: {previous!r}, {prefix!r}"
                    )
                if is_file != was_file:
                    raise ValueError("A file is also used as a parent directory")
            else:
                seen[folded] = (prefix, is_file)


def inventory_zip(data):
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE:
        raise ValueError("ZIP archive exceeds 4 MiB compressed limit")
    files = {}
    directories = set()
    entry_names = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ValueError("Archive exceeds 1,000 entries")
            for item in entries:
                original = item.orig_filename
                name = safe_name(original[:-1] if original.endswith("/") else original)
                if name in entry_names:
                    raise ValueError(f"Duplicate ZIP entry: {name}")
                entry_names.add(name)
                if item.flag_bits & 1:
                    raise ValueError("Encrypted ZIP entries are not supported")
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise ValueError("Symlinks are not accepted")
                kind = stat.S_IFMT(item.external_attr >> 16)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError(
                        "Only regular artifact files and directories are accepted"
                    )
                if (
                    kind == stat.S_IFDIR
                    and not item.is_dir()
                    or kind == stat.S_IFREG
                    and item.is_dir()
                ):
                    raise ValueError("ZIP entry type disagrees with its path")
                if item.is_dir():
                    directories.add(name)
                    continue
                if name in files:
                    raise ValueError(f"Duplicate ZIP entry: {name}")
                if (
                    item.file_size > MAX_FILE
                    or item.file_size > max(1, item.compress_size) * 200
                ):
                    raise ValueError(
                        "ZIP entry exceeds size or compression-ratio budget"
                    )
                total += item.file_size
                if total > MAX_TOTAL:
                    raise ValueError("Archive exceeds 32 MiB uncompressed budget")
                with archive.open(item) as stream:
                    content = stream.read(MAX_FILE + 1)
                if len(content) > MAX_FILE or len(content) != item.file_size:
                    raise ValueError("ZIP entry size disagrees with its content")
                files[name] = {
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                    "executable": bool((item.external_attr >> 16) & 0o111),
                }
    except (
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
        zlib.error,
        EOFError,
    ) as exc:
        raise ValueError(f"Invalid or unsupported ZIP archive: {exc}") from exc
    _validate_paths(files, directories)
    return files


def pack_directory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Artifact root must be a real directory")
    files = []
    total = 0

    def unreadable(error):
        raise ValueError(f"Cannot inventory artifact directory: {error}") from error

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=unreadable):
        if any((Path(directory) / d).is_symlink() for d in dirs):
            raise ValueError("Symlink directories are not accepted")
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Only regular artifact files are accepted")
            relative = safe_name(path.relative_to(root).as_posix())
            size = path.stat().st_size
            if size > MAX_FILE:
                raise ValueError("Artifact file exceeds 8 MiB")
            total += size
            if total > MAX_TOTAL or len(files) >= MAX_ENTRIES:
                raise ValueError("Artifact directory exceeds analysis budget")
            files.append((relative, path))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for name, path in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ValueError("Artifact changed while reading")
            archive.writestr(info, data)
    data = output.getvalue()
    inventory_zip(data)
    return data


def read_artifact(path):
    path = Path(path)
    if path.is_dir():
        return pack_directory(path)
    if (
        path.is_symlink()
        or not stat.S_ISREG(path.stat().st_mode)
        or path.stat().st_size > MAX_ARCHIVE
    ):
        raise ValueError("Archive must be a regular file within the 4 MiB limit")
    data = path.read_bytes()
    inventory_zip(data)
    return data
