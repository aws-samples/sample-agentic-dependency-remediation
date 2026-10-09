# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""A sandboxed working copy of the target repository.

Every file operation that the model can trigger goes through this class. It
enforces three rules:

* paths must resolve inside the workspace root (no traversal, no symlinks out)
* protected paths such as CI/CD workflows cannot be written
* a limit on the number of files changed in one run
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 200_000
MAX_READ_LINES = 400
MAX_ORIGINAL_BYTES = 20_000_000
MAX_EXTRACTED_BYTES = 500_000_000
COPY_CHUNK_BYTES = 1024 * 1024

# Paths the agent must never modify. Matched against the POSIX relative path.
PROTECTED_PATTERNS = (
    ".git/*",
    ".github/*",
    ".gitlab-ci.yml",
    ".circleci/*",
    "Jenkinsfile",
    "buildspec*.yml",
    "buildspec*.yaml",
    ".remediation/*",
    "CODEOWNERS",
    "*/CODEOWNERS",
)

# Directories that are never packaged, listed, or searched.
IGNORED_DIRS = {".git", "node_modules", "target", ".venv", "venv", "__pycache__", ".remediation", "dist", "build"}


class WorkspaceError(Exception):
    """Raised when a requested operation violates workspace rules."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Workspace:
    def __init__(self, root: Path, max_files_changed: int = 15):
        self.root = root.resolve()
        self.max_files_changed = max_files_changed
        self._baseline: dict[str, str] = {}
        self._originals: dict[str, str] = {}

    # ----- setup -----------------------------------------------------------------

    def extract_archive(self, source: bytes | Path, max_total_bytes: int = MAX_EXTRACTED_BYTES) -> None:
        """Extract a .zip or .tar.gz source archive from any Git host or CI system.

        * Only regular files are extracted. Symlinks, hard links, devices, and
          directories entries are skipped, so no link can point outside the workspace.
        * Every path is resolved and must stay inside the workspace ("..", absolute paths rejected).
        * Files are streamed to disk in chunks and the running total of extracted
          bytes is enforced, so a compression bomb cannot exhaust memory or disk.
        * A single wrapper folder (as in GitHub and GitLab "download archive") is removed.
        """
        with contextlib.ExitStack() as stack:
            if isinstance(source, (bytes, bytearray)):
                handle = io.BytesIO(source)
            else:
                handle = stack.enter_context(open(source, "rb"))
            is_zip = handle.read(4) == b"PK\x03\x04"
            handle.seek(0)

            if is_zip:
                archive = stack.enter_context(zipfile.ZipFile(handle))
                members = []
                for info in archive.infolist():
                    mode = (info.external_attr >> 16) & 0o170000
                    if info.is_dir() or mode not in (0, 0o100000):  # regular files only
                        continue
                    members.append((info.filename, info))
                open_member = archive.open
            else:
                archive = stack.enter_context(tarfile.open(fileobj=handle, mode="r:*"))
                members = [(m.name, m) for m in archive.getmembers() if m.isreg() and not (m.issym() or m.islnk())]
                open_member = archive.extractfile

            # Drop "./" and "/" prefixes only; ".." stays and is rejected by _resolve below.
            names = [tuple(p for p in PurePosixPath(name).parts if p not in (".", "/")) for name, _ in members]
            wrapper = bool(names) and all(len(p) > 1 for p in names) and len({p[0] for p in names}) == 1
            self.root.mkdir(parents=True, exist_ok=True)
            total = 0
            for parts, (_, member) in zip(names, members):
                rel = PurePosixPath(*(parts[1:] if wrapper else parts))
                if not rel.parts or rel.parts[0] in IGNORED_DIRS:
                    continue
                target = self._resolve(str(rel), must_exist=False)
                target.parent.mkdir(parents=True, exist_ok=True)
                src = open_member(member)
                if src is None:
                    continue
                with src, open(target, "wb") as dst:
                    while chunk := src.read(COPY_CHUNK_BYTES):
                        total += len(chunk)
                        if total > max_total_bytes:
                            raise WorkspaceError("Source archive expands beyond the size limit.")
                        dst.write(chunk)
        self.snapshot()

    def snapshot(self) -> None:
        """Record file hashes and original text so that changes can be computed later."""
        self._baseline = {}
        self._originals: dict[str, str] = {}
        for rel in self._iter_files():
            data = (self.root / rel).read_bytes()
            self._baseline[rel] = _sha(data)
            # Keep original text (lockfiles can be large) so that patches and reverts are exact.
            if len(data) <= MAX_ORIGINAL_BYTES:
                self._originals[rel] = data.decode("utf-8", errors="replace")

    # ----- path handling ---------------------------------------------------------

    def _resolve(self, rel_path: str, must_exist: bool = True) -> Path:
        rel_path = rel_path.strip().lstrip("/")
        if not rel_path or "\x00" in rel_path:
            raise WorkspaceError("Invalid path.")
        candidate = (self.root / rel_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise WorkspaceError(f"Path '{rel_path}' is outside the repository.")
        if must_exist and not candidate.exists():
            raise WorkspaceError(f"Path '{rel_path}' does not exist.")
        return candidate

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    @staticmethod
    def is_protected(rel_path: str) -> bool:
        rel = PurePosixPath(rel_path.lstrip("/")).as_posix()
        return any(fnmatch.fnmatch(rel, pattern) for pattern in PROTECTED_PATTERNS)

    def _iter_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if path.is_file() and not path.is_symlink():
                    yield self.relative(path)

    # ----- operations exposed to the model ----------------------------------------

    def list_files(self, subdir: str = "", limit: int = 300) -> list[str]:
        files = list(self._iter_files())
        if subdir.strip("/"):
            prefix = subdir.strip("/") + "/"
            files = [f for f in files if f.startswith(prefix)]
        return files[:limit]

    def read_file(self, rel_path: str, start_line: int = 1, end_line: int | None = None) -> str:
        path = self._resolve(rel_path)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise WorkspaceError(f"'{rel_path}' is larger than {MAX_FILE_BYTES} bytes.")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(start_line, 1)
        end = min(end_line or len(lines), start + MAX_READ_LINES - 1, len(lines))
        numbered = [f"{i:>5}| {lines[i - 1]}" for i in range(start, end + 1)]
        header = f"# {rel_path} (lines {start}-{end} of {len(lines)})"
        return "\n".join([header, *numbered])

    def search(self, pattern: str, max_results: int = 50) -> list[str]:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise WorkspaceError(f"Invalid regular expression: {exc}") from exc
        results: list[str] = []
        for rel in self._iter_files():
            path = self.root / rel
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    results.append(f"{rel}:{number}: {line.strip()[:200]}")
                    if len(results) >= max_results:
                        return results
        return results

    def write_file(self, rel_path: str, content: str, *, trusted: bool = False) -> None:
        if not trusted and self.is_protected(rel_path):
            raise WorkspaceError(f"'{rel_path}' is a protected path and cannot be modified.")
        path = self._resolve(rel_path, must_exist=False)
        rel = self.relative(path)
        if not trusted:
            # `trusted` is reserved for agent code (for example, lockfiles that the
            # build regenerates). Model-initiated writes are always size- and budget-checked.
            if len(content.encode("utf-8")) > MAX_FILE_BYTES:
                raise WorkspaceError("Content exceeds the maximum file size.")
            pending = set(self.changed_files()) | {rel}
            if len(pending) > self.max_files_changed:
                raise WorkspaceError(f"Change budget exceeded: at most {self.max_files_changed} files can be changed.")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def revert_file(self, rel_path: str) -> None:
        path = self._resolve(rel_path, must_exist=False)
        rel = self.relative(path)
        if self.is_protected(rel):
            raise WorkspaceError(f"'{rel}' is a protected path.")
        if rel in self._baseline:
            if rel not in self._originals:
                raise WorkspaceError(f"'{rel}' is too large to restore.")
            path.write_text(self._originals[rel], encoding="utf-8")
        elif path.exists():
            path.unlink()
        else:
            raise WorkspaceError(f"'{rel}' does not exist.")

    def replace_in_file(self, rel_path: str, old: str, new: str) -> int:
        path = self._resolve(rel_path)
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count == 0:
            raise WorkspaceError("The text to replace was not found. Read the file again and copy the text exactly.")
        if count > 1:
            raise WorkspaceError(f"The text to replace occurs {count} times. Include more surrounding lines so it is unique.")
        self.write_file(rel_path, text.replace(old, new, 1))
        return 1

    # ----- change tracking and packaging -----------------------------------------

    def changed_files(self) -> list[str]:
        changed = []
        for rel in self._iter_files():
            if self.is_protected(rel):
                continue
            digest = _sha((self.root / rel).read_bytes())
            if self._baseline.get(rel) != digest:
                changed.append(rel)
        return changed

    def fingerprint(self) -> str:
        """Hash of all changed file contents. Used to prove a PR matches a passing build."""
        h = hashlib.sha256()
        for rel in sorted(self.changed_files()):
            h.update(rel.encode())
            h.update((self.root / rel).read_bytes())
        return h.hexdigest()

    def unified_patch(self) -> str:
        """A complete patch of all changes, in the format that `git apply` and `patch -p1` accept."""
        import difflib

        def lines(text: str) -> list[str]:
            out = text.splitlines(keepends=True)
            if out and not out[-1].endswith("\n"):
                out[-1] += "\n\\ No newline at end of file\n"
            return out

        chunks: list[str] = []
        for rel in sorted(self.changed_files()):
            is_new = rel not in self._baseline
            if not is_new and rel not in self._originals:
                # Without the original text the diff would be wrong. Fail loudly instead of
                # publishing a patch that silently does not apply.
                raise WorkspaceError(f"Cannot build a patch for '{rel}': the original is larger than {MAX_ORIGINAL_BYTES} bytes.")
            try:
                new_text = (self.root / rel).read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise WorkspaceError(f"Cannot build a patch for '{rel}': it is not UTF-8 text.") from exc
            old_text = "" if is_new else self._originals[rel]
            header = [f"diff --git a/{rel} b/{rel}\n"]
            if is_new:
                header.append("new file mode 100644\n")
            body = list(
                difflib.unified_diff(lines(old_text), lines(new_text), "/dev/null" if is_new else f"a/{rel}", f"b/{rel}", n=3)
            )
            if body:
                chunks.extend(header + body)
        return "".join(chunks)

    def zip_bytes(self, extra_files: dict[str, str] | None = None) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for rel in self._iter_files():
                archive.write(self.root / rel, rel)
            for rel, content in (extra_files or {}).items():
                archive.writestr(rel, content)
        return buffer.getvalue()
