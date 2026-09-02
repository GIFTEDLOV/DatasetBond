"""Reject CRLF and missing final newlines in tracked text files."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / name for name in result.stdout.decode("utf-8").split("\0") if name]


def main() -> int:
    problems: list[str] = []
    for path in tracked_files():
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            problems.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        relative = path.relative_to(ROOT)
        if b"\r\n" in raw or b"\r" in raw:
            problems.append(f"{relative}: contains CRLF/CR line endings")
        if raw and not raw.endswith(b"\n"):
            problems.append(f"{relative}: missing final newline")

    if problems:
        print("line-ending check failed", file=sys.stderr)
        print("\n".join(f"- {problem}" for problem in problems), file=sys.stderr)
        return 1
    print("line-ending check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
