#!/usr/bin/env python3
"""Benign, reversible .locked rename simulator for Sysmon EID 11 lab tests."""
from __future__ import annotations

import argparse
import random
import re
import sys
from pathlib import Path

NOTE_NAME = "RANSOM_NOTE.txt"
BACKUP_DIR = ".sim_backup"
LOCKED = ".locked"
MARKER = ".lab_sim"
NOTE_BODY = (
    "Riverbend lab simulation. These files were renamed by encrypt_sim.py.\n"
    "This is not a real encryptor. Restore with: "
    "python encrypt_sim.py --target DIR --rollback\n"
    "Artifact for Wazuh rule 100102 (RANSOM_NOTE.txt / .locked) "
    "and 100121 (Sysmon EID 11 burst).\n"
)


class SandboxError(Exception):
    """Target is outside the allowed sandbox."""


def _slash(path: Path) -> str:
    return str(path).replace("\\", "/")


def refuse_reason(target: Path) -> str | None:
    raw = _slash(target)
    lowered = raw.lower()
    parts = list(target.parts) + list(Path(raw).parts)
    if any(p == ".git" for p in parts):
        return "path contains .git"
    if "/.git/" in f"/{raw.strip('/')}/" or raw.endswith("/.git") or raw == ".git":
        return "path contains .git"
    if re.match(r"^[a-z]:/windows(?:/|$)", lowered):
        return "path is under C:\\Windows"
    try:
        resolved = target.expanduser().resolve()
    except OSError as exc:
        return f"unresolvable path ({exc})"
    if any(p == ".git" for p in resolved.parts):
        return "path contains .git"
    if resolved.parent == resolved:
        return "path is filesystem root"
    if resolved == Path.home().resolve():
        return "path is home root"
    return None


def check_forbidden(target: Path) -> Path:
    reason = refuse_reason(target)
    if reason:
        raise SandboxError(f"refused: {reason}")
    return target.expanduser().resolve()


def is_sim_workspace(path: Path) -> bool:
    return (path / BACKUP_DIR).is_dir() and (path / BACKUP_DIR / MARKER).is_file()


def is_empty_dir(path: Path) -> bool:
    return next(path.iterdir(), None) is None


def check_workspace(path: Path, *, creating: bool) -> None:
    if not path.exists():
        if not creating:
            raise SandboxError("refused: target does not exist")
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise SandboxError("refused: target is not a directory")
    if is_empty_dir(path) or is_sim_workspace(path):
        return
    raise SandboxError(
        "refused: target is not empty and was not created by this simulator"
    )


def mark_workspace(path: Path) -> Path:
    backup = path / BACKUP_DIR
    backup.mkdir(exist_ok=True)
    (backup / MARKER).write_text("encrypt_sim\n", encoding="utf-8")
    return backup


def payload_bytes(rng: random.Random, index: int) -> bytes:
    return f"sim-doc-{index}\n".encode() + rng.randbytes(24)


def encrypt(target: Path, count: int, seed: int | None) -> str:
    rng = random.Random(seed)
    backup = mark_workspace(target)
    locked_n = 0
    for i in range(count):
        name = f"file_{i:04d}.txt"
        src = target / name
        dst = target / f"{name}{LOCKED}"
        bak = backup / name
        if dst.is_file() and bak.is_file():
            locked_n += 1
            continue
        if not src.is_file():
            src.write_bytes(payload_bytes(rng, i))
        if not bak.is_file():
            bak.write_bytes(src.read_bytes())
        if dst.exists():
            dst.unlink()
        src.rename(dst)
        dst.write_bytes(rng.randbytes(48))
        locked_n += 1
    (target / NOTE_NAME).write_text(NOTE_BODY, encoding="utf-8")
    return (
        f"summary encrypt target={target} files={count} "
        f"locked={locked_n} note={NOTE_NAME}"
    )


def rollback(target: Path) -> str:
    backup = target / BACKUP_DIR
    if not is_sim_workspace(target):
        raise SandboxError("refused: target is not a simulator workspace")
    restored = 0
    for bak in sorted(backup.iterdir()):
        if bak.name == MARKER or not bak.is_file():
            continue
        dest = target / bak.name
        dest.write_bytes(bak.read_bytes())
        locked = target / f"{bak.name}{LOCKED}"
        if locked.exists():
            locked.unlink()
        restored += 1
    note = target / NOTE_NAME
    if note.exists():
        note.unlink()
    for extra in target.glob(f"*{LOCKED}"):
        extra.unlink()
    return f"summary rollback target={target} restored={restored}"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benign encryption-behavior simulator"
    )
    parser.add_argument("--target", required=True, metavar="DIR")
    parser.add_argument("--files", type=int, default=50, metavar="N")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        target = check_forbidden(Path(args.target))
        if args.files < 0:
            raise SandboxError("refused: --files must be >= 0")
        check_workspace(target, creating=not args.rollback)
        if args.rollback:
            line = rollback(target)
        else:
            line = encrypt(target, args.files, args.seed)
    except SandboxError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
