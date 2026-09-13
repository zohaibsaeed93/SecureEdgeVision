"""Generate non-overwriting local Ed25519 key files for a demo node."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from secureedge.crypto import encode_public_key, generate_private_key, serialize_private_key

_SAFE_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class KeyGenerationError(ValueError):
    """Raised when local key files cannot be created safely."""


@dataclass(frozen=True)
class GeneratedKeyPaths:
    """Paths written by one successful local key-generation operation."""

    private_key: Path
    public_key: Path
    public_key_b64: str


def validate_node_id(node_id: str) -> str:
    """Validate a node ID against the existing wire-contract identifier shape."""

    if not isinstance(node_id, str) or _SAFE_NODE_ID.fullmatch(node_id) is None:
        raise KeyGenerationError("node ID must be a safe 1-128 character identifier")
    return node_id


def generate_node_key_files(node_id: str, output_dir: Path | str = "secrets") -> GeneratedKeyPaths:
    """Generate a private/public key pair without overwriting any target."""

    safe_node_id = validate_node_id(node_id)
    directory = Path(output_dir)
    _ensure_secure_directory(directory)

    private_path = directory / f"{safe_node_id}.key"
    public_path = directory / f"{safe_node_id}.pub"
    _reject_existing_targets(private_path, public_path)

    private_key = generate_private_key()
    private_pem = serialize_private_key(private_key)
    public_key_b64 = encode_public_key(private_key.public_key())
    public_b64 = public_key_b64.encode("ascii")
    created: list[tuple[Path, int, int]] = []

    try:
        _write_exclusive(private_path, private_pem, created)
        _write_exclusive(public_path, public_b64, created)
    except KeyGenerationError:
        _cleanup_created(created)
        raise
    except OSError as exc:
        _cleanup_created(created)
        raise KeyGenerationError("could not safely create node key files") from exc

    return GeneratedKeyPaths(
        private_key=private_path,
        public_key=public_path,
        public_key_b64=public_key_b64,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the explicit local key-generation command."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True, help="safe node identifier")
    parser.add_argument(
        "--output-dir",
        default="secrets",
        help="ignored local directory for generated keys (default: secrets)",
    )
    args = parser.parse_args(argv)

    try:
        paths = generate_node_key_files(args.node_id, args.output_dir)
    except KeyGenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"private_key: {paths.private_key}")
    print(f"public_key: {paths.public_key}")
    print(f"public_key_b64: {paths.public_key_b64}")
    return 0


def _ensure_secure_directory(directory: Path) -> None:
    try:
        directory_stat = os.lstat(directory)
    except FileNotFoundError:
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            directory_stat = os.lstat(directory)
        except OSError as exc:
            raise KeyGenerationError("could not create the key directory") from exc
    except OSError as exc:
        raise KeyGenerationError("could not inspect the key directory") from exc

    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise KeyGenerationError("key output path must be a directory, not a symlink")

    try:
        os.chmod(directory, 0o700)
        directory_mode = stat.S_IMODE(os.stat(directory).st_mode)
    except OSError as exc:
        raise KeyGenerationError("could not secure the key directory") from exc
    if directory_mode & 0o077:
        raise KeyGenerationError("key directory must not be accessible by group or other users")


def _reject_existing_targets(*paths: Path) -> None:
    for path in paths:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise KeyGenerationError("could not inspect an existing key target") from exc
        raise KeyGenerationError("refusing to overwrite an existing key target")


def _write_exclusive(path: Path, data: bytes, created: list[tuple[Path, int, int]]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow

    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise KeyGenerationError("refusing to overwrite an existing key target") from exc
    except OSError as exc:
        raise KeyGenerationError("could not create a key file") from exc

    descriptor_stat = os.fstat(descriptor)
    created.append((path, descriptor_stat.st_dev, descriptor_stat.st_ino))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            if hasattr(os, "fsync"):
                os.fsync(stream.fileno())
    except OSError as exc:
        raise KeyGenerationError("could not write a key file") from exc

    try:
        final_stat = os.lstat(path)
    except OSError as exc:
        raise KeyGenerationError("could not verify a key file") from exc
    if (
        not stat.S_ISREG(final_stat.st_mode)
        or final_stat.st_dev != descriptor_stat.st_dev
        or final_stat.st_ino != descriptor_stat.st_ino
    ):
        raise KeyGenerationError("key file verification failed")


def _cleanup_created(created: list[tuple[Path, int, int]]) -> None:
    for path, device, inode in reversed(created):
        try:
            current = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            continue
        if (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == device
            and current.st_ino == inode
        ):
            try:
                os.unlink(path)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
