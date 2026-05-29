#!/usr/bin/env python3
"""Small encrypted local vault for HITL-approved agent workflows."""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import getpass
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VERSION = 1
KDF = "PBKDF2HMAC-SHA256"
ITERATIONS = 1_200_000
SALT_BYTES = 32
DEFAULT_DIR = ".local-vault"
DEFAULT_FILE = "vault.json"
NEED_HITL_EXIT = 75


class VaultError(RuntimeError):
    """User-facing vault failure."""


@dataclass(frozen=True)
class VaultPaths:
    directory: Path
    vault_file: Path
    lock_file: Path


def default_paths() -> VaultPaths:
    directory = Path.cwd() / DEFAULT_DIR
    return VaultPaths(
        directory=directory,
        vault_file=directory / DEFAULT_FILE,
        lock_file=directory / ".vault.lock",
    )


def paths_from_args(args: argparse.Namespace) -> VaultPaths:
    if args.vault:
        vault_file = Path(args.vault).expanduser().resolve()
        directory = vault_file.parent
    else:
        return default_paths()
    return VaultPaths(directory=directory, vault_file=vault_file, lock_file=directory / ".vault.lock")


def ensure_private_directory(directory: Path) -> None:
    old_umask = os.umask(0o077)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    finally:
        os.umask(old_umask)

    mode = stat.S_IMODE(directory.stat().st_mode)
    if mode & 0o077:
        raise VaultError(f"{directory} must not be accessible by group/others; run: chmod 700 {directory}")


def ensure_private_file(path: Path) -> None:
    if not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise VaultError(f"{path} must not be accessible by group/others; run: chmod 600 {path}")


@contextlib.contextmanager
def vault_lock(paths: VaultPaths):
    ensure_private_directory(paths.directory)
    fd = os.open(paths.lock_file, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not passphrase:
        raise VaultError("master passphrase cannot be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def empty_payload() -> dict[str, Any]:
    return {"created_at": int(time.time()), "updated_at": int(time.time()), "entries": {}}


def encrypt_payload(payload: dict[str, Any], passphrase: str, salt: bytes, iterations: int) -> str:
    key = derive_key(passphrase, salt, iterations)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Fernet(key).encrypt(raw).decode("ascii")


def decrypt_payload(document: dict[str, Any], passphrase: str) -> dict[str, Any]:
    try:
        salt = base64.b64decode(document["salt"])
        iterations = int(document["iterations"])
        token = document["ciphertext"].encode("ascii")
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("vault file is malformed") from exc

    key = derive_key(passphrase, salt, iterations)
    try:
        raw = Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise VaultError("unlock failed: wrong passphrase or corrupted vault") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError("decrypted vault payload is malformed") from exc
    if not isinstance(payload, dict) or "entries" not in payload:
        raise VaultError("decrypted vault payload is missing entries")
    return payload


def read_document(paths: VaultPaths) -> dict[str, Any]:
    ensure_private_file(paths.vault_file)
    if not paths.vault_file.exists():
        raise VaultError("vault is not initialized; run: hitl_vault.py init")
    with paths.vault_file.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_document_atomic(paths: VaultPaths, document: dict[str, Any]) -> None:
    ensure_private_directory(paths.directory)
    serialized = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=".vault.", suffix=".tmp", dir=paths.directory)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(serialized)
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, paths.vault_file)
        dir_fd = os.open(paths.directory, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise


def build_document(payload: dict[str, Any], passphrase: str, salt: bytes | None = None) -> dict[str, Any]:
    salt = salt or os.urandom(SALT_BYTES)
    return {
        "version": VERSION,
        "kdf": KDF,
        "iterations": ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": encrypt_payload(payload, passphrase, salt, ITERATIONS),
    }


def load_payload(paths: VaultPaths, passphrase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document = read_document(paths)
    return document, decrypt_payload(document, passphrase)


def save_payload(paths: VaultPaths, payload: dict[str, Any], passphrase: str, document: dict[str, Any] | None) -> None:
    payload["updated_at"] = int(time.time())
    salt = base64.b64decode(document["salt"]) if document else None
    write_document_atomic(paths, build_document(payload, passphrase, salt=salt))


def require_interactive_tty() -> None:
    if not sys.stdin.isatty():
        raise VaultError("HITL unlock requires an interactive TTY; refusing non-interactive passphrase input")


def prompt_new_passphrase() -> str:
    require_interactive_tty()
    first = getpass.getpass("New vault master passphrase: ")
    second = getpass.getpass("Repeat vault master passphrase: ")
    if first != second:
        raise VaultError("passphrases did not match")
    if len(first) < 12:
        raise VaultError("master passphrase must be at least 12 characters")
    return first


def prompt_passphrase() -> str:
    require_interactive_tty()
    return getpass.getpass("Vault master passphrase: ")


def prompt_secret(name: str) -> str:
    require_interactive_tty()
    first = getpass.getpass(f"Secret value for {name}: ")
    second = getpass.getpass(f"Repeat secret value for {name}: ")
    if first != second:
        raise VaultError("secret values did not match")
    if not first:
        raise VaultError("secret value cannot be empty")
    return first


def validate_name(name: str) -> None:
    if not name or any(ch.isspace() for ch in name):
        raise VaultError("secret name cannot be empty or contain whitespace")


def cmd_init(args: argparse.Namespace) -> int:
    paths = paths_from_args(args)
    with vault_lock(paths):
        if paths.vault_file.exists() and not args.force:
            raise VaultError(f"vault already exists: {paths.vault_file}")
        passphrase = prompt_new_passphrase()
        write_document_atomic(paths, build_document(empty_payload(), passphrase))
    print(f"initialized encrypted vault: {paths.vault_file}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    validate_name(args.name)
    paths = paths_from_args(args)
    secret = prompt_secret(args.name)
    passphrase = prompt_passphrase()
    with vault_lock(paths):
        document, payload = load_payload(paths, passphrase)
        entries = payload.setdefault("entries", {})
        entries[args.name] = {
            "value": secret,
            "note": args.note or "",
            "updated_at": int(time.time()),
        }
        save_payload(paths, payload, passphrase, document)
    print(f"stored secret: {args.name}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    paths = paths_from_args(args)
    passphrase = prompt_passphrase()
    with vault_lock(paths):
        _, payload = load_payload(paths, passphrase)
    for name in sorted(payload.get("entries", {})):
        print(name)
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    paths = paths_from_args(args)
    passphrase = prompt_passphrase()
    with vault_lock(paths):
        _, payload = load_payload(paths, passphrase)
    try:
        value = payload["entries"][args.name]["value"]
    except KeyError as exc:
        raise VaultError(f"secret not found: {args.name}") from exc
    print(value)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    paths = paths_from_args(args)
    passphrase = prompt_passphrase()
    with vault_lock(paths):
        document, payload = load_payload(paths, passphrase)
        try:
            del payload["entries"][args.name]
        except KeyError as exc:
            raise VaultError(f"secret not found: {args.name}") from exc
        save_payload(paths, payload, passphrase, document)
    print(f"deleted secret: {args.name}")
    return 0


def parse_secret_mapping(mapping: str) -> tuple[str, str]:
    if ":" in mapping:
        name, env_name = mapping.split(":", 1)
    else:
        name = mapping
        env_name = mapping.upper().replace("-", "_").replace(".", "_")
    validate_name(name)
    if not env_name.isidentifier() or env_name.startswith("_"):
        raise VaultError(f"invalid environment variable name: {env_name}")
    return name, env_name


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        raise VaultError("run requires a command after --")
    paths = paths_from_args(args)
    mappings = [parse_secret_mapping(item) for item in args.secret]
    passphrase = prompt_passphrase()
    with vault_lock(paths):
        _, payload = load_payload(paths, passphrase)
        entries = payload.get("entries", {})
        child_env = os.environ.copy()
        for name, env_name in mappings:
            try:
                child_env[env_name] = entries[name]["value"]
            except KeyError as exc:
                raise VaultError(f"secret not found: {name}") from exc

    executable = shutil.which(args.command[0])
    if executable is None:
        raise VaultError(f"command not found: {args.command[0]}")
    completed = subprocess.run([executable, *args.command[1:]], env=child_env, check=False)
    return completed.returncode


def cmd_export_encrypted_copy(args: argparse.Namespace) -> int:
    paths = paths_from_args(args)
    destination = Path(args.destination).expanduser().resolve()
    ensure_private_file(paths.vault_file)
    ensure_private_directory(destination.parent)
    with vault_lock(paths):
        if not paths.vault_file.exists():
            raise VaultError("vault is not initialized")
        fd = os.open(destination, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                with paths.vault_file.open("rb") as source:
                    shutil.copyfileobj(source, handle)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
            raise
    print(f"wrote encrypted copy: {destination}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local encrypted vault for HITL-approved agent secret access.",
    )
    parser.add_argument("--vault", help="path to vault JSON file; default: ./.local-vault/vault.json")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    init = subparsers.add_parser("init", help="create a new encrypted vault")
    init.add_argument("--force", action="store_true", help="overwrite an existing vault")
    init.set_defaults(func=cmd_init)

    add = subparsers.add_parser("add", help="add or replace a secret")
    add.add_argument("name")
    add.add_argument("--note", default="")
    add.set_defaults(func=cmd_add)

    list_cmd = subparsers.add_parser("list", help="list secret names after HITL unlock")
    list_cmd.set_defaults(func=cmd_list)

    get = subparsers.add_parser("get", help="print one secret to stdout; use sparingly")
    get.add_argument("name")
    get.set_defaults(func=cmd_get)

    delete = subparsers.add_parser("delete", help="delete one secret")
    delete.add_argument("name")
    delete.set_defaults(func=cmd_delete)

    run = subparsers.add_parser("run", help="run a command with selected secrets in its environment")
    run.add_argument("--secret", action="append", required=True, help="secret name or name:ENV_VAR")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command after --")
    run.set_defaults(func=cmd_run)

    export = subparsers.add_parser("export-encrypted-copy", help="copy encrypted vault file for backup")
    export.add_argument("destination")
    export.set_defaults(func=cmd_export_encrypted_copy)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command_name == "run" and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"vault error: {exc}", file=sys.stderr)
        if "interactive TTY" in str(exc):
            return NEED_HITL_EXIT
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
