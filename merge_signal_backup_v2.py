"""Merge two Signal Android BackupV2 roots without duplicate chat items.

This utility targets local BackupV2 directories, not classic .backup files.
It requires the 64-character Signal Secure Backup recovery key and the cryptography package.
"""

from __future__ import annotations

import argparse
import getpass
import gzip
import hashlib
import hmac
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

try:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: install it with `python -m pip install cryptography`."
    ) from exc


BACKUP_KEY_INFO = b"20240801_SIGNAL_BACKUP_KEY"
METADATA_KEY_INFO = b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"
MESSAGE_KEY_INFO = b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
MEDIA_NAME_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ProgressReporter:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.interactive = not quiet and sys.stderr.isatty()

    def stage(self, message: str) -> None:
        if not self.quiet:
            print(f"[+] {message}", file=sys.stderr)

    def update(self, label: str, current: int, total: int) -> None:
        if self.quiet or total <= 0:
            return
        if self.interactive:
            percent = current * 100 // total
            width = 24
            filled = width * current // total
            bar = "#" * filled + "-" * (width - filled)
            print(
                f"\r[+] {label}: [{bar}] {percent:3d}% ({current:,}/{total:,})",
                end="",
                file=sys.stderr,
                flush=True,
            )
            if current >= total:
                print(file=sys.stderr)
            return
        interval = max(1, total // 10)
        if current == 1 or current == total or current % interval == 0:
            print(f"[+] {label}: {current:,}/{total:,}", file=sys.stderr)


class ProgressSink(Protocol):
    def update(self, label: str, current: int, total: int) -> None:
        ...


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            break
    raise ValueError("Invalid or truncated protobuf varint")


def write_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("Varints cannot encode negative values")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def protobuf_fields(data: bytes):
    offset = 0
    while offset < len(data):
        start = offset
        tag, offset = read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 7
        if field_number == 0:
            raise ValueError("Invalid protobuf field number 0")
        value: int | bytes
        if wire_type == 0:
            value, offset = read_varint(data, offset)
        elif wire_type == 1:
            offset += 8
            if offset > len(data):
                raise ValueError("Truncated fixed64 protobuf field")
            value = data[offset - 8 : offset]
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("Truncated length-delimited protobuf field")
            value = data[offset:end]
            offset = end
        elif wire_type == 5:
            offset += 4
            if offset > len(data):
                raise ValueError("Truncated fixed32 protobuf field")
            value = data[offset - 4 : offset]
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire_type}")
        yield field_number, wire_type, value, data[start:offset]


def first_field(data: bytes, field_number: int, wire_type: int | None = None):
    for number, actual_type, value, _ in protobuf_fields(data):
        if number == field_number and (wire_type is None or actual_type == wire_type):
            return value
    return None


def delimited_records(data: bytes):
    offset = 0
    while offset < len(data):
        length, offset = read_varint(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("Truncated length-delimited record")
        yield data[offset:end]
        offset = end


def encode_delimited(records) -> bytes:
    return b"".join(write_varint(len(record)) + record for record in records)


def hkdf(ikm: bytes, info: bytes, length: int, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) == 12:
        iv += b"\0" * 4
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def derive_keys(recovery_key: str, backup_id: bytes) -> tuple[bytes, bytes, bytes]:
    backup_key = hkdf(recovery_key.encode("ascii"), BACKUP_KEY_INFO, 32)
    metadata_key = hkdf(backup_key, METADATA_KEY_INFO, 32)
    message_key = hkdf(backup_key, MESSAGE_KEY_INFO + backup_id, 64)
    return metadata_key, message_key[:32], message_key[32:]


def parse_metadata(metadata: bytes, metadata_key: bytes) -> bytes:
    encrypted_id = first_field(metadata, 2, 2)
    if encrypted_id is None:
        raise ValueError("metadata has no encrypted backup ID")
    iv = first_field(encrypted_id, 1, 2)
    ciphertext = first_field(encrypted_id, 2, 2)
    if iv is None or ciphertext is None or len(iv) != 12 or len(ciphertext) != 16:
        raise ValueError("metadata has an invalid encrypted backup ID")
    return aes_ctr(metadata_key, iv, ciphertext)


def decrypt_main(main: bytes, aes_key: bytes, mac_key: bytes) -> tuple[bytes, list[bytes]]:
    if len(main) < 16 + 32:
        raise ValueError("main archive is too short")
    expected_mac = main[-32:]
    if not hmac.compare_digest(hmac.new(mac_key, main[:-32], hashlib.sha256).digest(), expected_mac):
        raise ValueError("main archive MAC check failed; wrong recovery key or corrupt backup")
    iv = main[:16]
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(main[16:-32]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    compressed = unpadder.update(padded) + unpadder.finalize()
    records = list(delimited_records(gzip.decompress(compressed)))
    if not records:
        raise ValueError("main archive contains no backup header")
    return records[0], records[1:]


def encrypt_main(header: bytes, frames: list[bytes], aes_key: bytes, mac_key: bytes) -> bytes:
    compressed = gzip.compress(encode_delimited([header, *frames]), mtime=0)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(compressed) + padder.finalize()
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = iv + ciphertext
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()


def read_snapshot(root: Path, snapshot: Path, recovery_key: str) -> dict:
    metadata = (snapshot / "metadata").read_bytes()
    initial_key = hkdf(recovery_key.encode("ascii"), BACKUP_KEY_INFO, 32)
    metadata_key = hkdf(initial_key, METADATA_KEY_INFO, 32)
    backup_id = parse_metadata(metadata, metadata_key)
    _, mac_key, aes_key = derive_keys(recovery_key, backup_id)
    header, frames = decrypt_main((snapshot / "main").read_bytes(), aes_key, mac_key)
    file_names = []
    for record in delimited_records((snapshot / "files").read_bytes()):
        media_name = first_field(record, 1, 2)
        if media_name is not None:
            file_names.append(media_name.decode("ascii"))
    return {
        "root": root,
        "snapshot": snapshot,
        "metadata": metadata,
        "backup_id": backup_id,
        "header": header,
        "frames": frames,
        "file_names": file_names,
        "mac_key": mac_key,
        "aes_key": aes_key,
    }


def find_snapshot(path: Path) -> tuple[Path, Path]:
    path = path.expanduser().resolve()
    if (path / "main").is_file() and (path / "metadata").is_file():
        return path.parent, path
    snapshots = sorted(
        candidate
        for candidate in path.iterdir()
        if candidate.is_dir()
        and (candidate / "main").is_file()
        and (candidate / "metadata").is_file()
    )
    if not snapshots:
        raise ValueError(f"No BackupV2 snapshot found under {path}")
    return path, snapshots[-1]


def frame_kind_and_key(frame: bytes):
    field = next(protobuf_fields(frame), None)
    if field is None:
        return None, None
    number, wire_type, value, _ = field
    if wire_type != 2:
        return None, None
    identities = {
        1: ("account", 0),
        2: ("recipient", 1),
        3: ("chat", 1),
        5: ("sticker", 1),
        6: ("adhoc", 1),
        7: ("notification", 12),
        8: ("folder", 9),
    }
    if number not in identities:
        return None, None
    kind, identity_field = identities[number]
    identity = first_field(value, identity_field, None) if identity_field else None
    if identity_field == 0:
        identity = b""
    if identity is None:
        return kind, (kind, frame)
    return kind, (kind, identity)


def chat_item_key(frame: bytes) -> tuple[int, int, int] | None:
    payload = first_field(frame, 4, 2)
    if payload is None:
        return None
    chat_id = first_field(payload, 1, 0)
    author_id = first_field(payload, 2, 0)
    date_sent = first_field(payload, 3, 0)
    if chat_id is None or author_id is None or date_sent is None:
        raise ValueError("ChatItem is missing chatId, authorId, or dateSent")
    return chat_id, author_id, date_sent


def chat_item_date(frame: bytes) -> int:
    key = chat_item_key(frame)
    if key is None:
        raise ValueError("Expected a ChatItem frame")
    return key[2]


def parse_cutoff(value: str) -> int:
    if value.isdigit():
        return int(value)
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def normalize_recovery_key(value: str) -> str:
    return "".join(value.split()).lower()


def merge_frames(
    target: dict,
    source: dict,
    cutoff_ms: int,
    progress: ProgressSink | None = None,
) -> tuple[list[bytes], int, int]:
    static = {}
    unkeyed_static = set()
    target_messages = []
    message_keys = set()
    total_frames = len(target["frames"]) + len(source["frames"])
    processed_frames = 0

    def update_progress() -> None:
        nonlocal processed_frames
        processed_frames += 1
        if progress is not None:
            progress.update("Analyzing frames", processed_frames, total_frames)

    for frame in target["frames"]:
        key = chat_item_key(frame)
        update_progress()
        if key is not None:
            if key not in message_keys:
                target_messages.append(frame)
                message_keys.add(key)
            continue
        kind, identity = frame_kind_and_key(frame)
        if identity is None:
            if frame not in unkeyed_static:
                unkeyed_static.add(frame)
        else:
            static[identity] = (kind, frame)

    source_messages = []
    imported = 0
    skipped_duplicates = 0
    for frame in source["frames"]:
        key = chat_item_key(frame)
        update_progress()
        if key is not None:
            if key[2] < cutoff_ms:
                continue
            if key in message_keys:
                skipped_duplicates += 1
                continue
            source_messages.append(frame)
            message_keys.add(key)
            imported += 1
            continue
        kind, identity = frame_kind_and_key(frame)
        if identity is None:
            if frame not in unkeyed_static:
                unkeyed_static.add(frame)
        else:
            static[identity] = (kind, frame)

    priority = {"account": 0, "recipient": 1, "chat": 2, "sticker": 3, "adhoc": 3, "notification": 3, "folder": 4}
    static_frames = [
        frame
        for _, (kind, frame) in sorted(static.items(), key=lambda item: priority.get(item[1][0], 3))
    ]
    messages = sorted(target_messages + source_messages, key=chat_item_date)
    return static_frames + list(unkeyed_static) + messages, imported, skipped_duplicates


def encode_files(file_names: list[str]) -> bytes:
    frames = []
    for name in file_names:
        encoded_name = name.encode("ascii")
        frame = b"\x0a" + write_varint(len(encoded_name)) + encoded_name
        frames.append(frame)
    return encode_delimited(frames)


def attachment_origin(target: dict, source: dict, name: str) -> Path | None:
    for backup in (target, source):
        candidate = backup["root"] / "files" / name[:2] / name
        if candidate.is_file():
            return candidate
    return None


def missing_referenced_files(target: dict, source: dict, names: list[str]) -> list[str]:
    return [name for name in names if attachment_origin(target, source, name) is None]


def validate_file_names(names: list[str]) -> None:
    invalid = [name for name in names if not MEDIA_NAME_RE.fullmatch(name)]
    if invalid:
        preview = ", ".join(repr(name) for name in invalid[:5])
        suffix = "" if len(invalid) <= 5 else f", ... and {len(invalid) - 5} more"
        raise ValueError(f"Unsupported media name(s): {preview}{suffix}")


def missing_attachment_message(missing: list[str]) -> str:
    preview = "\n".join(f"  {name}" for name in missing[:20])
    suffix = "" if len(missing) <= 20 else f"\n  ... and {len(missing) - 20} more"
    return f"Missing {len(missing)} referenced attachment blob(s):\n{preview}{suffix}"


def attachment_names_for_merge(
    target: dict,
    source: dict,
    names: list[str],
    skip_missing: bool,
) -> tuple[list[str], list[str]]:
    validate_file_names(names)
    missing = missing_referenced_files(target, source, names)
    if missing and not skip_missing:
        raise FileNotFoundError(missing_attachment_message(missing))
    available = [name for name in names if name not in set(missing)]
    return available, missing


def copy_referenced_files(
    output_root: Path,
    target: dict,
    source: dict,
    names: list[str],
    progress: ProgressSink | None = None,
) -> None:
    output_files = output_root / "files"
    output_files.mkdir(parents=True)
    total_names = len(names)
    for index, name in enumerate(names, start=1):
        if not MEDIA_NAME_RE.fullmatch(name):
            raise ValueError(f"Unsupported media name in files index: {name!r}")
        destination = output_files / name[:2] / name
        if not destination.exists():
            origin = attachment_origin(target, source, name)
            if origin is None:
                raise FileNotFoundError(f"Attachment blob is missing for media name {name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, destination)
        if progress is not None:
            progress.update("Copying attachments", index, total_names)


def run(args: argparse.Namespace) -> None:
    progress = ProgressReporter(args.quiet)
    args.recovery_key = normalize_recovery_key(args.recovery_key)
    if not re.fullmatch(r"[0-9a-z]{64}", args.recovery_key):
        raise ValueError("The recovery key must be exactly 64 lowercase letters or digits")
    progress.stage("Validating backup locations")
    target_root, target_snapshot = find_snapshot(Path(args.target))
    source_root, source_snapshot = find_snapshot(Path(args.source))
    output_root = Path(args.output).expanduser().resolve()
    if output_root.exists():
        raise FileExistsError(f"Output already exists: {output_root}")
    if target_root == source_root:
        raise ValueError("Target and source must be different backup roots")

    progress.stage(f"Decrypting target: {target_snapshot.name}")
    target = read_snapshot(target_root, target_snapshot, args.recovery_key)
    progress.stage(f"Decrypting source: {source_snapshot.name}")
    source = read_snapshot(source_root, source_snapshot, args.recovery_key)
    if target["backup_id"] != source["backup_id"]:
        raise ValueError("Target and source belong to different Signal accounts or backup keys")

    cutoff_ms = parse_cutoff(args.cutoff)
    progress.stage("Merging chat records")
    frames, imported, skipped_duplicates = merge_frames(
        target, source, cutoff_ms, progress
    )
    names = list(dict.fromkeys(target["file_names"] + source["file_names"]))
    progress.stage("Checking attachment availability")
    names, missing = attachment_names_for_merge(
        target, source, names, args.skip_missing_attachments
    )
    if missing:
        print(
            f"Warning: skipping {len(missing)} missing attachment blob(s). "
            "Messages that refer to them will not have usable attachments.",
            file=sys.stderr,
        )

    if args.dry_run:
        progress.stage("Dry run complete; no output was created")
        print_summary(
            None,
            target_snapshot,
            source_snapshot,
            cutoff_ms,
            imported,
            skipped_duplicates,
            len(names),
            len(missing),
        )
        return

    snapshot_name = args.snapshot_name or f"signal-backup-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H-%M-%S')}"
    snapshot_output = output_root / snapshot_name
    output_root.mkdir(parents=True)
    try:
        progress.stage("Copying attachments")
        copy_referenced_files(output_root, target, source, names, progress)
        progress.stage("Writing merged snapshot")
        (snapshot_output).mkdir()
        (snapshot_output / "metadata").write_bytes(source["metadata"])
        (snapshot_output / "files").write_bytes(encode_files(names))
        (snapshot_output / "main").write_bytes(
            encrypt_main(source["header"], frames, source["aes_key"], source["mac_key"])
        )
        for backup in (target, source):
            marker = backup["root"] / ".nomedia"
            if marker.is_file():
                shutil.copy2(marker, output_root / ".nomedia")
                break
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise

    print_summary(
        output_root,
        target_snapshot,
        source_snapshot,
        cutoff_ms,
        imported,
        skipped_duplicates,
        len(names),
        len(missing),
    )


def print_summary(
    output_root: Path | None,
    target_snapshot: Path,
    source_snapshot: Path,
    cutoff_ms: int,
    imported: int,
    skipped_duplicates: int,
    attachment_count: int,
    skipped_missing_attachments: int,
) -> None:
    if output_root is not None:
        print(f"Created: {output_root}")
    else:
        print("Dry run: no output created")
    print(f"Target snapshot: {target_snapshot.name}")
    print(f"Source snapshot: {source_snapshot.name}")
    print(f"Cutoff: {cutoff_ms} ms since epoch")
    print(f"Imported chat items: {imported}")
    print(f"Skipped duplicate chat items: {skipped_duplicates}")
    print(f"Attachment blobs: {attachment_count}")
    print(f"Skipped missing attachments: {skipped_missing_attachments}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Older BackupV2 root or snapshot")
    parser.add_argument("source", help="Newer BackupV2 root or snapshot")
    parser.add_argument("output", help="New output BackupV2 root; it must not exist")
    parser.add_argument(
        "--cutoff",
        required=True,
        help="Import source messages at or after this UTC ISO timestamp or epoch milliseconds",
    )
    parser.add_argument("--snapshot-name", help="Name for the output snapshot directory")
    parser.add_argument("--recovery-key", help="64-character Signal Secure Backup recovery key")
    parser.add_argument("--dry-run", action="store_true", help="Validate and report counts without creating output")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress messages")
    parser.add_argument(
        "--skip-missing-attachments",
        action="store_true",
        help="Omit unavailable blobs from the output index and keep the messages",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.recovery_key is None:
        args.recovery_key = getpass.getpass("Signal Secure Backup recovery key: ")
    try:
        run(args)
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())