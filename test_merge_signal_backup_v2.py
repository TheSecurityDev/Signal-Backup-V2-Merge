import os
import tempfile
import unittest
from pathlib import Path

import merge_signal_backup_v2 as merge


def varint_field(number: int, value: int) -> bytes:
    return merge.write_varint(number << 3) + merge.write_varint(value)


def bytes_field(number: int, value: bytes) -> bytes:
    return (
        merge.write_varint((number << 3) | 2)
        + merge.write_varint(len(value))
        + value
    )


def chat_item(chat_id: int, author_id: int, date_sent: int) -> bytes:
    payload = (
        varint_field(1, chat_id)
        + varint_field(2, author_id)
        + varint_field(3, date_sent)
    )
    return bytes_field(4, payload)


class MergeSignalBackupV2Tests(unittest.TestCase):
    def test_missing_attachments_can_be_skipped_explicitly(self):
        present = "aa" * 32
        missing = "bb" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blob = root / "files" / present[:2] / present
            blob.parent.mkdir(parents=True)
            blob.write_bytes(b"attachment")
            backup = {"root": root}

            available, missing_names = merge.attachment_names_for_merge(
                backup, backup, [present, missing], skip_missing=True
            )

        self.assertEqual(available, [present])
        self.assertEqual(missing_names, [missing])

    def test_missing_attachments_are_strict_by_default(self):
        missing = "cc" * 32
        with tempfile.TemporaryDirectory() as directory:
            backup = {"root": Path(directory)}
            with self.assertRaises(FileNotFoundError):
                merge.attachment_names_for_merge(
                    backup, backup, [missing], skip_missing=False
                )

    def test_cutoff_without_timezone_is_utc(self):
        self.assertEqual(merge.parse_cutoff("1970-01-01T00:00:00"), 0)

    def test_entropy_pool_normalization(self):
        entropy_pool = "AbC1 " * 16

        self.assertEqual(merge.normalize_entropy_pool(entropy_pool), "abc1" * 16)

    def test_main_round_trip_and_chat_item_key(self):
        aes_key = os.urandom(32)
        mac_key = os.urandom(32)
        header = b"\x08\x01"
        frame = chat_item(7, 9, 1234)

        encrypted = merge.encrypt_main(header, [frame], aes_key, mac_key)

        actual_header, actual_frames = merge.decrypt_main(
            encrypted, aes_key, mac_key
        )
        self.assertEqual((actual_header, actual_frames), (header, [frame]))
        self.assertEqual(merge.chat_item_key(frame), (7, 9, 1234))

    def test_merge_filters_cutoff_deduplicates_and_replaces_account(self):
        target = {
            "frames": [
                chat_item(1, 2, 100),
                chat_item(1, 3, 200),
                b"\x0a\x03old",
            ]
        }
        source = {
            "frames": [
                chat_item(1, 2, 100),
                chat_item(1, 4, 300),
                b"\x0a\x03new",
            ]
        }

        frames, imported, skipped = merge.merge_frames(target, source, 250)

        self.assertEqual(imported, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(
            [merge.chat_item_key(frame) for frame in frames if merge.chat_item_key(frame)],
            [(1, 2, 100), (1, 3, 200), (1, 4, 300)],
        )
        self.assertEqual(
            sum(merge.frame_kind_and_key(frame)[0] == "account" for frame in frames),
            1,
        )
        self.assertIn(b"\x0a\x03new", frames)
        self.assertNotIn(b"\x0a\x03old", frames)

    def test_merge_progress_counts_all_frames(self):
        class RecordingProgress:
            def __init__(self):
                self.updates = []

            def update(self, label, current, total):
                self.updates.append((label, current, total))

        progress = RecordingProgress()
        merge.merge_frames(
            {"frames": [chat_item(1, 2, 100), b"\x0a\x03old"]},
            {"frames": [chat_item(1, 4, 300), b"\x0a\x03new"]},
            0,
            progress,
        )

        self.assertEqual(progress.updates[-1], ("Analyzing frames", 4, 4))


if __name__ == "__main__":
    unittest.main()