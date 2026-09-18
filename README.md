# Signal BackupV2 Merge

Merge two encrypted Signal Android `BackupV2` backups into one backup without
duplicating chat items.

> **Important:** Work on copies of your backups. The output path must not exist.
> Both inputs must belong to the same Signal account and use the same backup
> key. This tool does not process classic `.backup` files.

## Requirements

- Python 3.10 or newer
- The 64-character Signal Secure Backup recovery key
- Two Signal `BackupV2` roots or snapshot directories from the same account

## Install

Clone this repository, then run the following from its directory:

```sh
python -m venv .venv
```

Activate the virtual environment:

```sh
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install the dependency:

```sh
python -m pip install -r requirements.txt
```

## Run

```sh
python merge_signal_backup_v2.py TARGET SOURCE OUTPUT --cutoff CUTOFF
```

| Argument | Description |
| --- | --- |
| `TARGET` | Older BackupV2 root or snapshot. All of its chat items are kept. |
| `SOURCE` | Newer BackupV2 root or snapshot. Only items at or after the cutoff are imported. |
| `OUTPUT` | New path for the merged BackupV2 root. It must not already exist. |
| `CUTOFF` | UTC ISO 8601 timestamp, or epoch time in milliseconds. |

Example:

```sh
python merge_signal_backup_v2.py "D:\\Signal\\old" "D:\\Signal\\new" "D:\\Signal\\merged" --cutoff "2025-01-01T00:00:00Z"
```

The script prompts for the recovery key without displaying it. To provide it
non-interactively, add `--recovery-key`:

```sh
python merge_signal_backup_v2.py TARGET SOURCE OUTPUT --cutoff 1735689600000 --recovery-key YOUR_64_CHARACTER_RECOVERY_KEY
```

Do not put the recovery key in a shared script or shell history.

## Recommended workflow

1. Keep the original backups unchanged and choose a new, empty output path.
2. Run a dry run to validate both backups and check attachment availability:

   ```sh
   python merge_signal_backup_v2.py TARGET SOURCE OUTPUT --cutoff CUTOFF --dry-run
   ```

3. Run the same command without `--dry-run`.
4. Use the generated output root with Signal's normal BackupV2 restore/import
   process. This script does not modify or restore backups automatically.

The output contains a generated snapshot directory, encrypted `main` and
`metadata` files, a `files` index, and copied attachment blobs.

## Options

- `--snapshot-name NAME`: Set the output snapshot directory name. A UTC
  timestamp-based name is used by default.
- `--dry-run`: Validate and report counts without creating output.
- `--skip-missing-attachments`: Keep messages but omit unavailable attachment
  blobs. Without this option, missing attachments stop the merge.
- `--quiet`: Suppress progress messages. The final summary is still printed.

## Merge rules

- Chat items are deduplicated by `(chatId, authorId, dateSent)`.
- Source chat items older than the cutoff are ignored.
- Static records are deduplicated by identity; a source record replaces a
  target record with the same identity.
- Attachment blobs referenced by either backup are copied once.
- The command prints counts for imported items, duplicates, and attachments.

## Tests

```sh
python -m unittest -v
```
