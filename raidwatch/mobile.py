"""PC-resident mobile data preservation (`raidwatch mobile`).

When the phone itself is seized, the client's PC often still holds the
same evidence the investigators will later extract from it — KakaoTalk
PC-chat databases, iTunes/Finder backups, Smart Switch backups, desktop
messenger state. Preserving it BEFORE anyone touches the machine gives
the defense an independent copy to counter selective-context quotes
("맥락 왜곡") in the prosecution's messenger reconstruction.

Detection is path-pattern based under user profiles; everything found
is copied read-only-intent (copy2, metadata preserved) + hashed.
"""

from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest
from .inventory import iter_fs

# (target_name, glob patterns against the posix-style rel path)
TARGETS: list[tuple[str, list[str]]] = [
    (
        "kakaotalk_pc",
        [
            "Users/*/AppData/Local/Kakao/KakaoTalk/*",
            "Users/*/AppData/Local/Kakao/KakaoTalk/*/*",
            "Users/*/AppData/Local/Kakao/KakaoTalk/*/*/*",
        ],
    ),
    (
        "itunes_backup",
        [
            "Users/*/AppData/Roaming/Apple Computer/MobileSync/Backup/*",
            "Users/*/AppData/Roaming/Apple Computer/MobileSync/Backup/*/*",
            "Users/*/Apple/MobileSync/Backup/*",
            "Users/*/Apple/MobileSync/Backup/*/*",
        ],
    ),
    (
        "smartswitch",
        [
            "Users/*/Documents/*[Ss]mart[ _-][Ss]witch*/*",
            "Users/*/Documents/*[Ss]mart[ _-][Ss]witch*/*/*",
        ],
    ),
    (
        "whatsapp_desktop",
        ["Users/*/AppData/Local/Packages/*WhatsApp*/LocalState/*/*"],
    ),
    (
        "telegram_desktop",
        ["Users/*/AppData/Roaming/Telegram Desktop/tdata/*/*"],
    ),
]


def _classify(rel: str) -> str | None:
    for name, patterns in TARGETS:
        if any(fnmatch.fnmatchcase(rel, p) for p in patterns):
            return name
    return None


def _is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def collect_mobile(
    root: Path,
    out_dir: Path,
    *,
    max_file_bytes: int = 2 * 1024 * 1024 * 1024,
) -> dict:
    """Detect + preserve PC-resident mobile messenger/backup data."""
    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    copies_dir = out_dir / "copies"

    by_target: dict[str, list] = {}
    summary = {"matched": 0, "copied": 0, "skipped_large": 0, "sqlite_dbs": 0}
    entries = []
    for rel, abs_path, st, kind in iter_fs(root):
        if kind != "file" or st is None:
            continue
        target = _classify(rel)
        if target is None:
            continue
        summary["matched"] += 1
        entry = {
            "path": rel,
            "target": target,
            "size": st.st_size,
        }
        if st.st_size > max_file_bytes:
            entry["status"] = "skipped_too_large"
            summary["skipped_large"] += 1
            entries.append(entry)
            by_target.setdefault(target, []).append(entry)
            continue
        dest = copies_dir / target / rel.replace("/", "__")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(abs_path, dest)
        except OSError as exc:
            entry["status"] = "copy_failed"
            entry["error"] = str(exc)
            entries.append(entry)
            by_target.setdefault(target, []).append(entry)
            continue
        entry["status"] = "copied"
        entry["copied_to"] = str(dest)
        entry["sha256"] = sha256_file(abs_path)
        if _is_sqlite(abs_path):
            entry["sqlite"] = True
            summary["sqlite_dbs"] += 1
        summary["copied"] += 1
        entries.append(entry)
        by_target.setdefault(target, []).append(entry)

    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "targets_found": sorted(by_target),
        "items": entries,
        "note": (
            "PC-resident copies of mobile data preserved read-only-intent. "
            "These predate the seizure — compare against the prosecution's "
            "phone extraction to catch selective-context reconstruction. "
            "KakaoTalk/iTunes DBs are SQLite; carve/open them offline."
        ),
    }
    write_json(out_dir / "mobile.json", report)
    write_manifest(out_dir, "mobile", {"summary": summary})
    return report
