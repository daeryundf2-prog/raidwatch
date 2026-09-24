"""Leftovers (`raidwatch leftovers`) — recover the investigator's own
work product left on the machine.

Best-case scenario for the defense: the search team generated their
itemized electronic-information list (전자정보 목록) and/or an export
archive on the seized machine itself and left it there — or deleted
it on the way out. Finding it means we hold their authoritative list
and possibly their extraction output, no OCR needed.

Three recovery channels:

1. live files — anything created/modified inside the raid window whose
   name or format looks like search-team output (list PDF/HWP/XLSX,
   .zip/.7z/.ad1/.e01 evidence containers, list/seizure keywords).
   Hits are copied into the results and independently hashed.
2. $Recycle.Bin — $I metadata holds the original path + deletion
   timestamp; entries deleted inside the window are flagged and their
   $R content is recovered when still present.
3. USN journal correlation (optional, needs journal.json from the
   same run) — files matching the signatures that were created and
   then deleted inside the window: gone from the filesystem but the
   journal remembers them → flag for carve recovery.

Honesty: finding nothing proves nothing — investigators usually write
to their own media. "Not found" must never be read as "they made no
list"; the printed list may live only on their laptop.
"""

from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path

from .common import ns_to_iso, sha256_file, utc_now_iso, write_json

# Formats an itemized list (전자정보 목록) is usually exported as.
LIST_EXTS = {".pdf", ".hwp", ".xlsx", ".xls", ".csv", ".docx", ".txt"}
# Evidence containers / export archives search tools produce.
CONTAINER_EXTS = {
    ".zip", ".7z", ".rar", ".ad1", ".e01", ".ex01", ".l01", ".lxf",
    ".tar", ".gz", ".001", ".dd", ".img",
}
NAME_HINTS = (
    "목록", "리스트", "압수", "전자정보", "압수물", "선별", "영장", "조서",
    "수사", "증거", "list", "seiz", "evid", "forens", "output", "report",
    "result", "export", "extract", "select", "item",
)

_SCAN_CAP = 500_000
_HIT_CAP = 50_000


def _classify(name: str, ext: str) -> str | None:
    """Return a hit category, or None."""
    low = name.lower()
    hinted = any(h in low for h in NAME_HINTS)
    if ext in CONTAINER_EXTS:
        return "container_named" if hinted else "container_in_window"
    if ext in LIST_EXTS and hinted:
        return "list_named"
    if hinted:
        return "name_match"
    if ext in LIST_EXTS:
        return "possible_list"  # new pdf/xlsx in the raid window — weak
    return None


def _filetime_to_epoch(ft: int) -> float:
    return (ft - 116444736000000000) / 10_000_000


def _parse_i_file(path: Path) -> tuple[int, float, str] | None:
    """$I metadata — v2 (Win10+) and v1 (Vista/7/8/8.1) layouts.

    v2: [ver:8=2][size:8][deltime:8][namelen:4][name UTF-16 nlen*2]
    v1: [ver:8=1][size:8][deltime:8][name UTF-16 fixed 520 bytes]
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 28:
        return None
    ver = struct.unpack_from("<Q", data, 0)[0]
    size = struct.unpack_from("<Q", data, 8)[0]
    del_ft = struct.unpack_from("<Q", data, 16)[0]
    try:
        if ver == 2:
            nlen = struct.unpack_from("<I", data, 24)[0]
            name = data[28:28 + nlen * 2].decode("utf-16-le")
        elif ver == 1 and len(data) >= 544:
            name = data[24:544].decode("utf-16-le")
        else:
            return None
    except (UnicodeDecodeError, struct.error):
        return None
    return size, _filetime_to_epoch(del_ft), name.rstrip("\x00")


def _parse_info2(
    path: Path, since_s: float, until_s: float, bin_dir: Path
) -> list[dict]:
    """XP/2003-era INFO2 index inside RECYCLER/RECYCLED.

    Header 20 bytes, then 800-byte records:
    [index:4][drive ASCII:4][deltime:8][size:4]
    [name ANSI 260][name UTF-16 520]
    Deleted content sits beside it as D<drive><index><ext> files.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 820:
        return []
    hits = []
    for off in range(20, len(data) - 799, 800):
        rec = data[off:off + 800]
        try:
            index = struct.unpack_from("<I", rec, 0)[0]
            drive = rec[4:8].rstrip(b"\x00").decode("ascii", "replace")
            del_ft = struct.unpack_from("<Q", rec, 8)[0]
            size = struct.unpack_from("<I", rec, 16)[0]
            uni = rec[280:800].decode(
                "utf-16-le", "replace").rstrip("\x00")
            ansi = rec[20:280].split(b"\x00")[0].decode(
                "cp949", "replace")
        except (struct.error, UnicodeDecodeError):
            continue
        name = uni or ansi
        if not name or not drive:
            continue
        deleted = _filetime_to_epoch(del_ft)
        if not (since_s <= deleted <= until_s):
            continue
        orig = f"{drive}{name}" if ":" in drive else name
        ext = Path(orig).suffix.lower()
        hinted = any(h in orig.lower() for h in NAME_HINTS)
        # XP stores the deleted content as D<drv><idx><ext> beside INFO2
        d_file = bin_dir / f"D{drive[0].lower()}{index}{ext}"
        hits.append({
            "category": (
                "bin_list_or_container"
                if (ext in LIST_EXTS | CONTAINER_EXTS or hinted)
                else "bin_deleted"
            ),
            "original_path": orig,
            "deleted_utc": deleted,
            "size": size,
            "i_file": str(path),
            "format": "info2_legacy",
            "r_file": str(d_file) if d_file.is_file() else None,
        })
    return hits


def _scan_recycle_bin(
    roots: list[Path], since_s: float, until_s: float
) -> list[dict]:
    hits = []
    # $Recycle.Bin (Vista+) plus XP/2003-era RECYCLER / RECYCLED.
    bin_names = ("$Recycle.Bin", "RECYCLER", "RECYCLED")
    for root in roots:
        for bin_name in bin_names:
            rb = Path(root) / bin_name
            if not rb.is_dir():
                continue
            try:
                sids = list(rb.iterdir())
            except OSError:
                continue
            for sid in sids:
                if not sid.is_dir():
                    continue
                try:
                    entries = list(sid.iterdir())
                except OSError:
                    continue
                for e in entries:
                    if e.name.startswith("$I"):
                        parsed = _parse_i_file(e)
                        if not parsed:
                            continue
                        size, deleted, orig_name = parsed
                        if not (since_s <= deleted <= until_s):
                            continue
                        ext = Path(orig_name).suffix.lower()
                        hinted = any(
                            h in orig_name.lower() for h in NAME_HINTS)
                        r_file = sid / ("$R" + e.name[2:])
                        hits.append({
                            "category": (
                                "bin_list_or_container"
                                if (ext in LIST_EXTS | CONTAINER_EXTS
                                    or hinted)
                                else "bin_deleted"
                            ),
                            "original_path": orig_name,
                            "deleted_utc": deleted,
                            "size": size,
                            "i_file": str(e),
                            "r_file": (
                                str(r_file) if r_file.is_file()
                                else None),
                        })
                    elif e.name.upper() == "INFO2":
                        hits.extend(
                            _parse_info2(e, since_s, until_s, sid))
    return hits


def _journal_deletions(
    journal_path: Path, since_iso: str | None, until_iso: str | None
) -> list[dict]:
    """Journal records of signature-looking files deleted in window."""
    try:
        data = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for ev in data.get("events") or []:
        ts = ev.get("timestamp_utc") or ""
        if since_iso and ts < since_iso:
            continue
        if until_iso and ts > until_iso:
            continue
        reasons = [str(r) for r in (ev.get("reasons") or [])]
        if not any("delete" in r or "rename_old" in r for r in reasons):
            continue
        name = str(ev.get("file_name") or "")
        ext = Path(name).suffix.lower()
        if ext in LIST_EXTS | CONTAINER_EXTS or any(
            h in name.lower() for h in NAME_HINTS
        ):
            out.append({
                "category": "deleted_in_window",
                "name": name,
                "timestamp_utc": ts,
                "reasons": reasons,
            })
    return out


def run_leftovers(
    roots: list[Path],
    out_dir: Path,
    *,
    since_ns: int | None = None,
    until_ns: int | None = None,
    journal: Path | None = None,
    max_copy_mb: int = 4096,
) -> dict:
    out_dir = Path(out_dir)
    files_dir = out_dir / "files"
    out_dir.mkdir(parents=True, exist_ok=True)
    since_s = since_ns / 1e9 if since_ns else 0.0
    until_s = until_ns / 1e9 if until_ns else float("inf")

    out_resolved = out_dir.resolve()
    hits: list[dict] = []
    scanned = 0
    seen_dirs: set[Path] = set()
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        seen_dirs.add(root.resolve())
        stack = [root]
        stop = False
        while stack and not stop:
            cur = stack.pop()
            try:
                entries = list(cur.iterdir())
            except OSError:
                continue
            scanned += len(entries)
            for p in entries:
                if scanned > _SCAN_CAP or len(hits) >= _HIT_CAP:
                    stop = True
                    break
                try:
                    if p.is_dir():
                        # Dedup by resolved path — junctions report
                        # st_ino=0 and is_symlink() misses them, but
                        # resolve() maps every reparse to its target.
                        rp = p.resolve()
                        if rp in seen_dirs:
                            continue
                        seen_dirs.add(rp)
                        if p.name not in (
                            "$Recycle.Bin", "System Volume Information",
                            "proc", "sys", "dev",
                        ) and not rp.is_relative_to(out_resolved):
                            stack.append(p)
                        continue
                    st = p.stat()
                except OSError:
                    continue
                btime = getattr(st, "st_birthtime", None)
                created = since_s <= (btime if btime is not None else st.st_ctime) <= until_s
                modified = since_s <= st.st_mtime <= until_s
                if not (created or modified):
                    continue
                cat = _classify(p.name, p.suffix.lower())
                if cat is None:
                    continue
                dest = files_dir / p.name
                i = 1
                while dest.exists():
                    dest = files_dir / f"{p.stem}_{i}{p.suffix}"
                    i += 1
                copied = None
                digest = None
                if st.st_size <= max_copy_mb * 1024 * 1024:
                    try:
                        files_dir.mkdir(exist_ok=True)
                        shutil.copy2(p, dest)
                        digest = sha256_file(dest)
                        copied = dest.name
                    except OSError:
                        pass
                hits.append({
                    "category": cat,
                    "path": str(p),
                    "created_utc": btime if btime is not None else st.st_ctime,
                    "modified_utc": st.st_mtime,
                    "size": st.st_size,
                    "copied": copied,
                    "sha256": digest,
                    "copy_skipped": copied is None,
                })
        if stop:
            break

    bin_hits = _scan_recycle_bin(roots, since_s, until_s)
    for h in bin_hits:
        r = h.get("r_file")
        if r:
            src = Path(r)
            orig = Path(h["original_path"].replace("\\", "/")).name
            dest = files_dir / ("bin_" + orig)
            try:
                files_dir.mkdir(exist_ok=True)
                shutil.copy2(src, dest)
                h["copied"] = dest.name
                h["sha256"] = sha256_file(dest)
            except OSError:
                pass
    deleted = (
        _journal_deletions(
            Path(journal),
            ns_to_iso(since_ns) if since_ns else None,
            ns_to_iso(until_ns) if until_ns else None,
        )
        if journal else []
    )

    def _count(cat_prefix: str) -> int:
        return sum(
            1 for h in hits if h["category"].startswith(cat_prefix)
        ) + sum(
            1 for h in bin_hits if h["category"].startswith(cat_prefix)
        )

    report = {
        "generated_utc": utc_now_iso(),
        "since_utc": ns_to_iso(since_ns) if since_ns else None,
        "until_utc": ns_to_iso(until_ns) if until_ns else None,
        "roots": [str(r) for r in roots],
        "summary": {
            "live_hits": len(hits),
            "lists_or_containers": (
                _count("container") + _count("list") + _count("bin_list")
            ),
            "recycle_bin_entries": len(bin_hits),
            "deleted_in_window": len(deleted),
            "scanned_entries": scanned,
            "truncated": scanned > _SCAN_CAP or len(hits) >= _HIT_CAP,
        },
        "live_files": hits,
        "recycle_bin": bin_hits,
        "deleted_in_window": deleted,
        "note": (
            "live_files/recycle_bin = search-team work product found on "
            "this machine — copied into files/ and independently "
            "hashed; these are authoritative (their own list/archive, "
            "no OCR needed). deleted_in_window = journal says a "
            "signature file was created then deleted inside the raid "
            "window — candidate for carve recovery. Empty results "
            "prove nothing: the team may have written only to their "
            "own media."
        ),
    }
    write_json(out_dir / "leftovers.json", report)
    return report
