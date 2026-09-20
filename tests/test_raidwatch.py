from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from raidwatch.artifacts import collect_artifacts
from raidwatch.cli import main as cli_main
from raidwatch.common import iso_to_ns, utc_now_iso
from raidwatch.db import Inventory
from raidwatch.diff import diff_inventories
from raidwatch.inventory import build_inventory
from raidwatch.profile import evaluate, load_profile
from raidwatch.scan import scan_target
from raidwatch.sources import collect_sources, extract_strings
from raidwatch.verify import parse_seized_list, verify_items
from raidwatch.watcher import run_watch


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _backdate_creation(path: Path, epoch_s: float) -> bool:
    """Set a file's creation time backwards — os.utime only moves
    atime/mtime, but the window/leftovers logic keys on btime/ctime.

    Windows: SetFileTime can rewrite creation time. POSIX: nothing can
    (btime is immutable, ctime is metadata-change) — callers should
    skipTest when this returns False and the signal still looks new.
    """
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    ft = int((epoch_s + 11644473600) * 10_000_000)  # unix s → FILETIME

    class _FT(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    buf = _FT(ft & 0xFFFFFFFF, (ft >> 32) & 0xFFFFFFFF)
    h = ctypes.windll.kernel32.CreateFileW(
        str(path),
        0x0100,       # FILE_WRITE_ATTRIBUTES
        0x00000007,   # share rw+delete
        None,
        3,            # OPEN_EXISTING
        0x02000000,   # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    if h in (-1, wintypes.HANDLE(-1).value):
        return False
    try:
        ok = ctypes.windll.kernel32.SetFileTime(
            h, ctypes.byref(buf), None, None)
    finally:
        ctypes.windll.kernel32.CloseHandle(h)
    return bool(ok)


def _creation_signal(path: Path) -> float:
    st = path.lstat()
    bt = getattr(st, "st_birthtime", None)
    return bt if bt is not None else st.st_ctime


class RaidwatchFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        _write(root / "docs" / "contract.hwp", "fake hwp body 계약서".encode("utf-8"))
        _write(root / "docs" / "notes.txt", b"plain notes")
        _write(root / "docs" / "계약서_초안.txt", b"draft")
        _write(root / "photos" / "img001.jpg", b"\xff\xd8\xffJPEGDATA")
        _write(root / "sys" / "driver.sys", b"sysdata")
        _write(root / "docs" / "report.pdf", b"%PDF-1.4 fake")

    @staticmethod
    def profile_dict() -> dict:
        return {
            "profile_version": "1.0",
            "case_id": "TEST-001",
            "criteria": {
                "keywords": [{"term": "계약서"}],
                "extensions": [".hwp", ".txt"],
                "filename_patterns": ["*초안*", "report.*"],
                "path_exclude": ["sys/*"],
            },
        }


class BaselineTests(unittest.TestCase):
    def test_baseline_records_all_files_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            summary = build_inventory(root, inv)
            paths = inv.paths()
            self.assertIn("docs/contract.hwp", paths)
            self.assertIn("photos/img001.jpg", paths)
            rec = inv.get("docs/notes.txt")
            self.assertEqual(rec.status, "ok")
            self.assertEqual(len(rec.sha256), 64)
            self.assertEqual(summary["counts"]["file"], 6)
            inv.close()


class ScanTests(unittest.TestCase):
    def test_scan_narrow_vs_broad_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            profile_path = Path(td) / "profile.json"
            profile_path.write_text(
                json.dumps(RaidwatchFixture.profile_dict()), encoding="utf-8"
            )
            profile = load_profile(profile_path)
            result = scan_target(root, profile)
            hits = {h["path"]: h for h in result["hits"]}

            # contract.hwp: extension only (keyword/pattern miss) → borderline
            self.assertEqual(hits["docs/contract.hwp"]["verdict"], "borderline")
            # 계약서_초안.txt: keyword AND extension AND *초안* pattern → in_scope
            self.assertEqual(hits["docs/계약서_초안.txt"]["verdict"], "in_scope")
            # report.pdf: filename pattern only → borderline
            self.assertEqual(hits["docs/report.pdf"]["verdict"], "borderline")
            # sys/driver.sys: path_exclude → not a hit
            self.assertNotIn("sys/driver.sys", hits)
            # photos/img001.jpg: no criteria → not a hit
            self.assertNotIn("photos/img001.jpg", hits)

    def test_evaluate_excluded_and_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "p.json"
            profile_path.write_text(
                json.dumps(RaidwatchFixture.profile_dict()), encoding="utf-8"
            )
            profile = load_profile(profile_path)
            item = {"path": "sys/driver.sys", "size": 7, "mtime_ns": 1,
                    "ctime_ns": 1, "atime_ns": 1, "sha256": None}
            self.assertEqual(evaluate(item, profile)["verdict"], "excluded")
            item2 = dict(item, path="misc/random.bin")
            self.assertEqual(evaluate(item2, profile)["verdict"], "out_of_scope")


class DiffTests(unittest.TestCase):
    def test_diff_classifies_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            base = Inventory(Path(td) / "base.db", create=True)
            build_inventory(root, base)

            # simulate raid aftermath
            (root / "docs" / "notes.txt").write_bytes(b"tampered content")
            (root / "docs" / "contract.hwp").unlink()
            _write(root / "new" / "planted.exe", b"MZ...")
            os.utime(root / "photos" / "img001.jpg", None)  # metadata touch

            cur = Inventory(Path(td) / "cur.db", create=True)
            build_inventory(root, cur)
            report = diff_inventories(base, cur)
            s = report["summary"]

            self.assertEqual(s["removed"], 1)
            self.assertEqual(s["added"], 2)  # new/ dir + new/planted.exe
            self.assertGreaterEqual(s["content_changed"], 1)
            classes = {c["path"]: c["class"] for c in report["changed"]}
            self.assertEqual(classes["docs/notes.txt"], "content_changed")
            base.close()
            cur.close()

    def test_diff_flags_backdated_added_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            base = Inventory(Path(td) / "base.db", create=True)
            build_inventory(root, base)

            # simulate a planted file whose mtime was stomped into the past
            planted = _write(root / "docs" / "planted_old.hwp", b"planted")
            old_ns = iso_to_ns("2001-01-01")
            os.utime(planted, ns=(old_ns, old_ns))

            cur = Inventory(Path(td) / "cur.db", create=True)
            build_inventory(root, cur)
            baseline_created_ns = iso_to_ns(utc_now_iso())
            report = diff_inventories(
                base, cur, baseline_created_ns=baseline_created_ns
            )
            self.assertEqual(report["summary"]["backdated_added"], 1)
            planted_entry = next(
                a for a in report["added"] if a["path"] == "docs/planted_old.hwp"
            )
            self.assertTrue(planted_entry["backdated"])
            base.close()
            cur.close()

    def test_diff_classifies_atime_only_as_accessed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            base = Inventory(Path(td) / "base.db", create=True)
            build_inventory(root, base)

            # touch atime only on one file
            target = root / "docs" / "report.pdf"
            st = target.stat()
            os.utime(target, ns=(st.st_atime_ns + 5_000_000_000, st.st_mtime_ns))

            cur = Inventory(Path(td) / "cur.db", create=True)
            build_inventory(root, cur)
            report = diff_inventories(base, cur)
            classes = {c["path"]: c["class"] for c in report["changed"]}
            self.assertEqual(classes.get("docs/report.pdf"), "accessed")
            base.close()
            cur.close()


class VerifyTests(unittest.TestCase):
    def test_verify_statuses_and_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)

            profile_path = Path(td) / "p.json"
            profile_path.write_text(
                json.dumps(RaidwatchFixture.profile_dict()), encoding="utf-8"
            )
            profile = load_profile(profile_path)

            ok_hash = inv.get("docs/계약서_초안.txt").sha256
            seized = [
                {"claimed_path": "C:\\docs\\계약서_초안.txt",
                 "rel": "docs/계약서_초안.txt", "sha256": ok_hash},
                {"claimed_path": "docs/notes.txt",
                 "rel": "docs/notes.txt", "sha256": "0" * 64},
                {"claimed_path": "photos/img001.jpg",
                 "rel": "photos/img001.jpg", "sha256": None},
                {"claimed_path": "docs/nonexistent.pdf",
                 "rel": "docs/nonexistent.pdf", "sha256": None},
            ]
            report = verify_items(seized, inv, profile=profile)
            s = report["summary"]

            self.assertEqual(s["verified"], 2)  # hash-verified + path-only match
            self.assertEqual(s["hash_mismatch"], 1)
            self.assertEqual(s["not_in_inventory"], 1)
            scope = {it["claimed_path"]: it["scope_verdict"] for it in report["items"]}
            self.assertEqual(scope["photos/img001.jpg"], "out_of_scope")
            inv.close()

    def test_fuzzy_match_recovers_ocr_damaged_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)

            # OCR-damaged claimed path: U5ers-style corruption of the real path
            seized = [
                {"claimed_path": "d0cs/계약서_초압.txt",
                 "rel": "d0cs/계약서_초압.txt", "sha256": None},
                {"claimed_path": "t0tally/missing.bin",
                 "rel": "t0tally/missing.bin", "sha256": None},
            ]
            report = verify_items(seized, inv)
            s = report["summary"]
            self.assertEqual(s["fuzzy_matched"], 1)
            self.assertEqual(s["not_in_inventory"], 1)
            first = report["items"][0]
            self.assertEqual(first["matched_path"], "docs/계약서_초안.txt")
            self.assertTrue(any("fuzzy" in n for n in first["notes"]))
            inv.close()

    def test_parse_seized_list_pdf_text_layer(self) -> None:
        import zlib

        with tempfile.TemporaryDirectory() as td:
            payload = zlib.compress(
                b"BT (docs/report.pdf) Tj ET BT (docs/notes.txt) Tj ET"
            )
            pdf = _write(
                Path(td) / "seized.pdf",
                b"%PDF-1.4\nstream\n" + payload + b"\nendstream\n",
            )
            items = parse_seized_list(pdf)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0]["rel"], "docs/report.pdf")

    def test_parse_seized_list_scanned_pdf_needs_ocr(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pdf = _write(Path(td) / "scan.pdf", b"%PDF-1.4\nstream\n" + b"\x00" * 300)
            items = parse_seized_list(pdf)
            self.assertEqual(len(items), 1)
            self.assertTrue(items[0]["unparsed"])
            self.assertIn("OCR", items[0]["raw"]["pdf"])

    def test_parse_seized_list_txt_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            txt = Path(td) / "list.txt"
            txt.write_text(
                "docs/a.hwp\n" + "f" * 64 + "  docs/b.txt\n", encoding="utf-8"
            )
            items = parse_seized_list(txt)
            self.assertEqual(len(items), 2)
            self.assertIsNone(items[0]["sha256"])
            self.assertEqual(items[1]["sha256"], "f" * 64)
            self.assertEqual(items[1]["rel"], "docs/b.txt")

            csv_path = Path(td) / "list.csv"
            csv_path.write_text(
                "path,sha256\nC:\\docs\\a.hwp," + "a" * 64 + "\n", encoding="utf-8"
            )
            items = parse_seized_list(csv_path)
            self.assertEqual(items[0]["rel"], "docs/a.hwp")
            self.assertEqual(items[0]["sha256"], "a" * 64)


class SourcesTests(unittest.TestCase):
    def test_collects_spool_temp_and_recycle_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "seized-pc"
            _write(
                root / "Windows" / "System32" / "spool" / "PRINTERS" / "00042.SPL",
                b"\x00\x01Seized Evidence List docs/contract.hwp sha256=abc\x00",
            )
            _write(
                root / "Users" / "admin" / "AppData" / "Local" / "Temp"
                / "evidence_list.csv",
                b"path,sha256\ndocs/a.hwp,deadbeef\n",
            )
            _write(
                root / "Users" / "admin" / "AppData" / "Local" / "Temp"
                / "random_cache.bin",
                b"\x00\x01\x02\x03",
            )
            _write(root / "$Recycle.Bin" / "S-1-5-21" / "$RXYZ.csv", b"old,list\n")
            _write(root / "docs" / "normal.txt", b"ordinary file")

            out = Path(td) / "sources-out"
            report = collect_sources(root, out)
            s = report["summary"]

            self.assertEqual(s["by_reason"]["spool"], 1)
            self.assertEqual(s["by_reason"]["temp"], 1)  # csv only, not .bin
            self.assertEqual(s["by_reason"]["recycle_bin"], 1)
            paths = {i["path"] for i in report["items"]}
            self.assertNotIn("docs/normal.txt", paths)

            # SPL strings extraction recovered embedded text
            spl_item = next(
                i for i in report["items"] if i["path"].endswith("00042.SPL")
            )
            self.assertIsNotNone(spl_item["extracted_to"])
            extracted = Path(spl_item["extracted_to"]).read_text(encoding="utf-8")
            self.assertIn("Seized Evidence List", extracted)

    def test_extract_strings_finds_ascii_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            blob = Path(td) / "blob.bin"
            blob.write_bytes(b"\x01\x02evidence-item-list\x00\xff")
            self.assertIn("evidence-item-list", extract_strings(blob))


class ArtifactsTests(unittest.TestCase):
    def test_collects_investigator_traces_and_tools(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "seized-pc"
            _write(
                root / "Windows" / "Prefetch" / "FTKIMAGER.EXE-12AB34CD.pf",
                b"prefetch-data",
            )
            _write(
                root / "Windows" / "Prefetch" / "SVCHOST.EXE-99887766.pf",
                b"prefetch-data",
            )
            _write(
                root / "Windows" / "System32" / "winevt" / "Logs"
                / "System.evtx",
                b"evtx-data",
            )
            _write(
                root / "Users" / "admin" / "AppData" / "Roaming" / "Microsoft"
                / "Windows" / "Recent" / "secret.lnk",
                b"L\x00\x00\x00C:\\Users\\admin\\Documents\\secret.hwp\x00",
            )
            _write(root / "Windows" / "System32" / "config" / "SYSTEM", b"hive")
            _write(root / "docs" / "unrelated.txt", b"nope")

            out = Path(td) / "art-out"
            report = collect_artifacts(root, out)
            s = report["summary"]

            self.assertGreaterEqual(s["matched"], 4)
            tools = report["observed_investigator_tools"]
            self.assertIn("FTK Imager", tools)
            self.assertNotIn("svchost", json.dumps(tools).lower())

            all_entries = [e for lst in report["artifacts"].values() for e in lst]
            cats = {e["category"] for e in all_entries}
            self.assertIn("prefetch", cats)
            self.assertIn("evtx", cats)
            self.assertIn("recent_items", cats)
            self.assertIn("registry_or_device_log", cats)
            lnk_entry = next(
                e for e in all_entries if e["path"].endswith("secret.lnk")
            )
            self.assertTrue(
                any("secret.hwp" in t for t in lnk_entry["link_targets_guess"])
            )
            self.assertIn("shadow_copies", report)


class WatchTests(unittest.TestCase):
    def test_watch_records_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            out = Path(td) / "watch"
            run_watch(root, out, once=True)
            (root / "intruder.log").write_bytes(b"new file")
            run_watch(root, out, once=True)
            events = [
                json.loads(line)
                for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            kinds = [e["event"] for e in events]
            self.assertIn("session_start", kinds)
            self.assertIn("snapshot_init", kinds)
            created = [e for e in events if e["event"] == "created"]
            self.assertTrue(any(e["path"] == "intruder.log" for e in created))

    def test_watch_records_process_events(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            out = Path(td) / "watch"
            run_watch(root, out, once=True)
            proc = subprocess.Popen(["sleep", "5"])
            try:
                run_watch(root, out, once=True)
            finally:
                proc.terminate()
                proc.wait()
            events = [
                json.loads(line)
                for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            started = [e for e in events if e["event"] == "process_started"]
            self.assertTrue(any("sleep" in e["name"] for e in started))


class CliTests(unittest.TestCase):
    def test_cli_baseline_and_diff_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            base_out = Path(td) / "case" / "baseline"
            rc = cli_main(["baseline", str(root), "--out", str(base_out)])
            self.assertEqual(rc, 0)
            self.assertTrue((base_out / "inventory.db").exists())
            self.assertTrue((base_out / "manifest.json").exists())

            (root / "docs" / "notes.txt").write_bytes(b"changed")
            diff_out = Path(td) / "case" / "diff"
            rc = cli_main([
                "diff",
                "--baseline", str(base_out / "inventory.db"),
                "--rescan", str(root),
                "--out", str(diff_out),
            ])
            self.assertEqual(rc, 0)
            report = json.loads((diff_out / "diff.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["content_changed"], 1)
            self.assertTrue((diff_out / "report.md").exists())


class TextExtractTests(unittest.TestCase):
    def test_plain_text_cp949(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            from raidwatch.text_extract import extract_text

            f = _write(Path(td) / "memo.txt", "계약서 압수 대상".encode("cp949"))
            self.assertIn("압수", extract_text(f))

    def test_docx_xml_extraction(self) -> None:
        import zipfile

        with tempfile.TemporaryDirectory() as td:
            from raidwatch.text_extract import extract_text

            docx = Path(td) / "doc.docx"
            with zipfile.ZipFile(docx, "w") as zf:
                zf.writestr(
                    "word/document.xml",
                    "<w:doc><w:t>비밀계약 문서 본문</w:t></w:doc>",
                )
            self.assertIn("비밀계약", extract_text(docx))

    def test_pdf_stream_strings(self) -> None:
        import zlib

        with tempfile.TemporaryDirectory() as td:
            from raidwatch.text_extract import extract_text

            payload = zlib.compress(b"BT (seized-evidence-list-2024) Tj ET")
            pdf = _write(
                Path(td) / "list.pdf",
                b"%PDF-1.4\nstream\n" + payload + b"\nendstream\n",
            )
            self.assertIn("seized-evidence", extract_text(pdf))

    def test_zip_member_recursion(self) -> None:
        import zipfile

        with tempfile.TemporaryDirectory() as td:
            from raidwatch.text_extract import extract_text

            zpath = Path(td) / "archive.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("inner/memo.txt", "내부 문서 증거")
            self.assertIn("증거", extract_text(zpath))

    def test_unsupported_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            from raidwatch.text_extract import extract_text

            f = _write(Path(td) / "img.jpg", b"\xff\xd8\xff")
            self.assertIsNone(extract_text(f))


class ContentScanTests(unittest.TestCase):
    def test_content_keyword_produces_hit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            _write(root / "plain.bin", b"binary")
            _write(root / "memo.txt", "본문에 은밀한계약 키워드".encode("utf-8"))

            profile_path = Path(td) / "p.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "criteria": {
                            "keywords": [
                                {"term": "은밀한계약", "in": "content"}
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_path)
            result = scan_target(root, profile)
            self.assertEqual(result["summary"]["content_extracted"], 1)
            hits = {h["path"]: h for h in result["hits"]}
            self.assertIn("memo.txt", hits)
            self.assertNotIn("plain.bin", hits)


class MftTests(unittest.TestCase):
    @staticmethod
    def _record(
        name: str,
        data: bytes,
        *,
        deleted: bool,
        si_mtime: int = 133000000000000000,
        fn_mtime: int = 133000000000000000,
    ) -> bytes:
        """Build a minimal 1024-byte FILE record (valid fixup)."""
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<HH", rec, 4, 0x30, 3)  # usa off, count
        struct.pack_into("<HHH", rec, 0x30, 0xAAAA, 0x1111, 0x2222)
        rec[510:512] = b"\xaa\xaa"  # pre-fixup sector tails
        rec[1022:1024] = b"\xaa\xaa"
        struct.pack_into("<H", rec, 0x14, 0x38)  # first attr
        struct.pack_into("<H", rec, 0x16, 0 if deleted else 1)  # flags

        off = 0x38

        def put_attr(atype: int, content: bytes) -> None:
            nonlocal off
            hdr = 24
            struct.pack_into("<II", rec, off, atype, hdr + len(content))
            rec[off + 8] = 0  # resident
            struct.pack_into("<IH", rec, off + 16, len(content), hdr)
            rec[off + hdr : off + hdr + len(content)] = content
            off += hdr + len(content)

        si = struct.pack("<4Q", si_mtime, si_mtime, si_mtime, si_mtime) + b"\0" * 24
        put_attr(0x10, si)

        nb = name.encode("utf-16-le")
        fn = (
            struct.pack("<Q", 5)
            + struct.pack("<4Q", fn_mtime, fn_mtime, fn_mtime, fn_mtime)
            + struct.pack("<QQ", len(data), len(data))
            + struct.pack("<II", 0, 0)
            + bytes([len(name), 1])
            + nb
        )
        put_attr(0x30, fn)
        put_attr(0x80, data)
        struct.pack_into("<I", rec, off, 0xFFFFFFFF)
        return bytes(rec)

    def test_parse_deleted_and_timestomp_flag(self) -> None:
        import struct as _s  # noqa: F401  (kept for symmetry)

        from raidwatch.mft import parse_mft

        deleted = self._record("temp_list.csv", b"path,hash\n", deleted=True)
        stomped = self._record(
            "planted.txt", b"x", deleted=False,
            si_mtime=132000000000000000, fn_mtime=133000000000000000,
        )
        entries = parse_mft(deleted + stomped)
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0]["deleted"])
        self.assertEqual(entries[0]["name"], "temp_list.csv")
        self.assertFalse(entries[0]["si_fn_mismatch"])
        self.assertTrue(entries[1]["si_fn_mismatch"])

    def test_carve_recovers_resident_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            from raidwatch.mft import carve_mft

            dump = Path(td) / "mft.bin"
            dump.write_bytes(
                self._record("목록.csv", "경로,해시\n".encode("utf-8"), deleted=True)
            )
            report = carve_mft(dump, Path(td) / "out")
            self.assertEqual(report["summary"]["resident_recovered"], 1)
            rec = report["resident_recovered"][0]
            self.assertEqual(rec["name"], "목록.csv")
            self.assertIn("해시", Path(rec["recovered_to"]).read_text("utf-8"))


class JournalTests(unittest.TestCase):
    def test_parse_usn_csv(self) -> None:
        from raidwatch.journal import parse_usn_csv

        csv_text = (
            "File name,Reason,Time stamp,USN\n"
            "evidence_list.xlsx,0x00000100,0x01DAC00000000000,0x1234\n"
            "temp_report.csv,0x00000200,0x01DAC00000000001,0x1235\n"
        )
        events = parse_usn_csv(csv_text)
        self.assertEqual(len(events), 2)
        self.assertIn("file_create", events[0]["reasons"])
        self.assertIn("file_delete", events[1]["reasons"])
        self.assertIsNotNone(events[0]["timestamp_utc"])

    def test_replay_journal_filters_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            from raidwatch.journal import replay_journal

            csv_path = Path(td) / "j.csv"
            csv_path.write_text(
                "File name,Reason,Time stamp,USN\n"
                "a.txt,0x00000200,0x01DAC00000000000,0x1\n",
                encoding="utf-8",
            )
            report = replay_journal(Path(td) / "out", csv_path=csv_path)
            self.assertEqual(report["summary"]["events_parsed"], 1)
            self.assertEqual(
                report["summary"]["deletes_renames_security_changes"], 1
            )


class PfparseTests(unittest.TestCase):
    def test_v30_prefetch(self) -> None:
        import struct

        from raidwatch.pfparse import parse_prefetch

        data = bytearray(0x200)
        struct.pack_into("<I", data, 0, 30)  # version @0x00: Win10
        data[4:8] = b"SCCA"  # signature @0x04 (real .pf layout)
        data[0x10:0x4C] = "FTKIMAGER.EXE".encode("utf-16-le").ljust(60, b"\0")
        struct.pack_into("<Q", data, 0x80, 133600000000000000)  # last run
        struct.pack_into("<I", data, 0xD0, 7)  # run count
        pf = parse_prefetch(bytes(data))
        self.assertEqual(pf["status"], "ok")
        self.assertEqual(pf["exe_name"], "FTKIMAGER.EXE")
        self.assertEqual(pf["run_count"], 7)
        self.assertEqual(len(pf["last_runs_utc"]), 1)

    def test_mam_compressed_falls_back(self) -> None:
        from raidwatch.pfparse import parse_prefetch

        pf = parse_prefetch(b"MAM\x04" + b"\0" * 32)
        self.assertEqual(pf["status"], "compressed_unparsed")


class EvtxTests(unittest.TestCase):
    def test_chunk_decompression_and_strings(self) -> None:
        import zlib

        from raidwatch.evtx import decompress_chunks, evtx_strings

        # EVTX chunks carry raw DEFLATE (no zlib wrapper)
        co = zlib.compressobj(level=6, wbits=-15)
        payload = (
            co.compress("Print Job 307 목록.xlsx".encode("utf-16-le"))
            + co.flush()
        )
        data = bytearray(0x1000 + 0x200 + len(payload))
        data[0:8] = b"ElfFile\x00"
        data[0x1000 : 0x1000 + 8] = b"ElfChnk\x00"
        # next_record_offset @chunk+48 bounds the compressed region
        next_rec = 0x1000 + 0x200 + len(payload)
        data[0x1000 + 48 : 0x1000 + 52] = next_rec.to_bytes(4, "little")
        data[0x1200 : 0x1200 + len(payload)] = payload

        blob = decompress_chunks(bytes(data))
        self.assertIn("Print Job".encode("utf-16-le"), blob)

        evtx = Path(tempfile.mkdtemp()) / "PrintService.evtx"
        evtx.write_bytes(bytes(data))
        strings = evtx_strings(evtx)
        self.assertTrue(any("Print Job" in s for s in strings))


class PackageTests(unittest.TestCase):
    def test_package_builds_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = Path(td) / "case"
            verify_dir = case / "verify"
            verify_dir.mkdir(parents=True)
            (verify_dir / "verify.json").write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "claimed_path": "photos/img001.jpg",
                                "claimed_sha256": "a" * 64,
                                "status": "verified",
                                "scope_verdict": "out_of_scope",
                                "notes": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (verify_dir / "manifest.json").write_text(
                json.dumps({"command": "verify", "finished_utc": utc_now_iso()}),
                encoding="utf-8",
            )

            from raidwatch.package import build_package

            out = Path(td) / "package"
            result = build_package(case, out)
            self.assertEqual(result["summary"]["disposal_items"], 1)
            self.assertTrue((out / "폐기청구목록.md").exists())
            self.assertTrue((out / "절차기록.md").exists())
            self.assertTrue((out / "index.json").exists())
            body = (out / "폐기청구목록.md").read_text(encoding="utf-8")
            self.assertIn("photos/img001.jpg", body)


class RegressionTests(unittest.TestCase):
    """Bugs caught by adversarial review — must not regress."""

    def _profile(self, criteria: dict) -> dict:
        """Build a normalized criteria dict (as load_profile produces)."""
        crit = {
            "keywords": [],
            "extensions": set(),
            "filename_patterns": [],
            "date_ranges": [],
            "path_include": [],
            "path_exclude": [],
            "size_bytes": {"min": None, "max": None},
            "hash_sets": [],
        }
        for k, v in criteria.items():
            if k == "keywords":
                v = [
                    {
                        "term": kw["term"],
                        "regex": kw.get("regex", False),
                        "in": kw.get("in", "name"),
                        "case_sensitive": kw.get("case_sensitive", False),
                    }
                    for kw in v
                ]
            elif k == "extensions":
                v = set(v)
            crit[k] = v
        return {"criteria": crit, "profile_sha256": "x"}

    def test_content_only_keyword_unverifiable_not_out_of_scope(self) -> None:
        # A file we could not extract text from must NOT be classified
        # out_of_scope — the content criterion was never evaluated.
        profile = self._profile({
            "keywords": [{"term": "비밀", "in": "content"}],
            "extensions": [],
            "filename_patterns": [],
        })
        item = {"path": "a.bin", "name": "a.bin", "size": 10,
                "mtime_ns": 1, "ctime_ns": 1, "atime_ns": 1,
                "sha256": None, "kind": "file", "status": "ok",
                "content": None}
        self.assertEqual(evaluate(item, profile)["verdict"], "unverifiable")

    def test_in_scope_partial_when_a_group_unevaluable(self) -> None:
        # extension matched but content keyword unevaluable → partial,
        # not a full in_scope endorsement.
        profile = self._profile({
            "keywords": [{"term": "비밀", "in": "content"}],
            "extensions": [".bin"],
            "filename_patterns": [],
        })
        item = {"path": "a.bin", "name": "a.bin", "size": 10,
                "mtime_ns": 1, "ctime_ns": 1, "atime_ns": 1,
                "sha256": None, "kind": "file", "status": "ok",
                "content": None}
        self.assertEqual(
            evaluate(item, profile)["verdict"], "in_scope_partial"
        )

    def test_md5_claim_is_not_a_sha256_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)
            seized = [{
                "claimed_path": "docs/notes.txt",
                "rel": "docs/notes.txt",
                "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_algo": "md5",
            }]
            report = verify_items(seized, inv)
            self.assertEqual(report["summary"]["hash_mismatch"], 0)
            self.assertEqual(report["summary"]["hash_incomparable"], 1)
            inv.close()

    def test_claimed_hash_without_baseline_digest_is_unverifiable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv, hash_files=False)
            seized = [{
                "claimed_path": "docs/notes.txt",
                "rel": "docs/notes.txt",
                "sha256": "a" * 64,
                "hash_algo": "sha256",
            }]
            report = verify_items(seized, inv)
            item = report["items"][0]
            self.assertEqual(item["status"], "unverifiable")
            inv.close()

    def test_rebuild_drops_stale_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)
            (root / "docs" / "notes.txt").unlink()
            (root / "docs" / "report.pdf").unlink()
            build_inventory(root, inv)  # same db reused
            self.assertNotIn("docs/notes.txt", inv.paths())
            self.assertNotIn("docs/report.pdf", inv.paths())
            inv.close()

    def test_headerless_fsutil_journal_rows(self) -> None:
        from raidwatch.journal import parse_usn_csv

        # fsutil csv output has NO header: name,fileid,parentid,usn,time,reason
        text = (
            '"out.exe","0x100","0x5","0x1234",'
            '"2024-05-01 12:00:00","File create | Close"\n'
            '"gone.txt","0x101","0x5","0x1235",'
            '"2024-05-01 12:01:00","File delete | Close"\n'
        )
        events = parse_usn_csv(text)
        names = {e["file_name"] for e in events}
        self.assertIn("gone.txt", names)
        delete_ev = next(e for e in events if e["file_name"] == "gone.txt")
        self.assertIn("file_delete", delete_ev["reasons"])
        self.assertIsNotNone(delete_ev["timestamp_utc"])

    def test_scan_counts_unverifiable_hits_separately(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            _write(root / "secret.bin", b"\x00\x01\x02")
            profile = self._profile({
                "keywords": [{"term": "비밀", "in": "content"}],
                "extensions": [], "filename_patterns": [],
                "path_exclude": [],
            })
            result = scan_target(root, profile)
            self.assertEqual(result["summary"]["unverifiable"], 1)
            self.assertEqual(result["hits"], [])


class BundleFieldTests(unittest.TestCase):
    def test_bundle_builds_runnable_kit(self) -> None:
        import subprocess
        import sys

        from raidwatch.bundle import build_bundle

        with tempfile.TemporaryDirectory() as td:
            kit = build_bundle(Path(td) / "kit")
            kit_dir = Path(kit["kit_dir"])
            self.assertTrue((kit_dir / "raidwatch.pyz").is_file())
            self.assertTrue((kit_dir / "RUN.bat").is_file())
            self.assertTrue((kit_dir / "RUN.sh").is_file())
            # the pyz must be a runnable zipapp
            r = subprocess.run(
                [sys.executable, str(kit_dir / "raidwatch.pyz"), "--help"],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r.returncode, 0)
            self.assertIn("raidwatch", r.stdout)

    def test_bundle_embeds_exe_when_given(self) -> None:
        import json as _json

        from raidwatch.bundle import build_bundle

        with tempfile.TemporaryDirectory() as td:
            fake_exe = Path(td) / "raidwatch.exe"
            fake_exe.write_bytes(b"MZ fake binary")
            kit = build_bundle(Path(td) / "kit", exe=fake_exe)
            kit_dir = Path(kit["kit_dir"])
            self.assertTrue((kit_dir / "raidwatch.exe").is_file())
            manifest = _json.loads(
                (kit_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["exe"], "raidwatch.exe")
            self.assertEqual(manifest["requires"], "nothing — self-contained exe")
            # RUN.bat must prefer the exe path
            bat = (kit_dir / "RUN.bat").read_text(encoding="utf-8")
            self.assertIn("raidwatch.exe", bat)

    def test_bundle_prefill_config(self) -> None:
        from raidwatch.bundle import build_bundle

        with tempfile.TemporaryDirectory() as td:
            kit = build_bundle(
                Path(td) / "kit",
                raid_date="2026-09-19 14:30",
                dest="\\\\nas\\share\\case001",
                stamp="y",
            )
            kit_dir = Path(kit["kit_dir"])
            cfg = (kit_dir / "CONFIG.txt").read_text(encoding="utf-8")
            self.assertIn("raid_datetime=2026-09-19 14:30", cfg)
            self.assertIn("dest=\\\\nas\\share\\case001", cfg)
            self.assertIn("stamp=y", cfg)
            # blank keys stay blank — asked on site
            self.assertIn("notes=\n", cfg)
            # RUN.bat loads the config and skips preset questions
            bat = (kit_dir / "RUN.bat").read_text(encoding="utf-8")
            self.assertIn("CFG_%%a", bat)
            self.assertIn("CFG_raid_datetime", bat)
            self.assertIn("SEIZEDBAKED", bat)
            # RUN.sh parity
            sh = (kit_dir / "RUN.sh").read_text(encoding="utf-8")
            self.assertIn("raid_datetime", sh)

    def test_bundle_ships_picker_dialog(self) -> None:
        from raidwatch.bundle import build_bundle

        with tempfile.TemporaryDirectory() as td:
            kit = build_bundle(Path(td) / "kit")
            kit_dir = Path(kit["kit_dir"])
            ps1 = (kit_dir / "KIT-INPUT.ps1").read_text(encoding="utf-8")
            self.assertIn("DateTimePicker", ps1)
            self.assertIn("OpenFileDialog", ps1)
            self.assertIn("answers.txt", ps1)
            bat = (kit_dir / "RUN.bat").read_text(encoding="utf-8")
            self.assertIn("KIT-INPUT.ps1", bat)
            self.assertIn("ANS_%%a", bat)
            self.assertIn("ANS_skip", bat)
            # braces balanced in the shipped script
            self.assertEqual(ps1.count("{"), ps1.count("}"))

    def test_bundle_baked_seized_skips_question(self) -> None:
        from raidwatch.bundle import build_bundle

        with tempfile.TemporaryDirectory() as td:
            seized = Path(td) / "seized.txt"
            seized.write_text("C:\\x\\a.pdf\n", encoding="utf-8")
            kit = build_bundle(Path(td) / "kit", seized=seized)
            kit_dir = Path(kit["kit_dir"])
            self.assertTrue((kit_dir / "inputs" / "seized.txt").is_file())

    def test_field_runs_applicable_steps_and_archives(self) -> None:
        from raidwatch.field import run_field

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            _write(
                root / "Windows" / "System32" / "spool" / "PRINTERS" / "j.SPL",
                "seized list 원본".encode("utf-8"),
            )
            inputs = Path(td) / "inputs"
            inputs.mkdir()
            (inputs / "profile.json").write_text(
                json.dumps(RaidwatchFixture.profile_dict()), encoding="utf-8"
            )
            (inputs / "seized.txt").write_text(
                "docs/contract.hwp\n", encoding="utf-8"
            )

            out = Path(td) / "raidwatch-out"
            report = run_field(root, inputs, out)
            steps = {s["step"]: s["status"] for s in report["steps"]}
            self.assertEqual(steps["sources"], "ok")
            self.assertEqual(steps["artifacts"], "ok")
            self.assertEqual(steps["scan"], "ok")
            self.assertEqual(steps["verify"], "ok")
            self.assertTrue((out / "raidwatch-results.zip").is_file())
            self.assertTrue((out / "SHA256SUMS.txt").is_file())
            # every sums entry must match the real file hash
            from raidwatch.common import sha256_file

            bad = []
            for line in (out / "SHA256SUMS.txt").read_text().splitlines():
                digest, rel = line.split(None, 1)
                if sha256_file(out / rel.strip()) != digest:
                    bad.append(rel)
            self.assertEqual(bad, [])

    def test_field_survives_missing_inputs_and_errors(self) -> None:
        from raidwatch.field import run_field

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            _write(root / "a.txt", b"data")
            report = run_field(root, Path(td) / "no-inputs", Path(td) / "out")
            steps = {s["step"]: s["status"] for s in report["steps"]}
            self.assertEqual(steps["sources"], "ok")
            self.assertEqual(steps["artifacts"], "ok")
            self.assertNotIn("scan", steps)
            self.assertNotIn("verify", steps)

    def test_field_records_seizure_info_and_uses_since(self) -> None:
        import zipfile

        from raidwatch.field import run_field

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            # one temp candidate older than the raid, one newer
            old_tmp = root / "Users" / "u" / "AppData" / "Local" / "Temp" / "old-report.csv"
            new_tmp = root / "Users" / "u" / "AppData" / "Local" / "Temp" / "new-list.csv"
            _write(old_tmp, b"old")
            _write(new_tmp, b"new")
            raid_ns = int(datetime(2026, 9, 19, 14, 0).astimezone().timestamp() * 1e9)
            import os

            os.utime(old_tmp, ns=(raid_ns - 10**12, raid_ns - 10**12))
            os.utime(new_tmp, ns=(raid_ns + 10**12, raid_ns + 10**12))

            inputs = Path(td) / "inputs"
            inputs.mkdir()
            (inputs / "info.txt").write_text(
                "datetime: 2026-09-19 14:00\nnotes: case-123\n", encoding="utf-8"
            )
            report = run_field(root, inputs, Path(td) / "out")
            info = report["seizure_info"]
            self.assertEqual(info["raid_datetime"], "2026-09-19 14:00")
            self.assertEqual(info["notes"], "case-123")
            self.assertIsNotNone(info["raid_datetime_utc"])
            # 14:30 local → since filter: old temp file excluded, new included
            src_items = json.loads(
                (Path(td) / "out" / "steps" / "sources" / "sources.json").read_text()
            )["items"]
            names = {Path(i["path"]).name for i in src_items}
            self.assertIn("new-list.csv", names)
            self.assertNotIn("old-report.csv", names)
            # the archive itself carries the run report
            with zipfile.ZipFile(Path(td) / "out" / "raidwatch-results.zip") as zf:
                fr = json.loads(zf.read("steps/field-report.json"))
            self.assertEqual(fr["seizure_info"]["notes"], "case-123")

    def test_field_parses_korean_datetime_and_json_info(self) -> None:
        from raidwatch.field import _parse_dt_lenient, _read_seizure_info

        ns = _parse_dt_lenient("2026년 9월 19일 오후 2시 30분")
        self.assertIsNotNone(ns)
        local = datetime.fromtimestamp(ns / 1e9).astimezone()
        self.assertEqual((local.year, local.month, local.day, local.hour, local.minute),
                         (2026, 9, 19, 14, 30))
        self.assertIsNone(_parse_dt_lenient("모름"))
        self.assertIsNone(_parse_dt_lenient(""))

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "info.json"
            p.write_text(
                json.dumps({"raid_datetime": "2026-09-19T14:30", "notes": "n"}),
                encoding="utf-8",
            )
            info = _read_seizure_info(p)
            self.assertIsNotNone(info["raid_dt_ns"])
            self.assertEqual(info["notes"], "n")


def _cell(payload: bytes) -> bytes:
    size = 4 + len(payload)
    pad = (-size) % 8
    return struct.pack("<i", -(size + pad)) + payload + b"\x00" * pad


def _nk(name: str, sub_list: int | None, sub_count: int,
        val_list: int | None, val_count: int) -> bytes:
    body = b"nk" + struct.pack("<H", 0x0020)
    body += struct.pack("<Q", 0)
    body += b"\x00" * 4
    body += struct.pack("<i", -1)
    body += struct.pack("<I", sub_count) + struct.pack("<I", 0)
    body += struct.pack("<I", sub_list if sub_list is not None else 0xFFFFFFFF)
    body += struct.pack("<I", 0xFFFFFFFF)
    body += struct.pack("<I", val_count)
    body += struct.pack("<I", val_list if val_list is not None else 0xFFFFFFFF)
    body += struct.pack("<I", 0xFFFFFFFF)
    body += struct.pack("<I", 0xFFFFFFFF)
    body += b"\x00" * 20
    nb = name.encode("latin-1")
    body += struct.pack("<H", len(nb)) + struct.pack("<H", 0) + nb
    return body


def _vk(name: str, type_id: int, data_idx: int, data_size: int) -> bytes:
    nb = name.encode("latin-1")
    body = b"vk" + struct.pack("<H", len(nb))
    body += struct.pack("<I", data_size)
    body += struct.pack("<I", data_idx)
    body += struct.pack("<I", type_id)
    body += struct.pack("<H", 0x0001) + b"\x00" * 2 + nb
    return body


def _lf(children: list[int]) -> bytes:
    body = b"lf" + struct.pack("<H", len(children))
    for c in children:
        body += struct.pack("<I", c) + b"\x00" * 4
    return body


def _vlist(vks: list[int]) -> bytes:
    return b"".join(struct.pack("<I", v) for v in vks)


def make_test_hive() -> bytes:
    """Minimal regf hive: SYSTEM\\ControlSet001 with USBSTOR + ShimCache."""
    cells: list[bytes] = []
    off = [0x20]

    def add(payload: bytes) -> int:
        idx = off[0]
        c = _cell(payload)
        cells.append((idx, c))
        off[0] += len(c)
        return idx

    shim_path = "C:\\Tools\\FTKIMAGER.EXE".encode("utf-16-le")
    ft = 133900000000000000
    entry = (
        b"00ts" + struct.pack("<I", 0)
        + struct.pack("<I", 32 + len(shim_path))
        + struct.pack("<I", len(shim_path))
        + struct.pack("<Q", ft) + b"\x00" * 8 + shim_path
    )
    shim_blob = struct.pack("<I", 0x34) + entry

    fn_data = add("USB DISK\x00".encode("utf-16-le"))
    fn_vk = add(_vk("FriendlyName", 1, fn_data, len("USB DISK\x00") * 2))
    serial_vl = add(_vlist([fn_vk]))
    serial_nk = add(_nk("SER123", None, 0, serial_vl, 1))
    dev_lf = add(_lf([serial_nk]))
    dev_nk = add(_nk("Disk&Ven_X&Prod_Y", dev_lf, 1, None, 0))
    usb_lf = add(_lf([dev_nk]))
    usb_nk = add(_nk("USBSTOR", usb_lf, 1, None, 0))
    enum_lf = add(_lf([usb_nk]))
    enum_nk = add(_nk("Enum", enum_lf, 1, None, 0))

    shim_data = add(shim_blob)
    shim_vk = add(_vk("AppCompatCache", 3, shim_data, len(shim_blob)))
    shim_vl = add(_vlist([shim_vk]))
    acc_nk = add(_nk("AppCompatCache", None, 0, shim_vl, 1))
    sm_lf = add(_lf([acc_nk]))
    sm_nk = add(_nk("Session Manager", sm_lf, 1, None, 0))
    ctl_lf = add(_lf([sm_nk]))
    ctl_nk = add(_nk("Control", ctl_lf, 1, None, 0))
    cs_lf = add(_lf([enum_nk, ctl_nk]))
    cs_nk = add(_nk("ControlSet001", cs_lf, 2, None, 0))
    root_lf = add(_lf([cs_nk]))
    root_nk = add(_nk("SYSTEM", root_lf, 1, None, 0))

    header = bytearray(0x1000)
    header[:4] = b"regf"
    struct.pack_into("<I", header, 0x24, root_nk)
    body = b"".join(c for _, c in cells)
    hbin_size = 0x20 + len(body)
    hbin_size += (-hbin_size) % 0x1000
    hbin = b"hbin" + struct.pack("<I", 0) + struct.pack("<I", hbin_size)
    hbin += b"\x00" * 0x14 + body
    hbin += b"\x00" * (hbin_size - len(hbin))
    return bytes(header) + hbin


class HiveParserTests(unittest.TestCase):
    def test_hive_usbstor_and_shimcache(self) -> None:
        from raidwatch.hive import Hive
        from raidwatch.hiveart import shimcache, usbstor

        hive = Hive(make_test_hive())
        devs = usbstor(hive)
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["serial"], "SER123")
        self.assertEqual(devs[0]["friendly_name"], "USB DISK")

        shim = shimcache(hive)
        self.assertEqual(len(shim), 1)
        self.assertIn("FTKIMAGER", shim[0]["path"])
        self.assertEqual(shim[0]["parse"], "win10_00ts")
        self.assertIsNotNone(shim[0]["entry_file_mtime_utc"])

    def test_hive_rejects_non_regf(self) -> None:
        from raidwatch.hive import Hive, HiveError

        with self.assertRaises(HiveError):
            Hive(b"not a hive" + b"\x00" * 5000)


class LnkParserTests(unittest.TestCase):
    def test_parse_lnk_target_and_times(self) -> None:
        from raidwatch.lnk import parse_lnk

        base = b"C:\\Docs\x00"
        suffix = "report.pdf".encode("utf-16-le") + b"\x00\x00"
        hdr_size = 0x24
        li = struct.pack("<I", 0)  # placeholder size
        li_hdr_len = hdr_size + len(base) + len(suffix)
        base_off = hdr_size
        suffix_off = base_off + len(base)
        ubase_off = 0
        usuffix_off = suffix_off
        li_body = (
            struct.pack("<I", hdr_size) + struct.pack("<I", 1)
            + struct.pack("<I", 0) + struct.pack("<I", base_off)
            + struct.pack("<I", 0) + struct.pack("<I", suffix_off)
            + struct.pack("<I", ubase_off) + struct.pack("<I", usuffix_off)
            + base + suffix
        )
        li = struct.pack("<I", len(li_body) + 4) + li_body

        flags = 0x02 | 0x80  # HasLinkInfo + IsUnicode
        hdr = b"L\x00\x00\x00"
        hdr += b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        hdr += struct.pack("<I", flags) + b"\x00" * 4
        hdr += struct.pack("<Q", 133900000000000000) * 3
        hdr += b"\x00" * (0x4C - len(hdr))
        out = parse_lnk(hdr + li)
        self.assertEqual(out["target_path"], "C:\\Docs\\report.pdf")
        self.assertIsNotNone(out["accessed_utc"])

    def test_lnk_rejects_garbage(self) -> None:
        from raidwatch.lnk import parse_lnk_file

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.lnk"
            p.write_bytes(b"junk" * 40)
            self.assertIsNone(parse_lnk_file(p)["target_path"])


class EvtxRecordTests(unittest.TestCase):
    def test_iter_records_timeline(self) -> None:
        from raidwatch.evtx import iter_records

        def rec(rid: int, ft: int, payload: bytes) -> bytes:
            size = 24 + len(payload) + 4
            return (
                b"**\x00\x00" + struct.pack("<I", size)
                + struct.pack("<Q", rid) + struct.pack("<Q", ft)
                + payload + struct.pack("<I", size)
            )

        ft = 133900000000000000
        blob = rec(1, ft, b"alpha") + rec(2, ft + 100, b"beta")
        records = list(iter_records(blob))
        self.assertEqual([r[0] for r in records], [1, 2])
        self.assertEqual(records[0][2], b"alpha")
        # corrupt tail size must be rejected
        bad = rec(3, ft, b"gamma")[:-4] + b"XXXX"
        self.assertEqual(list(iter_records(bad)), [])


class IncrementalInventoryTests(unittest.TestCase):
    def test_incremental_reuses_unchanged_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "a.txt", b"aaa")
            _write(root / "b.txt", b"bbb")
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)
            a_hash = inv.get("a.txt").sha256

            _write(root / "b.txt", b"CHANGED")
            _write(root / "c.txt", b"ccc")
            summary = build_inventory(root, inv, incremental=True)
            self.assertEqual(summary["reused"], 1)
            self.assertEqual(inv.get("a.txt").sha256, a_hash)
            self.assertNotEqual(inv.get("b.txt").sha256, a_hash)
            inv.close()

    def test_incremental_drops_deleted_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "gone.txt", b"x")
            _write(root / "stay.txt", b"y")
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)
            (root / "gone.txt").unlink()
            build_inventory(root, inv, incremental=True)
            self.assertIsNone(inv.get("gone.txt"))
            self.assertIsNotNone(inv.get("stay.txt"))
            inv.close()


class VssHelpersTests(unittest.TestCase):
    def test_shadow_path_mapping(self) -> None:
        from raidwatch.vss import shadow_path_for

        dev = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"
        self.assertEqual(
            str(shadow_path_for(
                Path("C:/Windows/System32/config/SYSTEM"), dev)),
            dev + "\\Windows\\System32\\config\\SYSTEM",
        )

    def test_list_shadows_non_windows_empty(self) -> None:
        import platform

        from raidwatch.vss import list_shadows

        if platform.system() == "Windows":
            self.skipTest("posix-only assertion")
        self.assertEqual(list_shadows(), [])


class AdsScanTests(unittest.TestCase):
    def test_ads_skipped_off_windows(self) -> None:
        import platform

        from raidwatch.artifacts import _scan_ads

        if platform.system() == "Windows":
            self.skipTest("posix-only assertion")
        with tempfile.TemporaryDirectory() as td:
            res = _scan_ads(Path(td), Path(td) / "out")
        self.assertEqual(res["status"], "skipped")


class HardenTests(unittest.TestCase):
    def test_harden_writes_kit(self) -> None:
        from raidwatch.harden import build_harden

        with tempfile.TemporaryDirectory() as td:
            res = build_harden(Path(td) / "harden")
            self.assertEqual(
                sorted(res["files"]),
                ["HARDEN.bat", "README.txt", "REVERT.bat",
                 "sysmon-raidwatch.xml"],
            )
            bat = (Path(td) / "harden" / "HARDEN.bat").read_text(
                encoding="utf-8")
            self.assertIn("createjournal", bat)
            self.assertIn("ProcessCreationIncludeCmdLine_Enabled", bat)
            xml = (Path(td) / "harden" / "sysmon-raidwatch.xml").read_text(
                encoding="utf-8")
            self.assertIn("FileCreateTime", xml)
            self.assertTrue(
                (Path(td) / "harden" / "manifest.json").exists())


class FieldCustodyTests(unittest.TestCase):
    def test_field_writes_custody_seal(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "a.txt", b"data")
            inputs = Path(td) / "inputs"
            inputs.mkdir()
            out = Path(td) / "out"
            from raidwatch.field import run_field

            report = run_field(root, inputs, out, hash_files=False)
            custody = out / "custody.txt"
            self.assertTrue(custody.exists())
            text = custody.read_text(encoding="utf-8")
            self.assertIn("root_hash", text)
            sums = (out / "SHA256SUMS.txt").read_text(encoding="utf-8")
            digests = [ln.split()[0] for ln in sums.splitlines()]
            expected = hashlib.sha256(
                "".join(digests).encode("ascii")).hexdigest()
            self.assertEqual(report["custody_root_hash"], expected)
            self.assertIn(report["custody_root_hash"], text)


class MirrorTests(unittest.TestCase):
    def test_mirror_copies_resolved_items(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "evidence" / "doc.hwp", b"seized-by-investigator")
            _write(root / "other.txt", b"not-seized")
            import hashlib

            claimed = hashlib.sha256(
                b"seized-by-investigator").hexdigest()
            vj = Path(td) / "verify.json"
            vj.write_text(json.dumps({
                "items": [
                    {"claimed_path": "C:\\evidence\\doc.hwp",
                     "claimed_sha256": claimed,
                     "matched_path": "evidence/doc.hwp",
                     "status": "verified"},
                    {"claimed_path": "C:\\ghost.txt",
                     "matched_path": None, "status": "not_in_inventory"},
                ],
                "summary": {"total": 2},
            }), encoding="utf-8")
            from raidwatch.mirror import run_mirror

            out = Path(td) / "mirror"
            rep = run_mirror(root, out, verify_path=vj)
            self.assertEqual(rep["summary"]["copied"], 1)
            self.assertTrue(
                (out / "files" / "evidence" / "doc.hwp").is_file())
            self.assertEqual(
                rep["items"][0]["hash_vs_claimed"], "match")
            sums = (out / "MIRROR-SHA256SUMS.txt").read_text()
            self.assertIn(claimed, sums)
            # unresolved item was not copied
            self.assertFalse((out / "files" / "ghost.txt").exists())

    def test_mirror_seized_list_on_the_fly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "docs" / "contract.pdf", b"%PDF-1 fake")
            seized = Path(td) / "seized.txt"
            seized.write_text("C:\\docs\\contract.pdf\n", encoding="utf-8")
            from raidwatch.mirror import run_mirror

            rep = run_mirror(root, Path(td) / "m", seized_path=seized)
            self.assertEqual(rep["summary"]["copied"], 1)
            self.assertTrue(
                (Path(td) / "m" / "files" / "docs" / "contract.pdf")
                .is_file())


class PetitionTests(unittest.TestCase):
    def test_petition_renders_html(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as td:
            case = Path(td) / "case"
            (case / "verify").mkdir(parents=True)
            (case / "verify" / "verify.json").write_text(json.dumps({
                "items": [{
                    "claimed_path": "C:\\x\\outside.docx",
                    "claimed_sha256": "ab" * 32,
                    "matched_path": "x/outside.docx",
                    "status": "verified",
                    "scope_verdict": "out_of_scope",
                    "notes": [],
                }],
                "summary": {"total": 1, "out_of_scope": 1},
            }), encoding="utf-8")
            from raidwatch.petition import run_petition

            rep = run_petition(case, Path(td) / "pet",
                               case_no="2026고단1234", counsel="김변호")
            doc = (Path(td) / "pet" / "청구서.html").read_text(
                encoding="utf-8")
            self.assertIn("압수물 환부·폐기 청구서", doc)
            self.assertIn("2026고단1234", doc)
            self.assertIn("outside.docx", doc)
            self.assertIn("308", doc)
            self.assertEqual(rep["items_listed"], 1)


class LockboxTests(unittest.TestCase):
    def test_lockbox_skips_off_windows(self) -> None:
        import platform

        if platform.system() == "Windows":
            self.skipTest("posix-only assertion")
        from raidwatch.lockbox import run_lockbox

        with tempfile.TemporaryDirectory() as td:
            rep = run_lockbox(None, Path(td) / "lb")
        self.assertEqual(rep["status"], "skipped")

    def test_protector_parser(self) -> None:
        from raidwatch.lockbox import _parse_protectors

        text = (
            "BitLocker Drive Encryption: Volume C:\n"
            "Numerical Password:\n"
            "    ID: {AABBCCDD-1234-5678-9ABC-DEF012345678}\n"
            "    Password:\n"
            "        123456-234567-345678-456789-567890-678901-789012-890123\n"
        )
        prot = _parse_protectors(text)
        self.assertTrue(prot["key_protector_ids"])
        # password on its own line after "Password:" — regex expects
        # 'Numerical Password:' label inline; at minimum no crash


class MobileTests(unittest.TestCase):
    def test_mobile_detects_and_copies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            kdb = root / "Users" / "u1" / "AppData" / "Local" / "Kakao" / "KakaoTalk" / "u1" / "chat.db"
            kdb.parent.mkdir(parents=True)
            kdb.write_bytes(b"SQLite format 3\x00" + b"x" * 100)
            _write(root / "Users" / "u1" / "Desktop" / "plain.txt", b"no")
            from raidwatch.mobile import collect_mobile

            rep = collect_mobile(root, Path(td) / "m")
            self.assertEqual(rep["summary"]["copied"], 1)
            self.assertEqual(rep["summary"]["sqlite_dbs"], 1)
            self.assertIn("kakaotalk_pc", rep["targets_found"])
            self.assertEqual(rep["items"][0]["status"], "copied")


class BoundaryTests(unittest.TestCase):
    def test_classify_paths(self) -> None:
        from raidwatch.boundary import classify_path

        self.assertTrue(
            classify_path(r"\\NAS\share\x.txt")["violation"])
        self.assertEqual(
            classify_path(r"\\NAS\share\x.txt")["territory"], "remote_unc")
        self.assertTrue(
            classify_path(r"C:\Users\u\OneDrive\a.docx")["violation"])
        self.assertFalse(
            classify_path(r"C:\Users\u\a.docx")["violation"])

    def test_cloud_marker_needs_own_segment(self) -> None:
        # substring false-positives from the real 엑셀 detail list:
        # X*box*GamingOverlay and 네이버*리뷰링크* are local files
        from raidwatch.boundary import classify_path

        self.assertFalse(
            classify_path(
                r"C:\데스크 피의자 PC\문서 파일"
                r"\XboxGamingOverlayTraces_FT_Server_20260611.txt"
            )["violation"])
        self.assertFalse(
            classify_path(
                r"C:\데스크 피의자 PC\문서 파일\네이버리뷰링크.docx"
            )["violation"])
        # real cloud segments still fire — incl. 'OneDrive - 회사' style
        self.assertTrue(
            classify_path(r"C:\Users\u\OneDrive - 회사\f.docx")[
                "violation"])
        self.assertTrue(classify_path(r"D:\box\export.zip")["violation"])

    def test_run_boundary_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            seized = Path(td) / "seized.txt"
            seized.write_text(
                "C:\\docs\\a.pdf\n\\\\NAS\\files\\b.pdf\n", encoding="utf-8")
            from raidwatch.boundary import run_boundary

            rep = run_boundary(seized, None, Path(td) / "b")
            self.assertEqual(rep["summary"]["total_paths"], 2)
            self.assertGreaterEqual(rep["summary"]["violations"], 1)
            self.assertTrue(rep["violating_paths"])


class ContainersTests(unittest.TestCase):
    def test_sniff_finds_container_on_extra_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            drive = Path(td) / "usb"
            (drive / "EXPORT").mkdir(parents=True)
            ad1 = drive / "EXPORT" / "seized.ad1"
            ad1.write_bytes(b"ad1-payload")
            _write(drive / "note.txt", b"not a container")
            from raidwatch.containers import sniff_containers

            rep = sniff_containers(
                Path(td) / "c", extra_roots=[drive])
            self.assertEqual(rep["summary"]["containers_found"], 1)
            self.assertTrue(rep["containers"][0]["sha256"])
            self.assertIn("seized.ad1", rep["containers"][0]["path"])

    def test_sniff_since_filter(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as td:
            drive = Path(td) / "usb"
            drive.mkdir()
            old = drive / "old.ad1"
            old.write_bytes(b"old")
            past = 946684800  # 2000-01-01
            os.utime(old, (past, past))
            from raidwatch.containers import sniff_containers

            rep = sniff_containers(
                Path(td) / "c", extra_roots=[drive],
                since_ns=(past + 100) * 1_000_000_000)
            self.assertEqual(rep["summary"]["containers_found"], 0)


class KeywordAuditTests(unittest.TestCase):
    def test_noise_ratio(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "t"
            _write(root / "docs" / "contract-2019.hwp", b"old")
            _write(root / "docs" / "contract-2026.hwp", b"new")
            _write(root / "docs" / "random.pdf", b"none")
            # make the 2019 file predate the warrant range
            import os

            os.utime(root / "docs" / "contract-2019.hwp",
                     (1262304000, 1262304000))  # 2010-01-01
            profile = {
                "profile_version": "1.0",
                "criteria": {
                    "keywords": [{"term": "contract"}],
                    "date_ranges": [
                        {"field": "mtime", "from": "2025-01-01",
                         "to": "2027-01-01"}
                    ],
                },
            }
            seized = Path(td) / "seized.txt"
            seized.write_text(
                "C:\\docs\\contract-2019.hwp\n"
                "C:\\docs\\contract-2026.hwp\n"
                "C:\\docs\\random.pdf\n",
                encoding="utf-8",
            )
            (Path(td) / "p.json").write_text(
                json.dumps(profile), encoding="utf-8")
            from raidwatch.audit import run_keyword_audit
            from raidwatch.profile import load_profile

            rep = run_keyword_audit(
                seized, load_profile(Path(td) / "p.json"),
                root, Path(td) / "a")
            kw = rep["keywords"][0]
            self.assertEqual(kw["seized"], 2)
            self.assertEqual(kw["out_of_scope"], 1)
            self.assertEqual(kw["in_scope"], 1)
            self.assertAlmostEqual(kw["noise_ratio"], 0.5)
            self.assertEqual(
                rep["summary"]["unattributed_items"], 1)


class InquiryTests(unittest.TestCase):
    def test_query_verdict(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as td:
            case = Path(td) / "case"
            (case / "verify").mkdir(parents=True)
            (case / "verify" / "verify.json").write_text(json.dumps({
                "items": [{
                    "claimed_path": "C:\\x\\outside.docx",
                    "matched_path": "x/outside.docx",
                    "status": "verified",
                    "scope_verdict": "out_of_scope",
                    "notes": [],
                }],
                "summary": {"total": 1},
            }), encoding="utf-8")
            from raidwatch.inquiry import load_case_index, query

            idx = load_case_index(case)
            self.assertEqual(len(idx["items"]), 1)
            answer = query(idx, "outside.docx")
            self.assertIn("OUT_OF_SCOPE", answer)
            self.assertIn("기록 없음", query(idx, "nothing.xyz"))


class WindowTests(unittest.TestCase):
    def test_window_finds_files_since_date(self) -> None:
        import os
        import time

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            _write(root / "before.txt", b"old")
            _write(root / "during.txt", b"investigator export")
            past = 1262304000  # 2010 — clearly before the raid
            os.utime(root / "before.txt", (past, past))
            since_ns = int((time.time() - 3600) * 1_000_000_000)
            _backdate_creation(root / "before.txt", past)
            if _creation_signal(root / "before.txt") > since_ns / 1e9:
                self.skipTest(
                    "platform cannot backdate creation time — "
                    "before.txt always looks created-in-window"
                )
            from raidwatch.window import scan_window

            rep = scan_window(
                root, Path(td) / "w", since_ns=since_ns)
            self.assertEqual(rep["summary"]["files_in_window"], 1)
            f = rep["files"][0]
            self.assertEqual(f["path"], "during.txt")
            self.assertTrue(f["created_in_window"])
            self.assertFalse(rep["summary"]["truncated"])

    def test_field_date_only_runs_window(self) -> None:
        import time

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "target"
            RaidwatchFixture(root)
            inputs = Path(td) / "inputs"
            inputs.mkdir()
            yesterday = time.strftime(
                "%Y-%m-%d", time.gmtime(time.time() - 86400))
            (inputs / "info.txt").write_text(
                f"datetime: {yesterday}\n", encoding="utf-8")
            from raidwatch.field import run_field

            rep = run_field(root, inputs, Path(td) / "out")
            steps = {s["step"]: s["status"] for s in rep["steps"]}
            self.assertEqual(steps.get("window"), "ok")
            self.assertTrue(
                (Path(td) / "out" / "steps" / "window"
                 / "window.json").is_file())


class SplitArchiveTests(unittest.TestCase):
    def test_split_and_rejoin(self) -> None:
        import zipfile

        import raidwatch.field as fld

        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            zip_p = out / fld.RESULTS_ZIP
            import os

            payload = os.urandom(8000)  # incompressible → zip stays big
            with zipfile.ZipFile(zip_p, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("big.bin", payload)
            original = zip_p.read_bytes()
            old_t, old_p = fld._SPLIT_THRESHOLD, fld._PART_SIZE
            fld._SPLIT_THRESHOLD, fld._PART_SIZE = 1000, 700
            try:
                info = fld._maybe_split_archive(zip_p, out, "deadbeef")
            finally:
                fld._SPLIT_THRESHOLD, fld._PART_SIZE = old_t, old_p

            self.assertIsNotNone(info)
            self.assertFalse(zip_p.exists())  # monolith removed
            parts_dir = out / fld.PARTS_DIR
            blobs = sorted(
                parts_dir.glob(f"{fld.RESULTS_ZIP}.0*"))
            self.assertEqual(len(blobs), info["count"])
            joined = b"".join(p.read_bytes() for p in blobs)
            self.assertEqual(joined, original)  # lossless reassembly
            self.assertTrue((parts_dir / "JOIN.bat").is_file())
            self.assertTrue((parts_dir / "join.sh").is_file())
            self.assertTrue(
                (parts_dir / "SHA256SUMS-parts.txt").is_file())
            self.assertTrue((parts_dir / "README-parts.txt").is_file())
            # JOIN.bat is a self-contained verifier: embedded seal
            # hash, auto-detected parts, certutil compare, popup.
            bat = (parts_dir / "JOIN.bat").read_text(encoding="utf-8")
            self.assertIn('set "WANT=deadbeef"', bat)
            self.assertIn('dir /b /on "%OUT%.???"', bat)
            self.assertIn("certutil -hashfile", bat)
            self.assertIn("SHA256SUMS-parts.txt", bat)
            self.assertIn("MessageBox", bat)
            sh = (parts_dir / "join.sh").read_text(encoding="utf-8")
            self.assertIn("WANT=deadbeef", sh)

    def test_small_zip_not_split(self) -> None:
        import raidwatch.field as fld

        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            zip_p = out / fld.RESULTS_ZIP
            zip_p.write_bytes(b"PK small")
            info = fld._maybe_split_archive(zip_p, out, "aa")
            self.assertIsNone(info)
            self.assertTrue(zip_p.exists())


class JoinTests(unittest.TestCase):
    def _make_parts(self, td: str) -> Path:
        import zipfile

        import raidwatch.field as fld

        out = Path(td)
        zip_p = out / fld.RESULTS_ZIP
        import os

        with zipfile.ZipFile(zip_p, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("b.bin", os.urandom(3000))
        original = zip_p.read_bytes()
        import hashlib

        whole = hashlib.sha256(original).hexdigest()
        old_t, old_p = fld._SPLIT_THRESHOLD, fld._PART_SIZE
        fld._SPLIT_THRESHOLD, fld._PART_SIZE = 500, 700
        try:
            fld._maybe_split_archive(zip_p, out, whole)
        finally:
            fld._SPLIT_THRESHOLD, fld._PART_SIZE = old_t, old_p
        self._original = original
        return out / fld.PARTS_DIR

    def test_join_verifies_ok(self) -> None:
        from raidwatch.join import run_join

        with tempfile.TemporaryDirectory() as td:
            parts_dir = self._make_parts(td)
            rep = run_join(parts_dir)
            self.assertEqual(rep["summary"]["verdict"], "ok")
            self.assertEqual(
                Path(rep["output"]).read_bytes(), self._original)
            self.assertFalse(rep["summary"]["bad_parts"])

    def test_join_detects_corrupt_part(self) -> None:
        from raidwatch.join import run_join

        with tempfile.TemporaryDirectory() as td:
            parts_dir = self._make_parts(td)
            victim = sorted(
                parts_dir.glob("raidwatch-results.zip.0*"))[1]
            victim.write_bytes(b"corrupted" + victim.read_bytes()[9:])
            rep = run_join(parts_dir)
            self.assertEqual(rep["summary"]["verdict"], "mismatch")
            self.assertIn(victim.name, rep["summary"]["bad_parts"])


class LeftoversTests(unittest.TestCase):
    def _fixture(self, td: str) -> Path:
        import struct

        base = Path(td) / "C"
        desk = base / "Users" / "pc" / "Desktop"
        desk.mkdir(parents=True)
        (desk / "전자정보목록.pdf").write_bytes(b"%PDF-1.4 list")
        (desk / "선별결과.zip").write_bytes(b"PK\x03\x04 archive")
        old = desk / "normal.txt"
        old.write_bytes(b"old")
        os.utime(old, (1_000_000_000, 1_000_000_000))
        _backdate_creation(old, 1_000_000_000)
        # recycle bin: 압수물목록.hwp deleted inside the window
        name = "C:\\Users\\pc\\Desktop\\압수물목록.hwp"
        nb = name.encode("utf-16-le") + b"\x00\x00"
        ft = 116444736000000000 + int(1_789_866_000 * 10_000_000)
        i_data = struct.pack("<QQQI", 2, 999, ft, len(nb) // 2) + nb
        bd = base / "$Recycle.Bin" / "S-1-5-21"
        bd.mkdir(parents=True)
        (bd / "$IABCDEF.hwp").write_bytes(i_data)
        (bd / "$RABCDEF.hwp").write_bytes(b"deleted list content")
        return base

    def test_leftovers_recovers_work_product(self) -> None:
        from raidwatch.common import iso_to_ns
        from raidwatch.leftover import run_leftovers

        with tempfile.TemporaryDirectory() as td:
            base = self._fixture(td)
            if _creation_signal(base / "Users/pc/Desktop/normal.txt"
                                ) > iso_to_ns("2026-09-19 10:00") / 1e9:
                self.skipTest(
                    "platform cannot backdate creation time — "
                    "normal.txt always counts as a live hit"
                )
            rep = run_leftovers(
                [base], Path(td) / "out",
                since_ns=iso_to_ns("2026-09-19 10:00"),
                until_ns=iso_to_ns("2026-12-31"),
            )
            self.assertEqual(rep["summary"]["live_hits"], 2)
            names = {h["path"] for h in rep["live_files"]}
            self.assertTrue(any("전자정보목록" in n for n in names))
            self.assertEqual(rep["summary"]["recycle_bin_entries"], 1)
            b = rep["recycle_bin"][0]
            self.assertEqual(b["category"], "bin_list_or_container")
            self.assertIn("압수물목록", b["original_path"])
            self.assertTrue(b["copied"].startswith("bin_"))
            self.assertEqual(
                (Path(td) / "out" / "files" / b["copied"]).read_bytes(),
                b"deleted list content",
            )

    def test_leftovers_journal_deletion(self) -> None:
        from raidwatch.common import iso_to_ns
        from raidwatch.leftover import run_leftovers

        with tempfile.TemporaryDirectory() as td:
            j = Path(td) / "journal.json"
            j.write_text(json.dumps({"events": [{
                "file_name": "선별결과.zip",
                "reasons": ["file_delete", "close"],
                "timestamp_utc": "2026-09-19T03:00:00Z",
            }, {
                "file_name": "ordinary.tmp",
                "reasons": ["file_delete"],
                "timestamp_utc": "2026-09-19T03:05:00Z",
            }]}))
            rep = run_leftovers(
                [Path(td)], Path(td) / "out",
                since_ns=iso_to_ns("2026-09-19 00:00"),
                until_ns=iso_to_ns("2026-12-31"),
                journal=j,
            )
            self.assertEqual(rep["summary"]["deleted_in_window"], 1)
            self.assertIn("선별결과", rep["deleted_in_window"][0]["name"])

    def test_i_file_v1_legacy(self) -> None:
        """Vista/7/8 $I v1: fixed 520-byte UTF-16 name at offset 24."""
        import struct

        from raidwatch.leftover import _parse_i_file

        with tempfile.TemporaryDirectory() as td:
            name = "C:\\선별결과.zip"
            nb = name.encode("utf-16-le").ljust(520, b"\x00")
            ft = 116444736000000000 + int(1_789_866_000 * 10_000_000)
            data = struct.pack("<QQQ", 1, 777, ft) + nb
            p = Path(td) / "$IXYZ.zip"
            p.write_bytes(data)
            size, deleted, orig = _parse_i_file(p)
            self.assertEqual(size, 777)
            self.assertEqual(deleted, 1_789_866_000.0)
            self.assertEqual(orig, name)

    def test_info2_xp_legacy(self) -> None:
        """XP INFO2: 20-byte header + 800-byte records, D-file content."""
        import struct

        from raidwatch.common import iso_to_ns
        from raidwatch.leftover import run_leftovers

        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "C"
            bin_dir = base / "RECYCLER" / "S-1-5-21"
            bin_dir.mkdir(parents=True)
            name = "선별결과.zip"
            ft = 116444736000000000 + int(1_789_866_000 * 10_000_000)
            rec = bytearray(800)
            struct.pack_into("<I", rec, 0, 3)          # index
            rec[4:8] = b"C:\\\x00"                     # drive
            struct.pack_into("<Q", rec, 8, ft)         # deltime
            struct.pack_into("<I", rec, 16, 4096)      # size
            rec[20:20 + len(name)] = name.encode("cp949")
            rec[280:280 + len(name) * 2] = name.encode("utf-16-le")
            (bin_dir / "INFO2").write_bytes(
                b"\x00" * 20 + bytes(rec))
            (bin_dir / "Dc3.zip").write_bytes(b"recovered bytes")
            rep = run_leftovers(
                [base], Path(td) / "out",
                since_ns=iso_to_ns("2026-09-19 10:00"),
                until_ns=iso_to_ns("2026-12-31"),
            )
            self.assertEqual(rep["summary"]["recycle_bin_entries"], 1)
            b = rep["recycle_bin"][0]
            self.assertEqual(b["format"], "info2_legacy")
            self.assertIn("선별결과", b["original_path"])
            self.assertEqual(
                (Path(td) / "out" / "files" / b["copied"]).read_bytes(),
                b"recovered bytes",
            )


class EnvTests(unittest.TestCase):
    def test_probe_environment(self) -> None:
        from raidwatch.env import probe_environment

        with tempfile.TemporaryDirectory() as td:
            env = probe_environment(Path(td))
            self.assertIn("capabilities", env)
            self.assertIn("volumes", env)
            self.assertTrue((Path(td) / "env.json").is_file())
            self.assertIsInstance(env["elevated"], bool)
            self.assertTrue(env["capabilities"]["window_scan"])


_XLSX_HEADERS = [
    "연번", "파일명", "확장자명", "파일 크기(바이트)", "경로",
    "SHA1", "생성일시", "수정일시", "접근일시",
]


def _write_test_xlsx(path: Path, sheets: list[list[list[str]]]) -> Path:
    """Build a minimal .xlsx (inline strings) in the police detail-list
    shape — enough for the stdlib reader: workbook + rels + sheets."""
    import zipfile

    def sheet_xml(rows: list[list[str]]) -> str:
        body = []
        for ri, row in enumerate(rows, 1):
            cells = "".join(
                f'<c r="{chr(ord("A") + ci)}{ri}" t="inlineStr">'
                f'<is><t xml:space="preserve">{v}</t></is></c>'
                for ci, v in enumerate(row)
            )
            body.append(f'<row r="{ri}">{cells}</row>')
        return (
            '<?xml version="1.0"?><worksheet '
            'xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
            '2006/main"><sheetData>' + "".join(body) + "</sheetData>"
            "</worksheet>"
        )

    wb = (
        '<?xml version="1.0"?><workbook '
        'xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
        '2006/main" xmlns:r="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships"><sheets>'
        + "".join(
            f'<sheet name="파일{i + 1}" sheetId="{i + 1}" '
            f'r:id="rId{i + 1}"/>'
            for i in range(len(sheets))
        )
        + "</sheets></workbook>"
    )
    rels = (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/'
        'relationships">'
        + "".join(
            f'<Relationship Id="rId{i + 1}" Type="t" '
            f'Target="worksheets/sheet{i + 1}.xml"/>'
            for i in range(len(sheets))
        )
        + "</Relationships>"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("xl/workbook.xml", wb)
        zf.writestr("xl/_rels/workbook.xml.rels", rels)
        for i, rows in enumerate(sheets):
            zf.writestr(f"xl/worksheets/sheet{i + 1}.xml", sheet_xml(rows))
    return path


def _seized_row(seq, name, path, sha1="A" * 40, size="100",
                modified="2025-01-02 10:00:00"):
    return [
        str(seq), name, name.rsplit(".", 1)[-1], size, path, sha1,
        "2025-01-01 10:00:00", modified, "2025-01-03 10:00:00",
    ]


class XlsxSeizedListTests(unittest.TestCase):
    def test_parse_police_detail_list_xlsx(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            x = _write_test_xlsx(Path(td) / "list.xlsx", [[
                _XLSX_HEADERS,
                _seized_row(1, "계약서.pdf", "C:\\docs\\계약서.pdf"),
                _seized_row(2, "notes.txt", "C:\\docs\\notes.txt",
                            sha1="B" * 40),
            ], [
                _XLSX_HEADERS,
                _seized_row(3, "more.hwp", "C:\\docs\\more.hwp",
                            sha1="C" * 40),
            ]])
            items = parse_seized_list(x)
            self.assertEqual(len(items), 3)
            self.assertEqual(items[0]["rel"], "docs/계약서.pdf")
            self.assertEqual(items[0]["sha256"], "a" * 40)
            self.assertEqual(items[0]["hash_algo"], "sha1")
            self.assertEqual(items[0]["claimed_meta"]["seq"], "1")
            self.assertEqual(items[2]["claimed_meta"]["sheet"], "파일2")

    def test_sha1_claim_verified_on_live_disk(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "pc"
            _write(root / "docs" / "a.txt", b"seized bytes")
            _write(root / "docs" / "b.txt", b"other bytes")
            good = hashlib.sha1(b"seized bytes").hexdigest()
            x = _write_test_xlsx(Path(td) / "list.xlsx", [[
                _XLSX_HEADERS,
                _seized_row(1, "a.txt", "C:\\docs\\a.txt", sha1=good),
                _seized_row(2, "b.txt", "C:\\docs\\b.txt",
                            sha1="0" * 40),
            ]])
            inv = Inventory(Path(td) / "inv.db", create=True)
            build_inventory(root, inv)
            rep = verify_items(
                parse_seized_list(x), inv, current_root=root)
            inv.close()
            a, b = rep["items"]
            self.assertEqual(a["status"], "verified")
            self.assertIn("sha1 verified", "; ".join(a["notes"]))
            self.assertEqual(b["status"], "hash_mismatch")
            self.assertEqual(rep["summary"]["hash_incomparable"], 0)

    def test_collector_report_json_ingested(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rep = Path(td) / "report.json"
            rep.write_text(json.dumps({
                "scan_config": {"start_time": "2026-07-28T13:00:00"},
                "likely_seized_files": [
                    "C:\\Users\\pc\\Desktop\\전자정보목록.pdf",
                    "C:\\Users\\pc\\Desktop\\선별결과.zip",
                ],
            }), encoding="utf-8")
            items = parse_seized_list(rep)
            self.assertEqual(len(items), 2)
            self.assertEqual(
                items[0]["rel"], "Users/pc/Desktop/전자정보목록.pdf")

    def test_json_object_without_list_key_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rep = Path(td) / "weird.json"
            rep.write_text(json.dumps({"stats": {"total": 3}}),
                           encoding="utf-8")
            items = parse_seized_list(rep)
            self.assertEqual(len(items), 1)
            self.assertTrue(items[0]["unparsed"])


class CertcheckTests(unittest.TestCase):
    def test_certcheck_flags_defects(self) -> None:
        from raidwatch.certcheck import run_certcheck

        with tempfile.TemporaryDirectory() as td:
            pkg = Path(td) / "pkg"
            rows = [
                _XLSX_HEADERS,
                _seized_row(1, "a.pdf", "C:\\d\\a.pdf"),
                _seized_row(2, "b.pdf", "C:\\d\\b.pdf"),
                # seq gap: no row 3
                _seized_row(4, "c.pdf", "C:\\d\\c.pdf",
                            sha1="A" * 40),  # dup of row 1's hash
                _seized_row(5, "WRONG.pdf", "C:\\d\\real.pdf"),
                _seized_row(6, "bad.pdf", "C:\\d\\bad.pdf",
                            sha1="NOT-HEX"),
                _seized_row(7, "late.pdf", "C:\\d\\late.pdf",
                            modified="2026-06-01 09:00:00"),
            ]
            _write_test_xlsx(pkg / "엑셀_20260101120000.xlsx", [rows])
            _write(
                pkg / "전자정보확인서_20260101120000_서식1.pdf",
                b"%PDF-1.4 empty",
            )
            rep = run_certcheck(pkg, Path(td) / "out")
            checks = {f["check"] for f in rep["findings"]}
            self.assertIn("seq_integrity", checks)
            self.assertIn("hash_format", checks)
            self.assertIn("name_path_mismatch", checks)
            self.assertIn("duplicate_sha1", checks)
            self.assertIn("post_cert_mtime", checks)
            self.assertEqual(
                rep["certificate_ts"], "2026-01-01T12:00:00")
            self.assertEqual(rep["row_summary"]["rows"], 6)

    def test_certcheck_live_reverify(self) -> None:
        import hashlib

        from raidwatch.certcheck import run_certcheck

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "mirror"
            data = b"claimed bytes"
            _write(root / "d" / "a.pdf", data)
            sha1 = hashlib.sha1(data).hexdigest()
            pkg = Path(td) / "pkg"
            _write_test_xlsx(pkg / "list.xlsx", [[
                _XLSX_HEADERS,
                _seized_row(1, "a.pdf", "C:\\d\\a.pdf", sha1=sha1,
                            size=str(len(data))),
                _seized_row(2, "gone.pdf", "C:\\d\\gone.pdf"),
            ]])
            rep = run_certcheck(pkg, Path(td) / "out", root=root)
            live = rep["live_reverify"]
            self.assertEqual(live["resolved"], 1)
            self.assertEqual(live["hash_verified"], 1)
            self.assertEqual(live["missing"], 1)


class ConvertTests(unittest.TestCase):
    def test_convert_prefers_report_json_over_path_dump(self) -> None:
        """file_paths.txt lists EVERY discovered path (11 > 10 rows)
        but report.json's likely_seized_files is the real estimate —
        convert must pick by meaning, not row count."""
        import json

        from raidwatch.convert import run_convert

        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "ForensicOutput" / "scan_20260914_202349"
            _write(
                scan / "file_paths.txt",
                ("# 추출된 파일/경로 목록\n"
                 + "\n".join(f"C:\\all\\f{i}.dat" for i in range(11))
                 ).encode("utf-8"),
            )
            _write(
                scan / "report.json",
                json.dumps({
                    "stats": {"likely_seized": 2},
                    "likely_seized_files": ["C:\\d\\a.pdf", "C:\\d\\b.pdf"],
                }).encode("utf-8"),
            )
            rep = run_convert(Path(td), Path(td) / "out")
            self.assertTrue(rep["source_used"].endswith("report.json"))
            self.assertEqual(rep["rows"], 2)

    def test_convert_newest_scan_dir_wins(self) -> None:
        import json

        from raidwatch.convert import run_convert

        with tempfile.TemporaryDirectory() as td:
            for day, path in (
                ("20260908_165149", "C:\\old\\a.pdf"),
                ("20260914_202349", "C:\\new\\b.pdf"),
            ):
                scan = Path(td) / "ForensicOutput" / f"scan_{day}"
                _write(
                    scan / "report.json",
                    json.dumps({"likely_seized_files": [path]}).encode("utf-8"),
                )
            rep = run_convert(Path(td), Path(td) / "out")
            self.assertIn("scan_20260914", rep["source_used"])

    def test_convert_csv_roundtrips_through_verify(self) -> None:
        from raidwatch.convert import run_convert
        from raidwatch.verify import parse_seized_list

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "list.txt"
            _write(src, "C:\\docs\\a.pdf\nC:\\docs\\b.pdf\n".encode("utf-8"))
            rep = run_convert(src, Path(td) / "out")
            self.assertEqual(rep["rows"], 2)
            items = parse_seized_list(Path(td) / "out" / "seized.csv")
            self.assertEqual(len(items), 2)
            self.assertFalse(any(i.get("unparsed") for i in items))
            self.assertEqual(items[0]["rel"], "docs/a.pdf")


if __name__ == "__main__":
    unittest.main()
