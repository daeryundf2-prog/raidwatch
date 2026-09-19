from __future__ import annotations

import json
import os
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
