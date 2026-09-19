"""raidwatch CLI — baseline, scan, diff, verify, watch subcommands."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .artifacts import collect_artifacts
from .audit import run_keyword_audit
from .boundary import run_boundary
from .bundle import build_bundle
from .containers import sniff_containers
from .common import write_json, write_manifest
from .db import Inventory
from .diff import run_diff
from .field import run_field
from .harden import build_harden
from .inventory import build_inventory
from .journal import replay_journal
from .lockbox import run_lockbox
from .mft import carve_mft
from .mirror import run_mirror
from .mobile import collect_mobile
from .package import build_package
from .petition import run_petition
from .profile import ProfileError, load_profile
from .remote import collect_remote
from .scan import run_scan
from .sources import collect_sources
from .verify import run_verify
from .watcher import run_watch


def _print(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def _build_temp_inventory(root: Path, hash_files: bool = True) -> tuple[Inventory, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory(prefix="raidwatch-")
    inv = Inventory(Path(tmp.name) / "inventory.db", create=True)
    build_inventory(root, inv, hash_files=hash_files)
    return inv, tmp


def cmd_baseline(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    inv = Inventory(out_dir / "inventory.db", create=True)
    summary = build_inventory(
        root,
        inv,
        hash_files=not args.no_hash,
        max_hash_bytes=args.max_hash_mb * 1024 * 1024 if args.max_hash_mb else None,
        follow_symlinks=args.follow_symlinks,
        incremental=args.incremental,
        progress=lambda n, p: print(f"  {n} entries... {p}", file=sys.stderr)
        if args.verbose
        else None,
    )
    write_manifest(
        out_dir,
        "baseline",
        {
            "root": str(root),
            "inventory_db": str(out_dir / "inventory.db"),
            "summary": summary,
        },
    )
    inv.close()
    _print({"inventory_db": str(out_dir / "inventory.db"), **summary})
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(f"profile error: {exc}", file=sys.stderr)
        return 2
    result = run_scan(
        Path(args.root).expanduser(),
        profile,
        Path(args.out).expanduser(),
        hash_files=not args.no_hash,
        max_hash_bytes=args.max_hash_mb * 1024 * 1024 if args.max_hash_mb else None,
        follow_symlinks=args.follow_symlinks,
    )
    _print(result["summary"])
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    out_dir = Path(args.out).expanduser().resolve()
    if args.current:
        report = run_diff(Path(args.baseline), Path(args.current), out_dir)
    else:
        inv, tmp = _build_temp_inventory(
            Path(args.rescan).expanduser(), hash_files=not args.no_hash
        )
        try:
            report = run_diff(Path(args.baseline), Path(tmp.name) / "inventory.db", out_dir)
        finally:
            inv.close()
            tmp.cleanup()
    _print(report["summary"])
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    profile = None
    if args.profile:
        try:
            profile = load_profile(args.profile)
        except ProfileError as exc:
            print(f"profile error: {exc}", file=sys.stderr)
            return 2
    out_dir = Path(args.out).expanduser().resolve()
    current_root = Path(args.current_root).expanduser().resolve() if args.current_root else None

    if args.baseline:
        inv = Inventory(Path(args.baseline))
        tmp = None
    else:
        inv, tmp = _build_temp_inventory(Path(args.root).expanduser())
    try:
        report = run_verify(
            Path(args.seized),
            inv,
            out_dir,
            profile=profile,
            current_root=current_root,
        )
    finally:
        inv.close()
        if tmp:
            tmp.cleanup()
    _print(report["summary"])
    return 0


def cmd_sources(args: argparse.Namespace) -> int:
    from .common import iso_to_ns

    since_ns = iso_to_ns(args.since) if args.since else None
    report = collect_sources(
        Path(args.root).expanduser(),
        Path(args.out).expanduser(),
        since_ns=since_ns,
        max_file_bytes=args.max_file_mb * 1024 * 1024,
    )
    _print(report["summary"])
    return 0


def cmd_artifacts(args: argparse.Namespace) -> int:
    from .common import iso_to_ns

    since_ns = iso_to_ns(args.since) if args.since else None
    report = collect_artifacts(
        Path(args.root).expanduser(),
        Path(args.out).expanduser(),
        since_ns=since_ns,
        max_file_bytes=args.max_file_mb * 1024 * 1024,
        use_vss=args.vss,
    )
    _print({**report["summary"], "observed_tools": report["observed_investigator_tools"]})
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    result = run_watch(
        Path(args.root).expanduser(),
        Path(args.out).expanduser(),
        interval=args.interval,
        once=args.once,
        max_passes=args.max_passes,
    )
    _print(result)
    return 0


def cmd_carve(args: argparse.Namespace) -> int:
    report = carve_mft(
        Path(args.mft).expanduser(),
        Path(args.out).expanduser(),
        recover_resident=not args.no_recover,
    )
    _print(report["summary"])
    return 0


def cmd_journal(args: argparse.Namespace) -> int:
    from .common import iso_to_ns

    since_ns = iso_to_ns(args.since) if args.since else None
    try:
        report = replay_journal(
            Path(args.out).expanduser(),
            volume=args.volume,
            csv_path=Path(args.csv).expanduser() if args.csv else None,
            since_ns=since_ns,
            name_filter=args.filter,
        )
    except (OSError, ValueError) as exc:
        print(f"journal error: {exc}", file=sys.stderr)
        return 2
    _print(report["summary"])
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    result = build_package(
        Path(args.case).expanduser(),
        Path(args.out).expanduser(),
    )
    _print(result["summary"])
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    result = build_bundle(
        Path(args.out).expanduser(),
        profile=Path(args.profile).expanduser() if args.profile else None,
        seized=Path(args.seized).expanduser() if args.seized else None,
        baseline=Path(args.baseline).expanduser() if args.baseline else None,
        exe=Path(args.exe).expanduser() if args.exe else None,
        raid_date=args.raid_date,
        dest=args.dest,
        stamp=args.stamp,
        notes=args.notes,
    )
    _print(result)
    return 0


def cmd_field(args: argparse.Namespace) -> int:
    from .common import iso_to_ns

    since_ns = iso_to_ns(args.since) if args.since else None
    report = run_field(
        Path(args.root).expanduser(),
        Path(args.inputs).expanduser(),
        Path(args.out).expanduser(),
        hash_files=not args.no_hash,
        since_ns=since_ns,
        use_vss=args.vss,
    )
    _print(
        {
            "steps": report["steps"],
            "results_zip": report["results_zip"],
            "results_zip_sha256": report["results_zip_sha256"],
            "custody_root_hash": report.get("custody_root_hash"),
        }
    )
    return 0


def cmd_mirror(args: argparse.Namespace) -> int:
    try:
        report = run_mirror(
            Path(args.root).expanduser(),
            Path(args.out).expanduser(),
            verify_path=Path(args.verify).expanduser() if args.verify else None,
            seized_path=Path(args.seized).expanduser() if args.seized else None,
            max_file_mb=args.max_file_mb,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"mirror error: {exc}", file=sys.stderr)
        return 2
    _print(report["summary"])
    return 0


def cmd_petition(args: argparse.Namespace) -> int:
    report = run_petition(
        Path(args.case).expanduser(),
        Path(args.out).expanduser(),
        case_no=args.case_no,
        suspect=args.suspect,
        counsel=args.counsel,
        agency=args.agency,
    )
    _print({"petition": report["petition"], "items_listed": report["items_listed"]})
    return 0


def cmd_lockbox(args: argparse.Namespace) -> int:
    report = run_lockbox(
        Path(args.root).expanduser() if args.root else None,
        Path(args.out).expanduser(),
    )
    _print({
        "status": report["status"],
        "volumes": sorted(report.get("volumes", {})),
        "sensitive": report.get("sensitive"),
        "recovery_keys_file": report.get("recovery_keys_file"),
    })
    return 0


def cmd_mobile(args: argparse.Namespace) -> int:
    report = collect_mobile(
        Path(args.root).expanduser(),
        Path(args.out).expanduser(),
        max_file_bytes=args.max_file_mb * 1024 * 1024,
    )
    _print({**report["summary"], "targets": report["targets_found"]})
    return 0


def cmd_boundary(args: argparse.Namespace) -> int:
    try:
        report = run_boundary(
            Path(args.seized).expanduser() if args.seized else None,
            Path(args.verify).expanduser() if args.verify else None,
            Path(args.out).expanduser(),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"boundary error: {exc}", file=sys.stderr)
        return 2
    _print(report["summary"])
    return 0


def cmd_containers(args: argparse.Namespace) -> int:
    from .common import iso_to_ns

    since_ns = iso_to_ns(args.since) if args.since else None
    report = sniff_containers(
        Path(args.out).expanduser(),
        since_ns=since_ns,
        extra_roots=[Path(r).expanduser() for r in args.scan],
        max_hash_gb=args.max_hash_gb,
    )
    _print(report["summary"])
    return 0


def cmd_keyword_audit(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(f"profile error: {exc}", file=sys.stderr)
        return 2
    report = run_keyword_audit(
        Path(args.seized).expanduser(),
        profile,
        Path(args.root).expanduser(),
        Path(args.out).expanduser(),
    )
    _print(report["summary"])
    return 0


def cmd_inquiry(args: argparse.Namespace) -> int:
    from .inquiry import run_inquiry

    return run_inquiry(
        Path(args.case).expanduser(),
        Path(args.out).expanduser() if args.out else None,
        query_text=args.query,
    )


def cmd_harden(args: argparse.Namespace) -> int:
    _print(build_harden(Path(args.out).expanduser()))
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui import run_gui

    return run_gui()


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        report = collect_remote(
            args.host,
            Path(args.kit).expanduser(),
            Path(args.out).expanduser(),
            remote_dir=args.remote_dir,
            remote_root=args.remote_root,
            port=args.port,
        )
    except OSError as exc:
        print(f"collect error: {exc}", file=sys.stderr)
        return 2
    _print(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raidwatch",
        description=(
            "Defense-side seizure verification: baseline inventory, "
            "warrant-profile rescan, post-raid diff, seized-list verification."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common_scan_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--no-hash", action="store_true", help="skip content hashing")
        p.add_argument("--max-hash-mb", type=int, default=None)
        p.add_argument("--follow-symlinks", action="store_true")
        p.add_argument(
            "--incremental",
            action="store_true",
            help="reuse hashes for files whose size+mtime are unchanged",
        )

    p = sub.add_parser("baseline", help="build a baseline inventory DB")
    p.add_argument("root")
    p.add_argument("--out", required=True)
    p.add_argument("--verbose", action="store_true")
    common_scan_opts(p)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("scan", help="independent warrant-criteria rescan")
    p.add_argument("root")
    p.add_argument("--profile", required=True)
    p.add_argument("--out", required=True)
    common_scan_opts(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("diff", help="baseline vs current comparison")
    p.add_argument("--baseline", required=True, help="baseline inventory.db")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--rescan", help="live root to re-inventory")
    grp.add_argument("--current", help="existing inventory.db")
    p.add_argument("--out", required=True)
    p.add_argument("--no-hash", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("verify", help="verify a delivered seized-evidence list")
    p.add_argument("--seized", required=True, help="seized list (json/csv/txt)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--baseline", help="baseline inventory.db")
    src.add_argument("--root", help="live root to inventory on the fly")
    p.add_argument("--profile", help="warrant profile JSON for scope verdicts")
    p.add_argument("--current-root", help="re-hash files on current disk")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "sources",
        help="recover original seized-list sources (printer spool/temp/recycle bin)",
    )
    p.add_argument("root")
    p.add_argument("--out", required=True)
    p.add_argument("--since", help="only collect files modified after this ISO date/time")
    p.add_argument("--max-file-mb", type=int, default=50)
    p.set_defaults(func=cmd_sources)

    p = sub.add_parser(
        "artifacts",
        help="reconstruct investigator activity (prefetch/recent/evtx/hives/VSS)",
    )
    p.add_argument("root")
    p.add_argument("--out", required=True)
    p.add_argument("--since", help="only include items modified after this ISO date/time")
    p.add_argument("--max-file-mb", type=int, default=200)
    p.add_argument(
        "--vss",
        action="store_true",
        help="create a fresh VSS snapshot to reach locked files (Windows, "
             "admin; existing shadows are always tried first, read-only)",
    )
    p.set_defaults(func=cmd_artifacts)

    p = sub.add_parser("watch", help="snapshot-polling change monitor")
    p.add_argument("root")
    p.add_argument("--out", required=True)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="single pass then exit")
    p.add_argument("--max-passes", type=int, default=None)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser(
        "carve",
        help="parse an $MFT dump: deleted entries + resident-data recovery",
    )
    p.add_argument("--mft", required=True, help="path to an $MFT byte dump")
    p.add_argument("--out", required=True)
    p.add_argument(
        "--no-recover", action="store_true",
        help="list deleted entries only, skip resident payload recovery",
    )
    p.set_defaults(func=cmd_carve)

    p = sub.add_parser(
        "journal",
        help="replay the NTFS USN journal (fsutil on Windows, or CSV export)",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--volume", help="e.g. C: — runs fsutil (Windows, elevated)")
    src.add_argument("--csv", help="previously exported USN journal CSV")
    p.add_argument("--out", required=True)
    p.add_argument("--since", help="only events after this ISO date/time")
    p.add_argument("--filter", help="substring filter on file names")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser(
        "package",
        help="assemble the legal-review bundle (disposal list + timeline)",
    )
    p.add_argument("--case", required=True, help="case dir holding raidwatch outputs")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_package)

    p = sub.add_parser(
        "bundle",
        help="build a self-contained field kit (raidwatch.pyz + inputs + RUN scripts)",
    )
    p.add_argument("--out", required=True, help="kit output directory")
    p.add_argument("--profile", help="warrant profile JSON to embed")
    p.add_argument("--seized", help="seized list to embed")
    p.add_argument("--baseline", help="baseline inventory.db to embed")
    p.add_argument(
        "--exe",
        help="PyInstaller-built raidwatch binary for the TARGET platform "
             "(dist/raidwatch.exe) — makes the kit runnable without Python",
    )
    p.add_argument(
        "--raid-date",
        help="preset seizure date/time in CONFIG.txt — client skips "
             "the question entirely",
    )
    p.add_argument(
        "--dest",
        help="preset result return path (e.g. \\\\server\\share) in "
             "CONFIG.txt — results upload automatically",
    )
    p.add_argument(
        "--stamp", choices=["y", "n", "ask"],
        help="preset the red-stamp OCR question (default: ask on-site)",
    )
    p.add_argument("--notes", help="preset case number / notes")
    p.set_defaults(func=cmd_bundle)

    p = sub.add_parser(
        "field",
        help="run the kit pipeline locally (what RUN.bat/RUN.sh invoke)",
    )
    p.add_argument("--root", required=True, help="analysis root on this machine")
    p.add_argument("--inputs", required=True, help="kit inputs dir (may be empty)")
    p.add_argument("--out", required=True, help="output dir for raidwatch-out")
    p.add_argument(
        "--since",
        help="seizure date/time (overrides inputs/info.*; narrows temp sources)",
    )
    p.add_argument("--no-hash", action="store_true")
    p.add_argument(
        "--vss",
        action="store_true",
        help="create a VSS snapshot for locked files (Windows, admin)",
    )
    p.set_defaults(func=cmd_field)

    p = sub.add_parser(
        "harden",
        help="pre-raid kit: HARDEN.bat/REVERT.bat/sysmon config that turns "
             "on OS-native recording (USN, audit policy, PS logging)",
    )
    p.add_argument("--out", required=True, help="hardening kit output dir")
    p.set_defaults(func=cmd_harden)

    p = sub.add_parser(
        "mirror",
        help="copy the exact seized file set (what investigators took) "
             "to an external drive, preserving structure + hashing",
    )
    p.add_argument("--root", required=True, help="filesystem root to copy from")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--verify", help="verify.json with resolved matches")
    src.add_argument("--seized", help="raw seized list — resolved on the fly")
    p.add_argument("--out", required=True, help="destination (external SSD)")
    p.add_argument("--max-file-mb", type=int, default=0,
                   help="per-file cap; 0 = unlimited (default)")
    p.set_defaults(func=cmd_mirror)

    p = sub.add_parser(
        "petition",
        help="print-ready 환부·폐기 청구서 HTML from case outputs",
    )
    p.add_argument("--case", required=True, help="case dir holding raidwatch outputs")
    p.add_argument("--out", required=True)
    p.add_argument("--case-no", help="사건번호")
    p.add_argument("--suspect", help="피압수자 성명")
    p.add_argument("--counsel", help="변호인 성명")
    p.add_argument("--agency", help="집행기관 (e.g. ○○지방검찰청)")
    p.set_defaults(func=cmd_petition)

    p = sub.add_parser(
        "lockbox",
        help="extract BitLocker recovery keys + volume map before power-off "
             "(Windows; admin for key protectors)",
    )
    p.add_argument("--root", help="unused — volumes are auto-detected")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_lockbox)

    for name in ("mobile", "pc-mobile"):
        p = sub.add_parser(
            name,
            help="preserve PC-resident mobile data (KakaoTalk DB, "
                 "iTunes/SmartSwitch backups, desktop messenger state)",
        )
        p.add_argument("root")
        p.add_argument("--out", required=True)
        p.add_argument("--max-file-mb", type=int, default=2048)
        p.set_defaults(func=cmd_mobile)

    p = sub.add_parser(
        "boundary",
        help="warrant-territory violations: network/removable/cloud "
             "paths in the seized list (형소법 §215③)",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--seized", help="raw seized list")
    src.add_argument("--verify", help="verify.json")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_boundary)

    p = sub.add_parser(
        "containers",
        help="hash investigators' evidence containers (.ad1/.e01/.zip) "
             "on attached external media — before they leave",
    )
    p.add_argument("--out", required=True)
    p.add_argument("--since", help="only files modified after this ISO date/time")
    p.add_argument(
        "--scan", action="append", default=[],
        help="extra directory to scan (repeatable)",
    )
    p.add_argument(
        "--max-hash-gb", type=float, default=128,
        help="skip hashing containers larger than this (0 = hash "
             "regardless — a multi-TB image takes hours)",
    )
    p.set_defaults(func=cmd_containers)

    p = sub.add_parser(
        "keyword-audit",
        help="per-keyword noise ratio: how much of what was seized "
             "fails the warrant's own criteria",
    )
    p.add_argument("--seized", required=True, help="seized list")
    p.add_argument("--profile", required=True, help="warrant profile JSON")
    p.add_argument("--root", required=True, help="filesystem root")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_keyword_audit)

    p = sub.add_parser(
        "inquiry",
        help="interrogation-room checker: type a filename, get the "
             "scope verdict in one second",
    )
    p.add_argument("--case", required=True, help="case dir with verify/diff outputs")
    p.add_argument("--out")
    p.add_argument("--query", "-q", help="single lookup, non-interactive")
    p.set_defaults(func=cmd_inquiry)

    p = sub.add_parser("gui", help="office-side Tkinter front-end")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser(
        "collect",
        help="deploy a kit to a remote machine over SSH and pull results back",
    )
    p.add_argument("--host", required=True, help="user@host (key-based ssh auth)")
    p.add_argument("--kit", required=True, help="local kit dir built by `bundle`")
    p.add_argument("--out", required=True, help="local dir for downloaded results")
    p.add_argument("--remote-dir", default="raidwatch-kit")
    p.add_argument("--remote-root", help="analysis root on the remote machine")
    p.add_argument("--port", type=int, default=None)
    p.set_defaults(func=cmd_collect)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Korean help/report text must not crash on non-Korean consoles
    # (cp1252 etc.) — replace unencodable glyphs instead of dying.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
