"""raidwatch CLI — baseline, scan, diff, verify, watch subcommands."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .artifacts import collect_artifacts
from .bundle import build_bundle
from .common import write_json, write_manifest
from .db import Inventory
from .diff import run_diff
from .field import run_field
from .inventory import build_inventory
from .journal import replay_journal
from .mft import carve_mft
from .package import build_package
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
    )
    _print(
        {
            "steps": report["steps"],
            "results_zip": report["results_zip"],
            "results_zip_sha256": report["results_zip_sha256"],
        }
    )
    return 0


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
    p.set_defaults(func=cmd_field)

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
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
