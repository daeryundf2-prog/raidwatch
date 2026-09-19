"""Baseline-vs-current inventory diff with change classification."""

from __future__ import annotations

from pathlib import Path

from .common import ns_to_iso, write_json, write_manifest
from .db import FileRecord, Inventory


def _classify(before: FileRecord, after: FileRecord) -> str:
    if before.kind != after.kind:
        return "kind_changed"
    if before.sha256 and after.sha256:
        if before.sha256 != after.sha256:
            return "content_changed"
        mtime_same = before.mtime_ns == after.mtime_ns
        atime_diff = before.atime_ns != after.atime_ns
        meta_diff = (
            not mtime_same
            or before.ctime_ns != after.ctime_ns
            or before.size != after.size
        )
        if atime_diff and mtime_same:
            # Content identical, mtime preserved, only access time moved —
            # the file was opened/read, not modified.
            return "accessed"
        if meta_diff or atime_diff:
            return "metadata_changed"
        return "unchanged"
    if before.status != after.status:
        return "status_changed"
    if (
        before.mtime_ns != after.mtime_ns
        or before.ctime_ns != after.ctime_ns
        or before.size != after.size
    ):
        return "modified_unverifiable"
    return "unchanged_unverifiable"


def _brief(rec: FileRecord) -> dict:
    return {
        "size": rec.size,
        "mtime_utc": ns_to_iso(rec.mtime_ns),
        "sha256": rec.sha256,
        "kind": rec.kind,
        "status": rec.status,
    }


def diff_inventories(
    baseline: Inventory,
    current: Inventory,
    *,
    baseline_created_ns: int | None = None,
) -> dict:
    base = {r.path: r for r in baseline.iter_records()}
    cur = {r.path: r for r in current.iter_records()}

    added = []
    removed = []
    changed = []
    summary = {
        "added": 0,
        "removed": 0,
        "backdated_added": 0,
        "content_changed": 0,
        "accessed": 0,
        "metadata_changed": 0,
        "kind_changed": 0,
        "status_changed": 0,
        "modified_unverifiable": 0,
        "unchanged": 0,
        "unchanged_unverifiable": 0,
    }

    for path in sorted(set(base) | set(cur)):
        before = base.get(path)
        after = cur.get(path)
        if before is None:
            summary["added"] += 1
            entry = {"path": path, **_brief(after)}
            # A file that appeared during the raid window but claims an mtime
            # older than the baseline is a timestomp/planting indicator.
            if (
                baseline_created_ns is not None
                and after.kind == "file"
                and 0 < after.mtime_ns < baseline_created_ns
            ):
                entry["backdated"] = True
                summary["backdated_added"] += 1
            added.append(entry)
            continue
        if after is None:
            summary["removed"] += 1
            removed.append({"path": path, **_brief(before)})
            continue
        cls = _classify(before, after)
        summary[cls] += 1
        if cls in ("unchanged", "unchanged_unverifiable"):
            continue
        changed.append(
            {
                "path": path,
                "class": cls,
                "before": _brief(before),
                "after": _brief(after),
            }
        )
    return {
        "summary": summary,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def render_diff_markdown(report: dict, base_root: str | None, cur_root: str | None) -> str:
    s = report["summary"]
    lines = [
        "# raidwatch 변경점 리포트",
        "",
        f"- 기준선 루트: `{base_root or 'unknown'}`",
        f"- 비교 루트: `{cur_root or 'unknown'}`",
        "",
        "## 요약",
        "",
        "| 구분 | 건수 |",
        "|---|---|",
        f"| 추가(created) | {s['added']} |",
        f"| └ 그중 과거로 위장된 mtime(식재 의심) | {s['backdated_added']} |",
        f"| 삭제(removed) | {s['removed']} |",
        f"| 내용 변경 | {s['content_changed']} |",
        f"| 열람만(atime만 변경) | {s['accessed']} |",
        f"| 메타데이터만 변경(열람/접근 흔적) | {s['metadata_changed']} |",
        f"| 유형 변경 | {s['kind_changed']} |",
        f"| 변경(해시 불가) | {s['modified_unverifiable']} |",
        f"| 변경 없음 | {s['unchanged'] + s['unchanged_unverifiable']} |",
        "",
    ]
    for title, key in (("추가된 항목", "added"), ("삭제된 항목", "removed"), ("변경된 항목", "changed")):
        items = report[key]
        if not items:
            continue
        lines += [f"## {title} ({len(items)})", "", "| 경로 | 상세 |", "|---|---|"]
        for it in items:
            if key == "changed":
                detail = f"{it['class']} — before sha256 `{it['before']['sha256']}` → after `{it['after']['sha256']}`"
            else:
                detail = f"size {it['size']}, sha256 `{it['sha256']}`"
                if it.get("backdated"):
                    detail += " — **mtime이 기준선 이전으로 위장됨(식재 의심)**"
            lines.append(f"| `{it['path']}` | {detail} |")
        lines.append("")
    return "\n".join(lines)


def run_diff(baseline_db: Path, current_db: Path, out_dir: Path) -> dict:
    from .common import iso_to_ns

    baseline = Inventory(baseline_db)
    current = Inventory(current_db)
    created = baseline.get_meta("created_utc")
    baseline_created_ns = iso_to_ns(created) if created else None
    report = diff_inventories(
        baseline, current, baseline_created_ns=baseline_created_ns
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "diff.json", report)
    (out_dir / "report.md").write_text(
        render_diff_markdown(
            report, baseline.get_meta("root"), current.get_meta("root")
        ),
        encoding="utf-8",
    )
    write_manifest(
        out_dir,
        "diff",
        {
            "baseline_db": str(baseline_db),
            "current_db": str(current_db),
            "baseline_created_utc": baseline.get_meta("created_utc"),
            "current_created_utc": current.get_meta("created_utc"),
            "summary": report["summary"],
        },
    )
    baseline.close()
    current.close()
    return report
