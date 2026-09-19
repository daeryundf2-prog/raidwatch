"""Warrant-profile loading and criterion evaluation.

A profile translates the warrant's seizure conditions into machine-checkable
criteria. Evaluation produces two verdicts per criterion group so seized
items can be classified under both a narrow and a broad interpretation of
the warrant language.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .common import iso_to_ns, sha256_text

CRITERION_GROUPS = (
    "keywords",
    "extensions",
    "filename_patterns",
    "date_ranges",
    "path_include",
    "size_bytes",
    "hash_sets",
)


class ProfileError(ValueError):
    pass


def _norm_keyword(entry) -> dict:
    if isinstance(entry, str):
        return {"term": entry, "regex": False, "in": "name", "case_sensitive": False}
    if isinstance(entry, dict) and "term" in entry:
        return {
            "term": str(entry["term"]),
            "regex": bool(entry.get("regex", False)),
            "in": str(entry.get("in", "name")),
            "case_sensitive": bool(entry.get("case_sensitive", False)),
        }
    raise ProfileError(f"invalid keyword entry: {entry!r}")


def load_profile(path: Path | str) -> dict:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot load profile {path}: {exc}") from exc
    crit = raw.get("criteria", {})

    extensions = sorted(
        {(e if e.startswith(".") else "." + e).lower() for e in crit.get("extensions", [])}
    )
    keywords = [_norm_keyword(k) for k in crit.get("keywords", [])]
    for kw in keywords:
        if kw["regex"]:
            flags = 0 if kw["case_sensitive"] else re.IGNORECASE
            try:
                kw["_compiled"] = re.compile(kw["term"], flags)
            except re.error as exc:
                raise ProfileError(f"bad regex {kw['term']!r}: {exc}") from exc

    date_ranges = []
    for dr in crit.get("date_ranges", []):
        field = dr.get("field", "mtime")
        if field not in ("mtime", "ctime", "atime"):
            raise ProfileError(f"unknown date field {field!r}")
        date_ranges.append(
            {
                "field": field,
                "from_ns": iso_to_ns(dr["from"]) if dr.get("from") else None,
                "to_ns": iso_to_ns(dr["to"]) if dr.get("to") else None,
            }
        )

    size = crit.get("size_bytes") or {}
    hash_sets = []
    for hs in crit.get("hash_sets", []):
        hs_path = Path(hs["file"])
        if not hs_path.is_absolute():
            hs_path = path.parent / hs_path
        try:
            digests = {
                line.split()[0].strip().lower()
                for line in hs_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        except OSError as exc:
            raise ProfileError(f"cannot load hash set {hs_path}: {exc}") from exc
        hash_sets.append({"name": hs.get("name", hs_path.name), "digests": digests})

    return {
        "raw": raw,
        "profile_sha256": sha256_text(json.dumps(raw, ensure_ascii=False, sort_keys=True)),
        "source": str(path),
        "criteria": {
            "keywords": keywords,
            "extensions": set(extensions),
            "filename_patterns": [p.lower() for p in crit.get("filename_patterns", [])],
            "date_ranges": date_ranges,
            "path_include": [p.lower().replace("\\", "/") for p in crit.get("path_include", [])],
            "path_exclude": [p.lower().replace("\\", "/") for p in crit.get("path_exclude", [])],
            "size_bytes": {"min": size.get("min"), "max": size.get("max")},
            "hash_sets": hash_sets,
        },
    }


def _kw_match(kw: dict, name: str, rel: str) -> bool:
    if kw["regex"]:
        return bool(kw["_compiled"].search(name) or kw["_compiled"].search(rel))
    term = kw["term"] if kw["case_sensitive"] else kw["term"].lower()
    hay_name = name if kw["case_sensitive"] else name.lower()
    hay_rel = rel if kw["case_sensitive"] else rel.lower()
    return term in hay_name or term in hay_rel


def evaluate(item: dict, profile: dict) -> dict:
    """Evaluate an item ({path,name,size,mtime_ns,ctime_ns,atime_ns,sha256}).

    Returns {excluded, groups: {group: bool|None}, narrow, broad, matched}.
    A group value of None means "criterion present but not evaluable"
    (e.g. content keywords without content access).
    """
    crit = profile["criteria"]
    rel = item["path"].replace("\\", "/")
    rel_l = rel.lower()
    name = item.get("name") or rel.rsplit("/", 1)[-1]
    name_l = name.lower()

    excluded = any(
        fnmatch.fnmatch(rel_l, pat) or fnmatch.fnmatch(name_l, pat)
        for pat in crit["path_exclude"]
    )

    groups: dict[str, bool | None] = {}

    if crit["extensions"]:
        ext = "." + name_l.rsplit(".", 1)[-1] if "." in name_l else ""
        groups["extensions"] = ext in crit["extensions"]

    if crit["filename_patterns"]:
        groups["filename_patterns"] = any(
            fnmatch.fnmatch(name_l, p) or fnmatch.fnmatch(rel_l, p)
            for p in crit["filename_patterns"]
        )

    if crit["keywords"]:
        name_kws = [k for k in crit["keywords"] if k["in"] != "content"]
        content_kws = [k for k in crit["keywords"] if k["in"] == "content"]
        name_hit = any(_kw_match(k, name, rel_l) for k in name_kws)
        if name_hit:
            groups["keywords"] = True
        elif content_kws:
            groups["keywords"] = None if item.get("content") is None else bool(
                any(
                    (k["_compiled"].search(item["content"]) if k["regex"] else
                     (k["term"] if k["case_sensitive"] else k["term"].lower())
                     in (item["content"] if k["case_sensitive"] else item["content"].lower()))
                    for k in content_kws
                )
            )
        else:
            groups["keywords"] = False

    if crit["date_ranges"]:
        ok = False
        for dr in crit["date_ranges"]:
            value = item.get(f"{dr['field']}_ns") or 0
            if dr["from_ns"] is not None and value < dr["from_ns"]:
                continue
            if dr["to_ns"] is not None and value > dr["to_ns"]:
                continue
            ok = True
        groups["date_ranges"] = ok

    if crit["path_include"]:
        groups["path_include"] = any(
            fnmatch.fnmatch(rel_l, p) for p in crit["path_include"]
        )

    size_c = crit["size_bytes"]
    if size_c["min"] is not None or size_c["max"] is not None:
        size = item.get("size") or 0
        groups["size_bytes"] = (
            (size_c["min"] is None or size >= size_c["min"])
            and (size_c["max"] is None or size <= size_c["max"])
        )

    if crit["hash_sets"]:
        digest = (item.get("sha256") or "").lower()
        groups["hash_sets"] = bool(
            digest and any(digest in hs["digests"] for hs in crit["hash_sets"])
        )

    present = [g for g, v in groups.items() if v is not None]
    matched = [g for g in present if groups[g]]
    narrow = bool(present) and all(groups[g] for g in present)
    broad = bool(matched)
    if excluded:
        verdict = "excluded"
    elif narrow:
        verdict = "in_scope"
    elif broad:
        verdict = "borderline"
    else:
        verdict = "out_of_scope"
    return {
        "excluded": excluded,
        "groups": groups,
        "matched": matched,
        "narrow": narrow,
        "broad": broad,
        "verdict": verdict,
    }
