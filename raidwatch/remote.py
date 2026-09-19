"""Remote collection — push a kit to the client's machine, pull results.

Uses the system ssh/scp binaries (no external deps). Intended target:
the client's own machine where the analyst has legitimate access —
typically a Windows box with OpenSSH Server enabled, or any POSIX host.

Flow: kit dir → scp to remote → ssh run the field pipeline →
scp raidwatch-results.zip + SHA256SUMS.txt back → verify hashes.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest


def _ssh_cmd(host: str, remote_cmd: str, port: int | None) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes"]
    if port:
        cmd += ["-p", str(port)]
    return cmd + [host, remote_cmd]


def _scp_base(port: int | None) -> list[str]:
    cmd = ["scp", "-q", "-o", "BatchMode=yes"]
    if port:
        cmd += ["-P", str(port)]
    return cmd


def _run(cmd: list[str], timeout: int) -> str:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise OSError(
            f"{cmd[0]} failed ({proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return proc.stdout


def collect_remote(
    host: str,
    kit_dir: Path,
    out_dir: Path,
    *,
    remote_dir: str = "raidwatch-kit",
    remote_root: str | None = None,
    port: int | None = None,
    timeout: int = 1800,
) -> dict:
    """Deploy kit_dir to host via scp, run the field pipeline over ssh,
    download the results archive, and verify its contents against
    SHA256SUMS.txt.

    `remote_root` overrides the analysis root on the target (default:
    the RUN script's own default). Requires key-based ssh auth —
    BatchMode is forced so the command never hangs on a password prompt.
    """
    if shutil.which("ssh") is None or shutil.which("scp") is None:
        raise OSError("ssh/scp not found on PATH")
    kit_dir = Path(kit_dir).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log: list[str] = []

    # 1. push the kit
    _run(
        _scp_base(port) + ["-r", str(kit_dir), f"{host}:{remote_dir}"],
        timeout=300,
    )
    log.append(f"kit uploaded to {host}:{remote_dir}")

    # 2. run the field pipeline remotely — POSIX shell form first,
    # Windows OpenSSH (cmd) fallback
    root_arg = f" {remote_root}" if remote_root else ""
    remote_cmd = (
        f"cd {remote_dir} && "
        f"(sh RUN.sh{root_arg} || cmd /c RUN.bat{root_arg})"
    )
    _run(_ssh_cmd(host, remote_cmd, port), timeout=timeout)
    log.append("field pipeline finished")

    # 3. pull results
    results_local = out_dir / "raidwatch-results.zip"
    sums_local = out_dir / "SHA256SUMS.txt"
    _run(
        _scp_base(port) + [
            f"{host}:{remote_dir}/raidwatch-out/raidwatch-results.zip",
            str(results_local),
        ],
        timeout=600,
    )
    _run(
        _scp_base(port) + [
            f"{host}:{remote_dir}/raidwatch-out/SHA256SUMS.txt",
            str(sums_local),
        ],
        timeout=120,
    )
    log.append("results downloaded")

    # 4. verify archive members against the remote-produced SHA256SUMS
    verified = 0
    mismatched = []
    extract_dir = out_dir / "results-extracted"
    with zipfile.ZipFile(results_local) as zf:
        # extract member-by-member, refusing absolute/.. paths — the zip
        # came back over the wire, so treat its paths as untrusted
        for member in zf.namelist():
            target = (extract_dir / member).resolve()
            if not target.is_relative_to(extract_dir.resolve()):
                continue
            zf.extract(member, extract_dir)
    for line in sums_local.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        rel = rel.strip()
        target = extract_dir / rel
        if not target.is_file():
            mismatched.append(f"missing:{rel}")
            continue
        if sha256_file(target) == digest.strip():
            verified += 1
        else:
            mismatched.append(f"hash_mismatch:{rel}")

    report = {
        "host": host,
        "remote_dir": remote_dir,
        "collected_utc": utc_now_iso(),
        "log": log,
        "results_zip": str(results_local),
        "results_zip_sha256": sha256_file(results_local),
        "verified_files": verified,
        "mismatches": mismatched,
    }
    write_json(out_dir / "collect.json", report)
    write_manifest(
        out_dir, "collect", {"host": host, "verified_files": verified,
                             "mismatches": len(mismatched)},
    )
    return report
