"""Minimal office-side GUI — Tkinter (stdlib, ships inside the exe).

For the defense team's own workstation: pick a root, run baseline /
field / verify without touching a shell. The client still gets RUN.bat;
this is for whoever prepares the kit and reads results.

`raidwatch gui` fails cleanly on headless systems.
"""

from __future__ import annotations

import threading
import traceback
from pathlib import Path


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("tkinter unavailable — use the CLI commands instead")
        return 2

    root_tk = tk.Tk()
    root_tk.title("raidwatch")
    root_tk.geometry("640x480")

    main = ttk.Frame(root_tk, padding=10)
    main.pack(fill="both", expand=True)

    ttk.Label(main, text="Target root (e.g. C:\\)").grid(
        row=0, column=0, sticky="w")
    root_var = tk.StringVar(value="C:\\")
    ttk.Entry(main, textvariable=root_var, width=44).grid(
        row=0, column=1, sticky="ew")
    ttk.Button(
        main, text="…",
        command=lambda: root_var.set(
            filedialog.askdirectory() or root_var.get()),
    ).grid(row=0, column=2)

    ttk.Label(main, text="Output folder").grid(row=1, column=0, sticky="w")
    out_var = tk.StringVar(value="raidwatch-out")
    ttk.Entry(main, textvariable=out_var, width=44).grid(
        row=1, column=1, sticky="ew")
    ttk.Button(
        main, text="…",
        command=lambda: out_var.set(
            filedialog.askdirectory() or out_var.get()),
    ).grid(row=1, column=2)

    log = tk.Text(main, height=20, wrap="word")
    log.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=8)
    main.rowconfigure(3, weight=1)
    main.columnconfigure(1, weight=1)

    def say(msg: str) -> None:
        log.insert("end", msg + "\n")
        log.see("end")

    def work(name: str, fn) -> None:
        def _t():
            say(f"--- {name} started ---")
            try:
                res = fn()
                say(f"--- {name} done ---")
                if isinstance(res, dict) and res.get("results_zip"):
                    say(f"archive: {res['results_zip']}")
            except Exception:
                say(traceback.format_exc())
                say(f"--- {name} FAILED ---")

        threading.Thread(target=_t, daemon=True).start()

    def do_baseline():
        from .db import Inventory
        from .inventory import build_inventory

        def _run():
            out = Path(out_var.get())
            out.mkdir(parents=True, exist_ok=True)
            inv = Inventory(out / "baseline.db", create=True)
            try:
                return build_inventory(
                    Path(root_var.get()), inv, hash_files=True)
            finally:
                inv.close()

        work("baseline", _run)

    def do_field():
        from .field import run_field

        work(
            "field",
            lambda: run_field(
                Path(root_var.get()),
                Path("inputs"),
                Path(out_var.get()),
                use_vss=vss_var.get(),
            ),
        )

    def do_bundle():
        from .bundle import build_bundle

        kit = filedialog.asksaveasfilename(
            title="kit dir name", initialfile="raidwatch-kit")
        if not kit:
            return
        exe = filedialog.askopenfilename(
            title="raidwatch.exe to embed (Cancel = pyz only)")
        work(
            "bundle",
            lambda: build_bundle(
                Path(kit), exe_path=Path(exe) if exe else None),
        )

    vss_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        main, text="use VSS for locked files (admin)",
        variable=vss_var,
    ).grid(row=2, column=1, sticky="w")

    btns = ttk.Frame(main)
    btns.grid(row=4, column=0, columnspan=3, sticky="ew")
    ttk.Button(btns, text="Build baseline", command=do_baseline).pack(
        side="left", padx=4)
    ttk.Button(btns, text="Field run", command=do_field).pack(
        side="left", padx=4)
    ttk.Button(btns, text="Build kit", command=do_bundle).pack(
        side="left", padx=4)

    say("raidwatch gui — outputs land in the output folder only")
    try:
        root_tk.mainloop()
    except tk.TclError:
        print("no display — use the CLI commands instead")
        return 2
    return 0
