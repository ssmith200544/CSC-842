#!/usr/bin/env python3
"""
firewall_analyzer_gui.py - A simple desktop front-end for firewall_analyzer.

Launch it directly:

    python3 firewall_analyzer_gui.py

or via the engine:

    python3 firewall_analyzer.py --gui

It provides a window where you browse for a CSV with the native file dialog,
run the analysis, read the report on screen, and save the results as an Excel
workbook or a PDF (also JSON and charts).

Tkinter ships with Python on Windows and macOS. On Linux you may need the Tk
package, e.g. `sudo apt install python3-tk`.
"""

from __future__ import annotations

import os
import queue
import threading
import traceback

import firewall_analyzer as fa

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    TK_AVAILABLE = True
except ImportError:           # headless / Tk not installed
    TK_AVAILABLE = False


class AnalyzerApp:
    """The main application window."""

    def __init__(self, root: "tk.Tk"):
        self.root = root
        self.result: fa.AnalysisResult | None = None
        self._queue: queue.Queue = queue.Queue()

        root.title(f"Firewall Log Analyzer  v{fa.__version__}")
        root.geometry("960x720")
        root.minsize(760, 560)

        self._build_widgets()

    # -- layout -------------------------------------------------------------

    def _build_widgets(self) -> None:
        pad = {"padx": 6, "pady": 4}

        # File selection row
        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="CSV file:").pack(side="left")
        self.csv_var = tk.StringVar()
        self.csv_entry = ttk.Entry(top, textvariable=self.csv_var)
        self.csv_entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse\u2026",
                   command=self.browse).pack(side="left")

        # Options row
        opts = ttk.LabelFrame(self.root, text="Options")
        opts.pack(fill="x", **pad)

        ttk.Label(opts, text="Rule format:").grid(row=0, column=0, sticky="w",
                                                   padx=6, pady=4)
        self.fmt_var = tk.StringVar(value="generic")
        ttk.Combobox(opts, textvariable=self.fmt_var, width=10,
                     state="readonly",
                     values=["generic", "iptables", "pf"]).grid(
            row=0, column=1, sticky="w", padx=6)

        ttk.Label(opts, text="Subnet rules:").grid(row=0, column=2, sticky="w",
                                                   padx=6)
        self.subnet_var = tk.StringVar(value="adaptive")
        ttk.Combobox(opts, textvariable=self.subnet_var, width=10,
                     state="readonly",
                     values=["adaptive", "always", "never"]).grid(
            row=0, column=3, sticky="w", padx=6)

        ttk.Label(opts, text="Min hosts/subnet:").grid(row=0, column=4,
                                                       sticky="w", padx=6)
        self.minhosts_var = tk.IntVar(value=3)
        ttk.Spinbox(opts, from_=1, to=255, width=5,
                    textvariable=self.minhosts_var).grid(
            row=0, column=5, sticky="w", padx=6)

        self.analyze_btn = ttk.Button(opts, text="Analyze",
                                      command=self.analyze)
        self.analyze_btn.grid(row=0, column=6, sticky="e", padx=10, pady=4)

        # Report display
        self.text = scrolledtext.ScrolledText(self.root, wrap="word",
                                               font=("Courier New", 10))
        self.text.pack(fill="both", expand=True, **pad)
        self.text.insert("1.0",
                         "Select a CSV file and click Analyze.\n\n"
                         "The report appears here. Then save it as Excel or "
                         "PDF using the buttons below.")
        self.text.configure(state="disabled")

        # Save buttons
        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", **pad)
        self.save_buttons = {}
        for label, kind in (("Save Excel\u2026", "excel"),
                            ("Save PDF\u2026", "pdf"),
                            ("Save JSON\u2026", "json"),
                            ("Save Charts\u2026", "charts")):
            b = ttk.Button(bottom, text=label,
                           command=lambda k=kind: self.save(k), state="disabled")
            b.pack(side="left", padx=4)
            self.save_buttons[kind] = b

        # Status bar
        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self.root, textvariable=self.status, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

    # -- actions ------------------------------------------------------------

    def browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Select a firewall log CSV",
            filetypes=[("CSV / log files", "*.csv *.tsv *.txt *.log"),
                       ("All files", "*.*")])
        if path:
            self.csv_var.set(path)
            self.status.set(f"Selected {os.path.basename(path)}")

    def _config(self) -> fa.AnalysisConfig:
        return fa.AnalysisConfig(
            rule_format=self.fmt_var.get(),
            subnet_mode=self.subnet_var.get(),
            subnet_min_hosts=int(self.minhosts_var.get()),
        )

    def _compute(self) -> fa.AnalysisResult:
        """Run analysis synchronously. Safe to call off the UI thread."""
        return fa.analyze(self.csv_var.get(), self._config())

    def analyze(self) -> None:
        path = self.csv_var.get().strip()
        if not path:
            messagebox.showwarning("No file", "Please choose a CSV file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Not found", f"File not found:\n{path}")
            return

        # Run the analysis on a worker thread so the UI stays responsive on
        # large files; the result is delivered back through a queue.
        self.analyze_btn.configure(state="disabled")
        self.status.set("Analyzing\u2026")
        self.root.update_idletasks()

        def worker():
            try:
                self._queue.put(("ok", self._compute()))
            except Exception:                       # surface any failure
                self._queue.put(("err", traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._poll)

    def _poll(self) -> None:
        try:
            kind, payload = self._queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll)
            return
        self.analyze_btn.configure(state="normal")
        if kind == "err":
            self.status.set("Analysis failed.")
            messagebox.showerror("Analysis error", payload)
            return
        self.result = payload
        self._show_result(payload)

    def _show_result(self, result: fa.AnalysisResult) -> None:
        report = fa.format_report(result)
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", report)
        self.text.configure(state="disabled")
        n_crit = sum(1 for f in result.findings
                     if f.severity in ("CRITICAL", "HIGH"))
        self.status.set(
            f"Analyzed {result.summary['total']} records \u2022 "
            f"{len(result.findings)} findings ({n_crit} high/critical) \u2022 "
            f"{len(result.block_rules)} block / {len(result.allow_rules)} allow "
            "rules")
        for b in self.save_buttons.values():
            b.configure(state="normal")

    def save_to(self, kind: str, path: str) -> bool:
        """Write a given output type to an explicit path (testable)."""
        if self.result is None:
            return False
        if kind == "excel":
            return fa.write_excel(path, self.result)
        if kind == "pdf":
            return fa.write_pdf(path, self.result)
        if kind == "json":
            fa.write_json(path, self.result)
            return True
        if kind == "charts":
            return fa.write_charts(path, self.result)
        return False

    def save(self, kind: str) -> None:
        if self.result is None:
            messagebox.showwarning("Nothing to save", "Run an analysis first.")
            return
        base = os.path.splitext(os.path.basename(self.csv_var.get()))[0]

        if kind == "charts":
            path = filedialog.askdirectory(title="Choose a folder for charts")
            if not path:
                return
        else:
            ext = {"excel": ".xlsx", "pdf": ".pdf", "json": ".json"}[kind]
            path = filedialog.asksaveasfilename(
                title=f"Save {kind.upper()}",
                defaultextension=ext,
                initialfile=f"{base}_report{ext}",
                filetypes=[(f"{kind.upper()} file", f"*{ext}"),
                           ("All files", "*.*")])
            if not path:
                return
        try:
            ok = self.save_to(kind, path)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        if ok:
            self.status.set(f"Saved {path}")
            messagebox.showinfo("Saved", f"Wrote:\n{path}")
        else:
            messagebox.showwarning(
                "Not saved",
                f"Could not write {kind.upper()}. The optional library it needs "
                "may not be installed (openpyxl for Excel, reportlab for PDF, "
                "matplotlib for charts).")


def launch() -> int:
    if not TK_AVAILABLE:
        print("Tkinter is not available. On Linux install it with "
              "'sudo apt install python3-tk'.")
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Could not open a display for the GUI: {exc}\n"
              "Run on a machine with a desktop, or use the command line "
              "(python3 firewall_analyzer.py <file.csv>).")
        return 2
    AnalyzerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
