# Firewall Log Analyzer

A schema-flexible firewall/connection-log analyzer, threat detector, and
firewall-rule generator. Point it at a CSV of firewall logs and it will
normalize the columns, summarize the traffic, flag likely malicious patterns,
and propose concrete ALLOW / BLOCK rules.

This is a rewrite of the original `firewall_analyzer.py`. It keeps the
original idea (summarize connections, suggest rules) and extends it into a tool
that handles arbitrary CSV layouts, interprets what it sees, and looks for
attacks rather than only emitting blanket ALLOW rules.

---

## Why this version

The original script read one hard-coded file, grouped by destination port, and
wrote ALLOW rules for every observed flow. The rewrite addresses that and the
feedback it received:

| Feedback | Addressed |
|----------|-----------|
| Input filename was hard-coded | `argparse` CLI; the CSV path is a positional argument |
| No `main()` / `if __name__ == "__main__"` guard | Logic lives in `main()`; standard guard added |
| `pandas` / `openpyxl` install steps undocumented | **Core needs no third-party packages.** Excel/charts are optional (see below) |
| Tool only suggested when to ALLOW | Now aggregates allowed **and** blocked traffic and generates BLOCK rules |
| No anomaly / drop analysis | Detects port scans, sweeps, sensitive-service exposure, noisy/blocked sources, and suspicious egress |
| Suggested adding charts | Optional `--charts` produces PNG visualizations |
| Output gets huge on big files | **Subnet-based rule aggregation** — many hosts in a subnet collapse into one CIDR rule (adaptive by default) |
| Hard to use from a terminal | A **desktop GUI** with a file-browse dialog and Excel/PDF export |

It also adds the headline capability requested: **it ingests CSVs in different
formats.** Column names do not have to match a fixed schema.

---

## Requirements

- **Python 3.8+** — that is all the command-line tool needs. No `pip install`.
- The **GUI** uses `tkinter`, which ships with Python on Windows and macOS. On
  Linux, install it with `sudo apt install python3-tk`.

Optional, only for the extra output formats:

- `openpyxl` — multi-sheet Excel report (`--excel`)
- `reportlab` — PDF report (`--pdf`)
- `matplotlib` — PNG charts (`--charts`)

If one of these is missing, the tool prints a note and skips that output
instead of crashing.

```bash
# Optional extras (only if you want Excel / PDF / charts)
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
python3 -m pip install -r requirements.txt
```

---

## Usage

### Graphical interface

```bash
python3 firewall_analyzer_gui.py
# or
python3 firewall_analyzer.py --gui
```

The window lets you **Browse** for a CSV with the native file dialog, pick the
rule format and subnet behavior, click **Analyze** to read the report on
screen, and then **Save Excel**, **Save PDF**, **Save JSON**, or **Save
Charts**. Analysis runs on a background thread, so the window stays responsive
on large files.

### Command line

```bash
# Simplest possible run — console report only, no dependencies
python3 firewall_analyzer.py logs.csv

# pfSense-style rules, plus Excel, PDF, and charts
python3 firewall_analyzer.py logs.csv --rule-format pf --excel --pdf --charts

# Control how aggressively rules collapse to subnets
python3 firewall_analyzer.py logs.csv --subnet-mode adaptive --subnet-min-hosts 4

# Tune detection sensitivity and write everything to a folder
python3 firewall_analyzer.py logs.csv -o results/ \
    --scan-port-threshold 20 --sweep-host-threshold 8
```

### Options

| Option | Default | Purpose |
|--------|---------|---------|
| `csv_file` | (required) | Path to the firewall log CSV |
| `-o, --output-dir` | `.` | Where generated files go |
| `--gui` | off | Launch the graphical interface |
| `--rule-format {generic,iptables,pf}` | `generic` | Syntax for suggested rules |
| `--excel` | off | Also write `<name>_report.xlsx` (needs openpyxl) |
| `--pdf` | off | Also write `<name>_report.pdf` (needs reportlab) |
| `--json` | off | Also write `<name>_report.json` |
| `--charts` | off | Also write PNG charts (needs matplotlib) |
| `--subnet-mode {adaptive,always,never}` | `adaptive` | How ALLOW rules collapse to subnets (see below) |
| `--subnet-min-hosts` | 3 | Adaptive mode: hosts in a subnet (to same dst+port) before collapsing |
| `--subnet-prefix-v4` | 24 | IPv4 prefix length for aggregation |
| `--subnet-prefix-v6` | 64 | IPv6 prefix length for aggregation |
| `--top-rules` | 25 | Max number of ALLOW rules to propose |
| `--scan-port-threshold` | 15 | Distinct dst ports (one src→one dst) to call it a port scan |
| `--sweep-host-threshold` | 10 | Distinct dst hosts (one src, one port) to call it a sweep |
| `--block-threshold` | 5 | Min blocked events to flag a noisy source |
| `--block-ratio` | 0.5 | Min blocked/total ratio to flag a noisy source |
| `-q, --quiet` | off | Suppress console report (still writes files) |
| `-v, --verbose` | off | Verbose logging |

The process **exit code** is `1` when any CRITICAL or HIGH finding is present,
`0` otherwise, and `2` on input errors — convenient for cron jobs or CI gates.

---

## How the CSV schema detection works

You do not have to rename your columns. The tool maps your headers to a common
schema in two passes:

1. **Alias matching.** Header names are normalized (lowercased, punctuation
   removed) and matched against a table of known aliases. For example
   `Source IP`, `src_ip`, `SrcAddr`, `saddr`, and `from` all map to the source
   address; `Dpt`, `dport`, `destination_port`, and `service` all map to the
   destination port.

2. **Value-based heuristics.** For anything still unmapped, the tool samples the
   actual values in each column. Columns whose values parse as IP addresses
   become source/destination IP (in column order); integer columns in the
   0–65535 range become ports; columns full of `allow`/`deny`/`permit`/`drop`
   tokens become the action; date-like columns become the timestamp.

Source and destination IP are the only required fields. Everything else
(ports, action, protocol, timestamp, bytes) is used when present and skipped
when absent — detections that depend on a missing column are simply not run.

The tool prints the schema it detected at the top of every report so you can
confirm it guessed correctly.

The delimiter (comma, tab, semicolon, pipe) is auto-detected.

---

## What it detects

| Finding | Signal | Default severity |
|---------|--------|------------------|
| **Vertical port scan** | One source → many distinct ports on one host | HIGH (external) / MEDIUM (internal) |
| **Horizontal sweep** | One source → one port across many hosts | HIGH if external or sensitive port |
| **Sensitive-service exposure** | External source reaching internal RDP/SMB/SQL/etc. (not blocked) | CRITICAL |
| **Noisy / blocked source** | A source the firewall denies repeatedly | HIGH (external) / MEDIUM (internal) |
| **Suspicious egress** | Internal host → external on a known-bad (4444, Tor, IRC…) or uncommon high port | MEDIUM (known-bad) / LOW |

A correlation step folds redundant findings together: if a source is already
flagged for a sweep, its individual per-host hits on that port are not repeated
as dozens of separate alerts.

Internal vs. external is determined with Python's `ipaddress` module
(RFC 1918, loopback, link-local, and unique-local are treated as internal).

Each finding includes a plain-English interpretation and a recommended action,
not just a label.

---

## Suggested rules

- **BLOCK rules** come from the findings — block the scanning source, block the
  external host reaching RDP, block the C2 egress, and so on. When two or more
  flagged sources share a subnet (e.g. a distributed scan from one `/24`), they
  are consolidated into a single subnet block.
- **ALLOW rules** come from the most frequent flows that were *not* blocked and
  whose source is *not* implicated in any finding.

### Subnet-based aggregation

Real firewall policy is usually written against subnets, not individual hosts,
and a large capture can contain thousands of source IPs. The tool collapses
sources into CIDR rules so the output stays practical:

- **`adaptive`** (default) — for each destination + port, hosts are grouped by
  subnet. A subnet collapses to one CIDR rule only when at least
  `--subnet-min-hosts` distinct hosts from it reach that destination + port.
  A subnet with one or two busy hosts stays as specific host rules; a subnet
  with a dozen clients becomes a single rule. This gives subnet rules where the
  traffic actually looks like a subnet, and host rules where it does not.
- **`always`** — collapse every flow to its source subnet.
- **`never`** — one rule per individual host (the original behavior).

`--subnet-prefix-v4` / `--subnet-prefix-v6` control the aggregation prefix
(defaults `/24` and `/64`).

Three output syntaxes:

```
generic   ALLOW 192.168.1.0/24 -> 10.10.10.10:123/udp
iptables  iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.10.10 -p udp --dport 123 -j ACCEPT
pf        pass in quick proto udp from 192.168.1.0/24 to 10.10.10.10 port 123 keep state
```

> These are **starting points for review**, not rules to paste into production
> blindly. Confirm the legitimate flows, and remember the ALLOW list reflects
> only the traffic that happened to appear in the log sample.

---

## Output files

With the optional flags, for an input named `logs.csv` you get:

- `logs_report.xlsx` — Summary, Top Ports, Top Sources, Findings (severity
  color-coded), and Suggested Rules sheets
- `logs_report.pdf` — a readable PDF with the summary, color-coded findings,
  and the rule tables
- `logs_report.json` — the full analysis as structured data for pipelines
- `logs_charts/` — `top_ports.png`, `allow_vs_block.png`, `top_talkers.png`

---

## Sample data

`make_samples.py` generates three CSVs in different schemas, each with the same
injected attack patterns (a port scan, an SMB sweep, an external RDP exposure,
and a Metasploit-port egress beacon):

- `sample_full.csv` — full schema, conventional headers, with action/timestamp
- `sample_vendor.csv` — vendor-style headers (`EventTime`, `Disposition`,
  `SrcAddr`, `Dpt`…), `permit`/`deny` actions, no protocol column
- `sample_minimal.csv` — bare `from,to,port` to exercise heuristic detection

```bash
python3 make_samples.py
python3 firewall_analyzer.py sample_vendor.csv --rule-format pf
```

---

## AI use statement

Portions of this tool were developed with AI assistance (design discussion,
code review, and documentation). All logic was reviewed, tested against the
sample datasets, and validated by the author. See `AI Use Statement.txt`.

## License

MIT
