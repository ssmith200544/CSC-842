Firewall Analyzer

Project Description

The Firewall Analyzer is a simple Python tool that reads firewall log data from a CSV file and creates Excel reports that summarize network traffic.

The tool focuses on two main tasks:

1. Summarizing traffic by destination port
2. Creating basic firewall rule suggestions based on observed traffic

This project is intended as a beginner-friendly security analytics tool for reviewing firewall logs and identifying useful traffic patterns.

Files

| File                                | Description                                             |
| ----------------------------------- | ------------------------------------------------------- |
| `firewall_analyzer.py`              | Main Python script                                      |
| `firewall_practice_logs.csv`        | Input CSV file containing sample firewall log data      |
| `Firewall_Connections_Summary.xlsx` | Excel report summarizing traffic by destination port    |
| `Firewall_Rules_Summary.xlsx`       | Excel report showing suggested firewall rule candidates |

---

Required CSV Columns

The input CSV file should contain the following columns:

```text
source_ip
source_port
destination_ip
destination_port

Example:
source_ip,source_port,destination_ip,destination_port
192.168.1.10,50422,10.10.10.5,443
172.16.4.20,49152,192.168.100.5,445
203.0.113.8,33554,192.168.100.5,3389


Requirements:
python -m pip install pandas openpyxl



How to Run

Place the Python script and CSV file in the same folder.

Then run:

python firewall_analyzer.py

After the script runs, it creates two Excel files in the current directory:

Firewall_Connections_Summary.xlsx
Firewall_Rules_Summary.xlsx
```
