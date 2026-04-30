# 🛡️ Log Analyzer / Threat Hunter

A Python-based defensive security tool that ingests Apache access logs, detects attack patterns using custom detection rules, and generates a fully self-contained visual HTML threat report.

Built from scratch as an independent cybersecurity research project — no frameworks, no shortcuts.

---

## 📸 Report Preview

> Run the tool and open `report.html` in any browser to see the full interactive report with embedded charts and alert tables.

---

## 🏗️ Architecture

The tool is split into four clean layers:

```
sample_access.log
       │
       ▼
┌─────────────────┐
│  Ingestion.py   │  Parses raw log lines into structured objects
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Detection.py   │  Applies detection rules, builds alert list
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  reporting.py   │  Generates charts and HTML threat report
└─────────────────┘
```

---

## 🔍 Detection Rules

| Rule | Method | Severity |
|------|--------|----------|
| **Brute Force** | Count of 401s + time window (≥5 attempts in 60s) | 🔴 High |
| **SQL Injection** | Regex pattern matching on request URL (UNION, SELECT, DROP, --) | 🔴 High |
| **Directory Traversal** | Pattern matching for `../`, `/etc/passwd`, `/bin/sh` | 🟠 Medium |
| **Scanner User Agent** | Known tool fingerprints (sqlmap, Nikto, Nmap) | 🟠 Medium |

---

## 📊 Report Output

The HTML report includes:
- **Summary cards** — total alerts, IPs analyzed, top offender, attack types
- **Alerts by attack type** — bar chart
- **Alerts by IP address** — bar chart  
- **Total requests per IP** — traffic volume chart
- **Alert timeline** — attacks plotted over time
- **Full alert table** — every triggered rule with IP, timestamp, method, and user agent

All charts are embedded as base64 — the report is fully self-contained, no external files needed.

---

## 🚀 Usage

**1. Clone the repo**
```bash
git clone https://github.com/AbhiramInguva/log-analysis.git
cd log-analysis
```

**2. Install dependencies**
```bash
pip install matplotlib pandas
```

**3. Run detection**
```bash
python Detection.py
```

**4. Generate report**
```bash
python reporting.py
```

**5. Open the report**
```bash
open report.html   # macOS
xdg-open report.html  # Linux
```

---

## 📁 Project Structure

```
log-analysis/
├── Ingestion.py        # Log parser — extracts fields into objects
├── Detection.py        # Detection engine — brute force, SQLi, traversal, scanners
├── reporting.py        # Report generator — charts + HTML output
├── sample_access.log   # Sample log with real attack patterns baked in
└── README.md
```

---

## 🧪 Sample Log

The included `sample_access.log` contains deliberately crafted attack patterns for testing:

- `10.0.0.5` — Brute force attack (12 attempts in 22 seconds)
- `10.0.0.9` — SQL injection attempts (UNION SELECT, DROP TABLE, auth bypass)
- `10.0.0.7` — Directory traversal attempts (`/etc/passwd`, `/etc/shadow`)
- `10.0.0.11` — Scanner fingerprints (sqlmap, Nikto)
- `10.0.0.13` — Directory scan (10 sensitive paths in 9 seconds)
- `10.0.0.15` — Cleartext credentials over HTTP
- `192.168.1.x` — Normal legitimate traffic (should produce no alerts)

---

## 🛣️ Roadmap

- [ ] CLI interface with `argparse` (custom file, threshold, output path)
- [ ] Live mode — tail log file and alert in real time
- [ ] Cleartext credential detection
- [ ] Directory scan detection
- [ ] IPv6 support
- [ ] Whitelist support for known safe IPs

---

## 🔧 Built With

- Python 3
- `re` — regex parsing
- `datetime` — timestamp analysis
- `pandas` — data aggregation
- `matplotlib` — chart generation

---

## ⚠️ Disclaimer

This tool is built for educational and defensive security research purposes. Only run against log files from systems you own or have explicit permission to analyze.

---

## 👤 Author

**Abhiram Inguva**  
Cybersecurity enthusiast | GITAM School of Business  
[GitHub](https://github.com/AbhiramInguva)
