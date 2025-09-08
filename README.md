# Log File Analyzer for Intrusion Detection

## Overview
This project is a Python-based tool designed to parse web server logs (Apache style), detect suspicious activity indicative of cyber attacks, and visualize access patterns. It helps identify brute-force attempts, SQL injection, XSS, and DoS attacks.

---

## Features
- Parse Apache-style access logs into structured data  
- Detect suspicious events based on HTTP status codes and malicious URL patterns  
- Detect high-volume IP traffic (DoS detection)  
- Generate incident reports summarizing detected threats  
- Visualize access patterns with graphs (top IPs, attack types, HTTP statuses, request rates)  
- Export CSV reports and PNG plots for analysis  

---

## Tools & Libraries

| Tool / Library | Purpose                 |
|----------------|-------------------------|
| Python 3.x     | Core scripting          |
| pandas         | Data manipulation       |
| matplotlib     | Plots and graphs        |
| seaborn        | Enhanced visualizations |
| re (regex)     | Log parsing             |

---

## File Structure

```

log\_analyzer/
├── data/
│   └── sample.log                 # Sample log file to analyze
├── reports/
│   ├── parsed\_logs.csv            # Parsed log data
│   ├── suspicious\_logs.csv        # Detected suspicious events
│   ├── incident\_report.csv        # Summary report of incidents
│   └── plots/                    # Visualization PNG files
├── scripts/
│   ├── parser.py                 # Parses raw logs into CSV
│   ├── detection.py              # Detects suspicious activity
│   └── visualise.py              # Generates plots from logs
├── Report.pdf
├── requirements.txt              # Python dependencies
└── README.md                    # Project documentation


````

---

## Setup Instructions

1. **Clone or download the repository**

2. **Install dependencies**

```bash
pip install -r requirements.txt
````

3. **Run the analysis**

* Place your Apache log file in `data/sample.log`

* Parse logs:

```bash
python scripts/parser.py
```

* Detect threats:

```bash
python scripts/detection.py
```

* Visualize results:

```bash
python scripts/visualise.py
```

---

## Outputs

* Parsed logs: `reports/parsed_logs.csv`
* Suspicious logs: `reports/suspicious_logs.csv`
* Incident report: `reports/incident_report.csv`
* Visualizations: PNG files inside `reports/plots/`
* Project report document: `/Report.pdf`

---

## Detection Rules

* **Brute-force attempts:** Repeated failed login HTTP codes (401, 403)
* **SQL Injection attempts:** URLs containing SQL keywords or suspicious characters (`'`, `--`, `OR`, `SELECT`, `UNION`)
* **Cross-site scripting (XSS):** URLs containing `<script>` tags
* **Denial of Service (DoS):** High volume of requests from a single IP (threshold configurable)

---

## Notes

* The tool currently supports Apache-style log formats.
* Time parsing assumes log timestamps in format `[day/Mon/year:HH:MM:SS zone]`.
* You can customize detection rules inside `scripts/detection.py`.
* For large logs, parsing and detection may take some time; performance optimizations are possible.

---

## License

This project is released under the MIT License.

---