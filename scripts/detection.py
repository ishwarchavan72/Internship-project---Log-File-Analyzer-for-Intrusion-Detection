import os
import pandas as pd

# Resolve paths based on project root folder
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
csv_path = os.path.join(project_root, "reports", "parsed_logs.csv")
reports_dir = os.path.join(project_root, "reports")

if not os.path.exists(csv_path):
    print(f"[ERROR] parsed_logs.csv not found at {csv_path}")
    print("Run parser.py first.")
    exit(1)

# Load parsed logs
try:
    df = pd.read_csv(csv_path)
except Exception as e:
    print(f"[ERROR] Could not read parsed_logs.csv: {e}")
    exit(1)

if df.empty:
    print("⚠️ parsed_logs.csv is empty. No logs to analyze.")
    exit(1)

# Convert time column to datetime and drop rows with invalid time
df['time'] = pd.to_datetime(df['time'], errors='coerce')
df.dropna(subset=['time'], inplace=True)

suspicious = []

# --- Basic brute-force detection: flag any 401 or 403 ---
for _, row in df.iterrows():
    if str(row['status']) in ['401', '403']:
        suspicious.append({**row, 'reason': 'Failed login / brute-force'})

# --- Burst brute-force detection (more than 3 fails in 5 min window) ---
failed = df[df['status'].isin([401, 403])].copy()
failed.set_index('time', inplace=True)

# Group by 5 minute windows and IP, count occurrences
failed_count = failed.groupby([pd.Grouper(freq='5Min'), 'ip']).size().reset_index(name='count')

# Find IPs with more than 3 failed attempts in any 5-minute window
flagged_ips = failed_count[failed_count['count'] > 3]['ip'].unique()

# Append additional suspicious rows for flagged IPs (burst detection)
for ip in flagged_ips:
    ip_failed = failed[failed['ip'] == ip]
    for _, row in ip_failed.iterrows():
        suspicious.append({**row, 'reason': 'Brute-force attempt (burst detection)'})

# --- SQL Injection detection ---
for _, row in df.iterrows():
    url = str(row['url'])
    if any(x in url for x in ["'", " OR ", "--", "UNION", "SELECT"]):
        suspicious.append({**row, 'reason': 'SQL Injection attempt'})

# --- XSS detection ---
for _, row in df.iterrows():
    url = str(row['url'])
    if "<script>" in url.lower():
        suspicious.append({**row, 'reason': 'XSS attempt'})

# --- DoS detection (High traffic from single IP) ---
dos_ips = df['ip'].value_counts()
dos_ips = dos_ips[dos_ips > 30].index.tolist()  # Threshold: 30 requests (adjustable)

# Append DoS flagged rows
for ip in dos_ips:
    ip_rows = df[df['ip'] == ip].to_dict(orient='records')
    for row in ip_rows:
        suspicious.append({**row, 'reason': 'DoS - High traffic from single IP'})

# Remove duplicates (some rows might appear multiple times)
df_suspicious = pd.DataFrame(suspicious).drop_duplicates()

# Ensure reports directory exists
os.makedirs(reports_dir, exist_ok=True)

# Save suspicious logs CSV if not empty
if not df_suspicious.empty:
    suspicious_csv_path = os.path.join(reports_dir, "suspicious_logs.csv")
    df_suspicious.to_csv(suspicious_csv_path, index=False)
    print(f"✅ Suspicious logs saved: {suspicious_csv_path}")
else:
    print("No suspicious logs detected.")

# Write incident summary report
incident_report_path = os.path.join(reports_dir, "incident_report.csv")
with open(incident_report_path, "w") as report:
    report.write("=== INCIDENT REPORT ===\n")
    report.write(f"Total suspicious events detected: {len(df_suspicious)}\n")
    report.write(f"Unique IPs involved: {df_suspicious['ip'].nunique() if not df_suspicious.empty else 0}\n")
    report.write("\n")

    if not df_suspicious.empty:
        # Group incidents by reason
        for reason in df_suspicious['reason'].unique():
            report.write(f"--- {reason.upper()} ---\n")
            subset = df_suspicious[df_suspicious['reason'] == reason].head(10)
            for _, row in subset.iterrows():
                report.write(
                    f"IP: {row['ip']} | Time: {row['time']} | URL: {row['url']}\n"
                )
            report.write("\n")

print(f"✅ Incident report saved: {incident_report_path}")
