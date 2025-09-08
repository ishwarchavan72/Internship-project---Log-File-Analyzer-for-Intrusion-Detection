import re
import os
import pandas as pd

log_pattern = re.compile(r"""
    (?P<ip>\d+\.\d+\.\d+\.\d+)   # IP Address
    \s-\s-\s
    \[(?P<time>.*?)\]            # Timestamp inside []
    \s"
    (?P<method>\w+)              # HTTP Method (GET,POST,etc)
    \s
    (?P<url>\S+)                 # Requested URL 
    \s.*"\s
    (?P<status>\d+)              # HTTP Status code (200,401,etc)
    \s
    (?P<size>\d+)                # Response size in bytes
""", re.VERBOSE)

def parse_logs(logfile):
    # Resolve full path relative to project root (one level above scripts/)
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    full_path = os.path.join(base_path, logfile)

    if not os.path.exists(full_path):
        print(f"[ERROR] File not found: {full_path}")
        return pd.DataFrame()

    parsed_data = []
    with open(full_path, "r") as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                entry = match.groupdict()

                # Convert Apache style time -> datetime
                try:
                    entry["time"] = pd.to_datetime(
                        entry["time"], format="%d/%b/%Y:%H:%M:%S %z"
                    )
                except Exception:
                    entry["time"] = None   # fallback if parsing fails

                parsed_data.append(entry)

    return pd.DataFrame(parsed_data)

if __name__ == "__main__":
    df = parse_logs("data/sample.log")
    if df.empty:
        print("[ERROR] No logs parsed.")
    else:
        print("[OK] First five parsed logs:\n", df.head())

        # Make sure reports folder exists
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        reports_dir = os.path.join(base_path, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        output_file = os.path.join(reports_dir, "parsed_logs.csv")
        df.to_csv(output_file, index=False)
        print(f"✅ Logs saved to {output_file}")
