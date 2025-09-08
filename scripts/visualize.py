import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Set style
sns.set(style="whitegrid")
plt.rcParams["figure.figsize"] = (10, 6)

# Resolve paths based on project root
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
reports_dir = os.path.join(project_root, "reports")
plots_dir = os.path.join(reports_dir, "plots")

# Create output folder if it doesn't exist
os.makedirs(plots_dir, exist_ok=True)

# Load parsed logs
parsed_logs_path = os.path.join(reports_dir, "parsed_logs.csv")
try:
    df_logs = pd.read_csv(parsed_logs_path)
except FileNotFoundError:
    print(f"❌ parsed_logs.csv not found at {parsed_logs_path}. Run parser.py first.")
    exit()

# Load suspicious logs if available
suspicious_logs_path = os.path.join(reports_dir, "suspicious_logs.csv")
try:
    df_suspicious = pd.read_csv(suspicious_logs_path)
except FileNotFoundError:
    df_suspicious = pd.DataFrame()

# Convert time to datetime
df_logs['time'] = pd.to_datetime(df_logs['time'], errors='coerce')
df_logs.dropna(subset=['time'], inplace=True)

# =============================
#  Top 10 IPs by request count
# =============================
top_ips = df_logs['ip'].value_counts().head(10)
df_top_ips = top_ips.reset_index()
df_top_ips.columns = ['ip', 'count']

plt.figure()
sns.barplot(data=df_top_ips, x='count', y='ip', hue='ip', palette='viridis', dodge=False, legend=False)
plt.title("Top 10 IPs by Request Count")
plt.xlabel("Number of Requests")
plt.ylabel("IP Address")
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "top_10_ips.png"))
print(f"📌 Saved: Top 10 IPs plot → {os.path.join('reports', 'plots', 'top_10_ips.png')}")

# =============================
# Attack type distribution 
# =============================
if not df_suspicious.empty and 'reason' in df_suspicious.columns:
    attack_counts = df_suspicious['reason'].value_counts()

    plt.figure()
    plt.pie(
        attack_counts.values,
        labels=attack_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=sns.color_palette("magma", n_colors=len(attack_counts))
    )
    plt.title("Attack Type Distribution (Pie Chart)")
    plt.axis('equal')  # Make sure pie is a circle
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, "attack_distribution.png"))
    print(f"📌 Saved: Attack type distribution (pie chart) → {os.path.join('reports', 'plots', 'attack_distribution.png')}")
else:
    print("⚠️ No suspicious log data found. Skipping attack distribution plot.")

# =============================
#  HTTP Status Code Distribution
# =============================
status_counts = df_logs['status'].astype(str).value_counts()
df_status = status_counts.reset_index()
df_status.columns = ['status', 'count']

plt.figure()
plt.pie(
    status_counts.values,
    labels=status_counts.index,
    autopct='%1.1f%%',
    startangle=140,
    colors=sns.color_palette("pastel", n_colors=len(status_counts))
)
plt.title("HTTP Status Code Distribution (Pie Chart)")
plt.axis('equal')  # Make the pie chart a circle
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "status_distribution.png"))
print(f"📌 Saved: Status code distribution (pie chart) → {os.path.join('reports', 'plots', 'status_distribution.png')}")

# =============================
# Requests Per Minute
# =============================
df_logs['minute'] = df_logs['time'].dt.floor('min')
requests_per_min = df_logs.groupby('minute').size()

plt.figure()
requests_per_min.plot(kind='line', color='blue')
plt.title("Requests per Minute")
plt.xlabel("Time")
plt.ylabel("Number of Requests")
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "requests_per_minute.png"))
print(f"📌 Saved: Requests per minute plot → {os.path.join('reports', 'plots', 'requests_per_minute.png')}")

# =============================
#  DoS Detection Plot (High Traffic IPs)
# =============================
dos_threshold = 30  # Same as in detection.py
ip_counts = df_logs['ip'].value_counts()
dos_candidates = ip_counts[ip_counts > dos_threshold].head(10)

if not dos_candidates.empty:
    plt.figure()
    sns.barplot(x=dos_candidates.values, y=dos_candidates.index, palette="flare")
    plt.title(f"Top IPs by Traffic (>{dos_threshold} requests)")
    plt.xlabel("Number of Requests")
    plt.ylabel("IP Address")
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, "dos_candidates.png"))
    print(f"📌 Saved: DoS candidate IPs → {os.path.join('reports', 'plots', 'dos_candidates.png')}")
else:
    print("✅ No IPs exceeded DoS threshold in logs.")

print("\n✅ All visualizations saved in: reports/plots/")
