from pathlib import Path
import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
rows = []
# Baseline normal activity
for i in range(350):
    rows.append({
        "source": f"sample-host-{i%25+1}",
        "duration": max(1, int(rng.normal(35, 12))),
        "src_bytes": max(100, int(rng.normal(18000, 6000))),
        "dst_bytes": max(100, int(rng.normal(24000, 8000))),
        "failed_logins": int(rng.choice([0, 0, 0, 1, 2])),
        "connection_count": max(1, int(rng.normal(18, 7))),
        "unusual_port_flag": 0,
        "label": "Normal"
    })
# Example unusual records for testing the dashboard
for i in range(30):
    rows.append({
        "source": f"test-host-{i+1}",
        "duration": int(rng.integers(1, 8)),
        "src_bytes": int(rng.integers(500000, 3000000)),
        "dst_bytes": int(rng.integers(300000, 2500000)),
        "failed_logins": int(rng.integers(5, 15)),
        "connection_count": int(rng.integers(80, 180)),
        "unusual_port_flag": int(rng.choice([0, 1])),
        "label": "ExampleAnomaly"
    })

out = Path(__file__).parent / "data" / "network_activity.csv"
out.parent.mkdir(exist_ok=True)
pd.DataFrame(rows).to_csv(out, index=False)
print(f"Created {out}")
