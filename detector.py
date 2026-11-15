import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = [
    "duration", "src_bytes", "dst_bytes", "failed_logins",
    "connection_count", "unusual_port_flag"
]

def train_model(training_df):
    """Train only on rows marked Normal, if a label column is present."""
    df = training_df.copy()
    if "label" in df.columns:
        df = df[df["label"].astype(str).str.lower().eq("normal")]
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0)
    if len(X) < 20:
        raise ValueError("At least 20 normal training rows are required.")
    model = IsolationForest(
        n_estimators=150, contamination=0.08, random_state=42
    )
    model.fit(X)
    return model

def analyze(model, input_df):
    missing = [c for c in FEATURES if c not in input_df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    df = input_df.copy()
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0)
    predictions = model.predict(X)  # 1 = typical, -1 = anomaly
    raw_scores = model.decision_function(X)
    # Convert model output into an easy-to-read relative anomaly score.
    scores = (1 - raw_scores)
    df["anomaly_score"] = scores.round(4)
    df["classification"] = ["Suspicious" if p == -1 else "Normal" for p in predictions]

    def reason(row):
        notes = []
        if row["failed_logins"] >= 5:
            notes.append("many failed login attempts")
        if row["connection_count"] >= 80:
            notes.append("unusually high connection count")
        if row["unusual_port_flag"] == 1:
            notes.append("unusual port flag is set")
        if row["src_bytes"] + row["dst_bytes"] > 2_000_000:
            notes.append("large data transfer")
        return ", ".join(notes) if notes else "unusual combination of activity features"

    df["reason"] = df.apply(reason, axis=1)
    df["risk_level"] = "Low"
    df.loc[df["classification"] == "Suspicious", "risk_level"] = "Medium"
    df.loc[
        (df["classification"] == "Suspicious") &
        ((df["failed_logins"] >= 8) | (df["connection_count"] >= 120) |
         (df["unusual_port_flag"] == 1)),
        "risk_level"
    ] = "High"
    return df
