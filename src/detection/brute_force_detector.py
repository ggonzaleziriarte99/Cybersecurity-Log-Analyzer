from typing import Dict, Any

import pandas as pd


def detect_bruteforce(
    df: pd.DataFrame, threshold: int = 10, window_minutes: int = 5
) -> Dict[str, Any]:
    if df.empty:
        return {"suspicious_ips": [], "events": pd.DataFrame()}

    failed = df[df["status"] == "failed"].copy()
    if failed.empty:
        return {"suspicious_ips": [], "events": pd.DataFrame()}

    failed = failed.sort_values("timestamp")
    failed = failed.set_index("timestamp")

    counts = (
        failed.groupby("ip_address")
        .rolling(f"{window_minutes}min")["user"]
        .count()
        .reset_index(name="fail_count")
    )

    events = counts[counts["fail_count"] >= threshold]
    suspicious_ips = sorted(events["ip_address"].unique().tolist())

    return {"suspicious_ips": suspicious_ips, "events": events}


def top_attacking_ips(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    failed = df[df["status"] == "failed"]
    if failed.empty:
        return pd.DataFrame(columns=["ip_address", "failed_attempts"])

    counts = (
        failed.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    return counts.head(top_n)


def top_targeted_users(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    failed = df[df["status"] == "failed"]
    if failed.empty:
        return pd.DataFrame(columns=["user", "failed_attempts"])

    counts = (
        failed.groupby("user")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    return counts.head(top_n)
