import pandas as pd


def detect_suspicious_ips(df: pd.DataFrame, min_failed: int = 20) -> pd.DataFrame:
    failed = df[df["status"] == "failed"]
    if failed.empty:
        return pd.DataFrame(columns=["ip_address", "failed_attempts"])

    counts = (
        failed.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    suspicious = counts[counts["failed_attempts"] >= min_failed]
    return suspicious
