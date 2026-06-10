from typing import Dict, Any, Optional

import pandas as pd


def _risk_score(failed_attempts: int) -> str:
    if failed_attempts <= 5:
        return "LOW"
    if failed_attempts <= 20:
        return "MEDIUM"
    return "HIGH"


def compute_security_metrics(df: pd.DataFrame, geo_df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
    if df.empty:
        return {
            "total_logins": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "unique_ips": 0,
            "unique_users": 0,
            "top_attacking_ips": pd.DataFrame(columns=["ip_address", "failed_attempts"]),
            "attack_summary": pd.DataFrame(
                columns=["ip_address", "failed_attempts", "risk_score", "country", "city"]
            ),
            "most_targeted_users": pd.DataFrame(columns=["user", "failed_attempts"]),
            "attacks_per_hour": pd.DataFrame(columns=["timestamp", "failed_attempts"]),
            "heatmap": pd.DataFrame(columns=["day", "hour", "failed_attempts"]),
            "attacks_by_country": pd.DataFrame(columns=["country", "failed_attempts"]),
        }

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    total = len(df)
    failed = int((df["status"] == "failed").sum())
    success = int((df["status"] == "success").sum())
    unique_ips = int(df["ip_address"].nunique())
    unique_users = int(df["user"].nunique())

    failed_df = df[df["status"] == "failed"].copy()

    if failed_df.empty:
        attack_summary = pd.DataFrame(
            columns=["ip_address", "failed_attempts", "risk_score", "country", "city"]
        )
        top_ips = pd.DataFrame(columns=["ip_address", "failed_attempts"])
    else:
        attack_summary = (
            failed_df.groupby("ip_address")
            .size()
            .reset_index(name="failed_attempts")
            .sort_values("failed_attempts", ascending=False)
        )
        attack_summary["risk_score"] = attack_summary["failed_attempts"].apply(_risk_score)
        top_ips = attack_summary[["ip_address", "failed_attempts"]].head(10)

    top_users = (
        failed_df.groupby("user")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
        .head(10)
    )

    if failed_df.empty:
        attacks_per_hour = pd.DataFrame(columns=["timestamp", "failed_attempts"])
        heatmap = pd.DataFrame(columns=["day", "hour", "failed_attempts"])
        attacks_by_country = pd.DataFrame(columns=["country", "failed_attempts"])
    else:
        attacks_per_hour = (
            failed_df.set_index("timestamp")
            .resample("h")
            .size()
            .reset_index(name="failed_attempts")
        )

        failed_df["hour"] = failed_df["timestamp"].dt.hour
        failed_df["day"] = failed_df["timestamp"].dt.dayofweek
        heatmap = (
            failed_df.groupby(["day", "hour"]).size().reset_index(name="failed_attempts")
        )

        if geo_df is not None and not geo_df.empty:
            merged = failed_df.merge(geo_df, on="ip_address", how="left")
            merged["country"] = merged["country"].fillna("Unknown")
            merged["city"] = merged["city"].fillna("Unknown")
            attacks_by_country = (
                merged.groupby("country")
                .size()
                .reset_index(name="failed_attempts")
                .sort_values("failed_attempts", ascending=False)
            )
            attack_summary = attack_summary.merge(geo_df, on="ip_address", how="left")
            attack_summary["country"] = attack_summary["country"].fillna("Unknown")
            attack_summary["city"] = attack_summary["city"].fillna("Unknown")
        else:
            attacks_by_country = pd.DataFrame(columns=["country", "failed_attempts"])
            attack_summary["country"] = "Unknown"
            attack_summary["city"] = "Unknown"

    return {
        "total_logins": total,
        "failed_logins": failed,
        "successful_logins": success,
        "unique_ips": unique_ips,
        "unique_users": unique_users,
        "top_attacking_ips": top_ips,
        "attack_summary": attack_summary,
        "most_targeted_users": top_users,
        "attacks_per_hour": attacks_per_hour,
        "heatmap": heatmap,
        "attacks_by_country": attacks_by_country,
    }
