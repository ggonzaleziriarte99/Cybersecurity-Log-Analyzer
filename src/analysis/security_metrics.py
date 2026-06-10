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
        return _empty_metrics()

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    failed_df = df[df["status"] == "failed"].copy()
    success_count = int((df["status"] == "success").sum())

    if not failed_df.empty:
        attack_summary = failed_df.groupby("ip_address").size().reset_index(name="failed_attempts").sort_values("failed_attempts", ascending=False)
        attack_summary["risk_score"] = attack_summary["failed_attempts"].apply(_risk_score)
        top_ips = attack_summary.head(10)[["ip_address", "failed_attempts"]]
        top_users = failed_df.groupby("user").size().reset_index(name="failed_attempts").sort_values("failed_attempts", ascending=False).head(10)
        attacks_per_hour = failed_df.set_index("timestamp").resample("h").size().reset_index(name="failed_attempts")
        failed_df["hour"] = failed_df["timestamp"].dt.hour
        failed_df["day"] = failed_df["timestamp"].dt.dayofweek
        heatmap = failed_df.groupby(["day", "hour"]).size().reset_index(name="failed_attempts")
        
        if geo_df is not None and not geo_df.empty:
            merged = failed_df.merge(geo_df, on="ip_address", how="left")
            merged["country"] = merged["country"].fillna("Unknown")
            attacks_by_country = merged.groupby("country").size().reset_index(name="failed_attempts").sort_values("failed_attempts", ascending=False)
            attack_summary = attack_summary.merge(geo_df, on="ip_address", how="left")
            for col in ["country", "city"]: attack_summary[col] = attack_summary[col].fillna("Unknown")
        else:
            attacks_by_country = pd.DataFrame(columns=["country", "failed_attempts"])
            attack_summary["country"], attack_summary["city"] = "Unknown", "Unknown"
    else:
        return _empty_metrics(len(df), success_count, df["ip_address"].nunique(), df["user"].nunique())

    return {
        "total_logins": len(df),
        "failed_logins": len(failed_df),
        "successful_logins": success_count,
        "unique_ips": int(df["ip_address"].nunique()),
        "unique_users": int(df["user"].nunique()),
        "top_attacking_ips": top_ips,
        "attack_summary": attack_summary,
        "most_targeted_users": top_users,
        "attacks_per_hour": attacks_per_hour,
        "heatmap": heatmap,
        "attacks_by_country": attacks_by_country,
    }

def _empty_metrics(total=0, success=0, ips=0, users=0) -> Dict[str, Any]:
    return {
        "total_logins": total, "failed_logins": total - success, "successful_logins": success,
        "unique_ips": ips, "unique_users": users,
        "top_attacking_ips": pd.DataFrame(columns=["ip_address", "failed_attempts"]),
        "attack_summary": pd.DataFrame(columns=["ip_address", "failed_attempts", "risk_score", "country", "city"]),
        "most_targeted_users": pd.DataFrame(columns=["user", "failed_attempts"]),
        "attacks_per_hour": pd.DataFrame(columns=["timestamp", "failed_attempts"]),
        "heatmap": pd.DataFrame(columns=["day", "hour", "failed_attempts"]),
        "attacks_by_country": pd.DataFrame(columns=["country", "failed_attempts"]),
    }
