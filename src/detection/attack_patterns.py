from typing import Dict, Any

import pandas as pd

from src.detection.brute_force_detector import (
    detect_bruteforce,
    top_attacking_ips,
    top_targeted_users,
)
from src.detection.suspicious_ip_detector import detect_suspicious_ips


def analyze_attack_patterns(
    df: pd.DataFrame,
    brute_threshold: int = 10,
    window_minutes: int = 5,
    suspicious_min_failed: int = 20,
    top_n: int = 10,
) -> Dict[str, Any]:
    brute = detect_bruteforce(df, threshold=brute_threshold, window_minutes=window_minutes)
    suspicious_df = detect_suspicious_ips(df, min_failed=suspicious_min_failed)

    top_ips = top_attacking_ips(df, top_n=top_n)
    top_users = top_targeted_users(df, top_n=top_n)

    suspicious_ips = set(brute["suspicious_ips"]) | set(
        suspicious_df["ip_address"].tolist()
    )

    return {
        "brute_force": brute,
        "suspicious_ips": sorted(suspicious_ips),
        "suspicious_ip_df": suspicious_df,
        "top_attacking_ips": top_ips,
        "top_targeted_users": top_users,
    }
