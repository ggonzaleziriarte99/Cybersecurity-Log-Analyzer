from datetime import datetime, timedelta
from pathlib import Path
import sys

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.parser.log_parser import parse_log_line
from src.detection.brute_force_detector import detect_bruteforce
from src.analysis.security_metrics import compute_security_metrics


def test_parse_log_line_failed():
    line = (
        "Jan 10 10:15:32 server sshd[12345]: Failed password for root "
        "from 192.168.1.25 port 22 ssh2"
    )
    entry = parse_log_line(line, year=2026)
    assert entry is not None
    assert entry["status"] == "failed"
    assert entry["user"] == "root"
    assert entry["ip_address"] == "192.168.1.25"
    assert entry["port"] == 22
    assert entry["timestamp"].year == 2026


def test_parse_log_line_success():
    line = (
        "Jan 10 10:15:32 server sshd[12345]: Accepted password for ubuntu "
        "from 10.0.0.5 port 2222 ssh2"
    )
    entry = parse_log_line(line, year=2026)
    assert entry is not None
    assert entry["status"] == "success"
    assert entry["user"] == "ubuntu"
    assert entry["ip_address"] == "10.0.0.5"
    assert entry["port"] == 2222


def test_detect_bruteforce():
    base_time = datetime(2026, 1, 10, 10, 0, 0)
    rows = []
    for i in range(5):
        rows.append(
            {
                "timestamp": base_time + timedelta(seconds=i * 30),
                "user": "root",
                "ip_address": "203.0.113.77",
                "status": "failed",
                "port": 22,
            }
        )

    df = pd.DataFrame(rows)
    result = detect_bruteforce(df, threshold=4, window_minutes=5)
    assert "203.0.113.77" in result["suspicious_ips"]


def test_risk_score_buckets():
    base_time = datetime(2026, 1, 10, 10, 0, 0)
    rows = []
    rows.extend(
        [
            {
                "timestamp": base_time + timedelta(seconds=i),
                "user": "root",
                "ip_address": "10.0.0.1",
                "status": "failed",
                "port": 22,
            }
            for i in range(3)
        ]
    )
    rows.extend(
        [
            {
                "timestamp": base_time + timedelta(seconds=100 + i),
                "user": "root",
                "ip_address": "10.0.0.2",
                "status": "failed",
                "port": 22,
            }
            for i in range(10)
        ]
    )
    rows.extend(
        [
            {
                "timestamp": base_time + timedelta(seconds=200 + i),
                "user": "root",
                "ip_address": "10.0.0.3",
                "status": "failed",
                "port": 22,
            }
            for i in range(25)
        ]
    )

    df = pd.DataFrame(rows)
    metrics = compute_security_metrics(df)
    summary = metrics["attack_summary"]
    scores = dict(zip(summary["ip_address"], summary["risk_score"]))

    assert scores["10.0.0.1"] == "LOW"
    assert scores["10.0.0.2"] == "MEDIUM"
    assert scores["10.0.0.3"] == "HIGH"
