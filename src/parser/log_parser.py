import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import pandas as pd

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>[^ ]+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)\s+",
    re.IGNORECASE,
)


def parse_log_line(line: str, year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    if year is None:
        year = datetime.now().year

    month = match.group("month").title()
    day = match.group("day")
    time_str = match.group("time")

    timestamp = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")

    status_raw = match.group("status").lower()
    status = "failed" if status_raw.startswith("failed") else "success"

    return {
        "timestamp": timestamp,
        "user": match.group("user"),
        "ip_address": match.group("ip"),
        "status": status,
        "port": int(match.group("port")),
    }


def parse_log_file(path: Path, year: Optional[int] = None) -> pd.DataFrame:
    records = []
    path = Path(path)
    if not path.exists():
        return pd.DataFrame(columns=["timestamp", "user", "ip_address", "status", "port"])

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = parse_log_line(line, year=year)
        if entry:
            records.append(entry)

    df = pd.DataFrame(records, columns=["timestamp", "user", "ip_address", "status", "port"])
    return df
