import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

USERS = ["root", "admin", "ubuntu", "deploy", "backup", "app", "guest"]
IPS = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.12",
    "203.0.113.10",
    "198.51.100.23",
    "203.0.113.55",
]
BRUTE_FORCE_IPS = ["203.0.113.77", "198.51.100.88"]


def _random_timestamp(start: datetime, end: datetime) -> datetime:
    delta = end - start
    seconds = random.randint(0, int(delta.total_seconds()))
    return start + timedelta(seconds=seconds)


def _format_log(ts: datetime, status: str, user: str, ip: str, port: int) -> str:
    action = "Failed" if status == "failed" else "Accepted"
    return (
        f"{ts:%b %d %H:%M:%S} server sshd[{random.randint(1000, 9999)}]: "
        f"{action} password for {user} from {ip} port {port} ssh2"
    )


def generate_logs(count: int, output_path: Path) -> None:
    now = datetime.now()
    start = now - timedelta(days=1)

    lines = []
    for _ in range(count):
        ts = _random_timestamp(start, now)
        status = "failed" if random.random() < 0.7 else "success"
        user = random.choice(USERS)
        ip = random.choice(IPS)
        port = random.choice([22, 2222, 2200])
        lines.append(_format_log(ts, status, user, ip, port))

    # Inject brute force bursts
    for ip in BRUTE_FORCE_IPS:
        burst_start = now - timedelta(hours=random.randint(1, 10))
        for i in range(30):
            ts = burst_start + timedelta(seconds=i * 5)
            user = random.choice(USERS)
            lines.append(_format_log(ts, "failed", user, ip, 22))

    lines.sort()
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate fake SSH auth logs")
    parser.add_argument("--count", type=int, default=2000, help="Base number of log lines")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "auth.log",
        help="Output file path",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generate_logs(args.count, output_path)
    print(f"Generated logs at {output_path}")
