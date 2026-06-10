import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"
LOG_FILE = DATA_DIR / "auth.log"
APP_LOG = BASE_DIR / "logs" / "app.log"
REPORT_PATH = OUTPUT_DIR / "index.html"
ATTACK_SUMMARY_CSV = OUTPUT_DIR / "attack_summary.csv"
TOP_ATTACKING_IPS_CSV = OUTPUT_DIR / "top_attacking_ips.csv"
TARGETED_USERS_CSV = OUTPUT_DIR / "targeted_users.csv"

BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 5
SUSPICIOUS_IP_MIN_FAILED = 20

# Optional IP geolocation enrichment
GEOLOCATION_ENABLED = os.getenv("GEOLOCATION_ENABLED", "false").lower() in ("1", "true", "yes")
GEOLOCATION_PROVIDER = os.getenv("GEOLOCATION_PROVIDER", "ipinfo")
GEOLOCATION_API_KEY = os.getenv("GEOLOCATION_API_KEY", "")
