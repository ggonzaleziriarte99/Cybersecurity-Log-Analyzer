from pathlib import Path
import argparse

from config import (
    LOG_FILE,
    REPORT_PATH,
    OUTPUT_DIR,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    SUSPICIOUS_IP_MIN_FAILED,
    GEOLOCATION_ENABLED,
    GEOLOCATION_PROVIDER,
    GEOLOCATION_API_KEY,
)
from src.utils.logger import get_logger
from src.parser.log_parser import parse_log_file
from src.detection.attack_patterns import analyze_attack_patterns
from src.analysis.security_metrics import compute_security_metrics
from src.visualization.charts import build_charts
from src.reporting.report_generator import generate_report, export_csv_reports
from src.enrichment.ip_geolocation import enrich_ip_locations


def run(log_path: Path, report_path: Path) -> None:
    logger = get_logger()
    logger.info("Starting analysis on %s", log_path)

    df = parse_log_file(log_path)
    if df.empty:
        logger.warning("No parsed records. Exiting.")
        print("No parsed records found.")
        return

    patterns = analyze_attack_patterns(
        df,
        brute_threshold=BRUTE_FORCE_THRESHOLD,
        window_minutes=BRUTE_FORCE_WINDOW_MINUTES,
        suspicious_min_failed=SUSPICIOUS_IP_MIN_FAILED,
    )

    geo_df = None
    if GEOLOCATION_ENABLED:
        logger.info("Geolocation enabled: provider=%s", GEOLOCATION_PROVIDER)
        geo_df = enrich_ip_locations(
            df["ip_address"].unique().tolist(),
            provider=GEOLOCATION_PROVIDER,
            api_key=GEOLOCATION_API_KEY,
        )
    else:
        logger.info("Geolocation disabled")

    metrics = compute_security_metrics(df, geo_df=geo_df)
    charts = build_charts(df, metrics)

    generate_report(
        metrics=metrics,
        charts=charts,
        suspicious_ips=patterns["suspicious_ips"],
        top_users=metrics["most_targeted_users"],
        output_path=report_path,
    )

    export_csv_reports(metrics, OUTPUT_DIR)

    logger.info("Report generated at %s", report_path)
    print(f"Report generated: {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cybersecurity Log Analyzer")
    parser.add_argument("--log", type=Path, default=LOG_FILE, help="Path to auth.log")
    parser.add_argument(
        "--report", type=Path, default=REPORT_PATH, help="Path to output HTML report"
    )
    args = parser.parse_args()

    run(args.log, args.report)


if __name__ == "__main__":
    main()
