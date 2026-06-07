from pathlib import Path
from typing import Dict, Any, List

import plotly.io as pio

from src.utils.helpers import ensure_dir


def _metrics_table(metrics: Dict[str, Any]) -> str:
    rows = [
        ("Total login attempts", metrics.get("total_logins", 0)),
        ("Failed logins", metrics.get("failed_logins", 0)),
        ("Successful logins", metrics.get("successful_logins", 0)),
        ("Unique IPs", metrics.get("unique_ips", 0)),
    ]

    html = ["<table class='metrics'>"]
    html.append("<tr><th>Metric</th><th>Value</th></tr>")
    for label, value in rows:
        html.append(f"<tr><td>{label}</td><td>{value}</td></tr>")
    html.append("</table>")
    return "\n".join(html)


def _list_block(items: List[str], empty_message: str) -> str:
    if not items:
        return f"<p>{empty_message}</p>"
    lis = "".join([f"<li>{item}</li>" for item in items])
    return f"<ul>{lis}</ul>"


def _attack_summary_table(summary_df) -> str:
    if summary_df is None:
        return "<p>No attack data available.</p>"
    if hasattr(summary_df, "empty") and summary_df.empty:
        return "<p>No attack data available.</p>"

    columns = ["ip_address", "failed_attempts", "risk_score"]
    if "country" in summary_df.columns:
        columns.append("country")
    if "city" in summary_df.columns:
        columns.append("city")

    labels = {
        "ip_address": "IP",
        "failed_attempts": "Failed Attempts",
        "risk_score": "Risk Score",
        "country": "Country",
        "city": "City",
    }

    html = ["<table class='metrics'>"]
    header = "".join([f"<th>{labels[col]}</th>" for col in columns])
    html.append(f"<tr>{header}</tr>")

    for _, row in summary_df[columns].iterrows():
        row_html = "".join([f"<td>{row[col]}</td>" for col in columns])
        html.append(f"<tr>{row_html}</tr>")

    html.append("</table>")
    return "\n".join(html)


def export_csv_reports(metrics: Dict[str, Any], output_dir: Path) -> None:
    output_dir = Path(output_dir)
    ensure_dir(output_dir)

    attack_summary = metrics.get("attack_summary", None)
    top_ips = metrics.get("top_attacking_ips", None)
    top_users = metrics.get("most_targeted_users", None)

    if attack_summary is not None:
        attack_summary.to_csv(output_dir / "attack_summary.csv", index=False)
    if top_ips is not None:
        top_ips.to_csv(output_dir / "top_attacking_ips.csv", index=False)
    if top_users is not None:
        top_users.to_csv(output_dir / "targeted_users.csv", index=False)


def generate_report(
    metrics: Dict[str, Any],
    charts: Dict[str, Any],
    suspicious_ips: List[str],
    top_users,
    output_path: Path,
) -> None:
    output_path = Path(output_path)
    ensure_dir(output_path.parent)

    top_users_list = []
    if hasattr(top_users, "empty") and not top_users.empty:
        top_users_list = top_users["user"].tolist()

    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>Security Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 30px; color: #111; }",
        "h1, h2 { color: #0b3d91; }",
        ".section { margin-bottom: 28px; }",
        "table.metrics { border-collapse: collapse; width: 420px; }",
        "table.metrics th, table.metrics td { border: 1px solid #ccc; padding: 8px; }",
        "table.metrics th { background: #f1f1f1; text-align: left; }",
        "ul { padding-left: 18px; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Cybersecurity Log Analyzer Report</h1>",
        "<div class='section'>",
        "<h2>Summary Metrics</h2>",
        _metrics_table(metrics),
        "</div>",
        "<div class='section'>",
        "<h2>Suspicious IPs</h2>",
        _list_block(suspicious_ips, "No suspicious IPs detected."),
        "</div>",
        "<div class='section'>",
        "<h2>Most Targeted Users</h2>",
        _list_block(top_users_list, "No targeted users detected."),
        "</div>",
        "<div class='section'>",
        "<h2>Risk Scores by IP</h2>",
        _attack_summary_table(metrics.get("attack_summary")),
        "</div>",
        "<div class='section'>",
        "<h2>Top Attacking IPs</h2>",
        pio.to_html(charts["top_ips"], full_html=False, include_plotlyjs="cdn"),
        "</div>",
        "<div class='section'>",
        "<h2>Failed vs Successful Logins</h2>",
        pio.to_html(charts["failed_vs_success"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div class='section'>",
        "<h2>Attacks Over Time</h2>",
        pio.to_html(charts["attacks_over_time"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div class='section'>",
        "<h2>Most Targeted Users (Chart)</h2>",
        pio.to_html(charts["top_users"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div class='section'>",
        "<h2>Attacks by Country</h2>",
        pio.to_html(charts["attacks_by_country"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div class='section'>",
        "<h2>Activity Heatmap</h2>",
        pio.to_html(charts["heatmap"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</body>",
        "</html>",
    ]

    output_path.write_text("\n".join(html), encoding="utf-8")
