from pathlib import Path
from typing import Dict, Any, List

import plotly.io as pio

from src.utils.helpers import ensure_dir


def _metrics_table(metrics: Dict[str, Any], suspicious_count: int) -> str:
    kpis = [
        ("Total de Eventos", metrics.get("total_logins", 0)),
        ("Intentos Fallidos", metrics.get("failed_logins", 0)),
        ("IPs Sospechosas", suspicious_count),
        ("Usuarios Targeted", metrics.get("unique_users", 0)),
    ]

    html = ["<div class='kpi-container'>"]
    for label, value in kpis:
        html.append(f"<div class='kpi-card'><div class='kpi-label'>{label}</div><div class='kpi-value'>{value}</div></div>")
    html.append("</div>")
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

    for _, row in summary_df[columns].head(10).iterrows():
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
        "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fb; color: #31333f; }",
        ".container { max-width: 1200px; margin: auto; }",
        "h1 { color: #1f1f1f; border-bottom: 2px solid #e6e9ef; padding-bottom: 10px; margin-bottom: 20px; }",
        "h2 { color: #262730; margin-top: 40px; font-size: 1.5rem; }",
        ".kpi-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }",
        ".kpi-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border: 1px solid #e6e9ef; text-align: center; }",
        ".kpi-label { font-size: 0.9rem; color: #6d7284; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }",
        ".kpi-value { font-size: 2.2rem; font-weight: bold; color: #ff4b4b; }",
        ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 25px; margin-bottom: 25px; }",
        ".card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border: 1px solid #e6e9ef; }",
        "table.metrics { border-collapse: collapse; width: 100%; margin-top: 15px; }",
        "table.metrics th, table.metrics td { text-align: left; padding: 12px; border-bottom: 1px solid #f0f2f6; }",
        "table.metrics th { background-color: #f8f9fb; color: #555; font-size: 0.85rem; text-transform: uppercase; }",
        "ul { padding-left: 20px; line-height: 1.5; }",
        ".status-info { background-color: #e7f4ff; border-left: 5px solid #007bff; padding: 15px; margin-bottom: 30px; border-radius: 8px; font-size: 0.95rem; }",
        "</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        "<h1>🛡️ Cybersecurity Log Analyzer</h1>",
        "<div class='status-info'><strong>Estado del Sistema:</strong> Análisis forense de logs de autenticación finalizado con éxito.</div>",
        
        "<div class='section'>",
        "<h2>📌 Indicadores Clave de Seguridad</h2>",
        _metrics_table(metrics, len(suspicious_ips) if suspicious_ips else 0),
        "</div>",

        "<div class='grid'>",
        "<div class='card'>",
        "<h3>📊 Distribución de Eventos</h3>",
        pio.to_html(charts["failed_vs_success"], full_html=False, include_plotlyjs="cdn"),
        "</div>",
        "<div class='card'>",
        "<h3>📈 Línea de Tiempo de Ataques</h3>",
        pio.to_html(charts["attacks_over_time"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</div>",

        "<div class='grid'>",
        "<div class='card'>",
        "<h3>🌍 Geopolítica de Amenazas</h3>",
        pio.to_html(charts["attacks_by_country"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div class='card'>",
        "<h3>🔥 Mapa de Calor de Actividad</h3>",
        pio.to_html(charts["heatmap"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</div>",

        "<div class='grid'>",
        "<div class='card'>",
        "<h3>🔍 IPs con Comportamiento Malicioso</h3>",
        _list_block(suspicious_ips, "No se detectaron IPs sospechosas."),
        "</div>",
        "<div class='card'>",
        "<h3>👥 Cuentas de Usuario en Riesgo</h3>",
        _list_block(top_users_list, "No se detectaron usuarios objetivo."),
        "</div>",
        "</div>",

        "<div class='card'>",
        "<h3>⚖️ Matriz Forense y Riesgo por IP</h3>",
        _attack_summary_table(metrics.get("attack_summary")),
        "</div>",

        "<div class='grid' style='margin-top: 25px;'>",
        "<div class='card'>",
        "<h3>Top 10 IPs Atacantes</h3>",
        pio.to_html(charts["top_ips"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</div>",

        "</div>",
        "</body>",
        "</html>",
    ]

    output_path.write_text("\n".join(html), encoding="utf-8")
