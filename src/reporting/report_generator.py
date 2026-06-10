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
        "body { font-family: 'Source Sans Pro', sans-serif; margin: 0; display: flex; background-color: #ffffff; color: #31333F; }",
        ".sidebar { width: 300px; background-color: #f0f2f6; height: 100vh; position: fixed; padding: 2rem 1rem; box-sizing: border-box; overflow-y: auto; }",
        ".main-content { margin-left: 300px; padding: 3rem 5rem; width: 100%; box-sizing: border-box; }",
        "h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 1rem; }",
        "h2 { font-size: 1.75rem; margin-top: 2rem; border-bottom: 1px solid #e6e9ef; padding-bottom: 0.5rem; }",
        ".st-alert { padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; font-size: 0.9rem; }",
        ".st-success { background-color: #d4edda; color: #155724; }",
        ".st-info { background-color: #e7f4ff; color: #004085; }",
        ".st-warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }",
        ".kpi-container { display: flex; gap: 1rem; margin: 2rem 0; }",
        ".kpi-card { flex: 1; padding: 1rem; border: 1px solid #e6e9ef; border-radius: 0.5rem; box-shadow: rgba(0, 0, 0, 0.05) 0px 1px 2px 0px; }",
        ".kpi-label { font-size: 0.8rem; color: #6d7284; }",
        ".kpi-value { font-size: 1.8rem; font-weight: 600; color: #ff4b4b; }",
        ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }",
        "table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }",
        "th { text-align: left; background-color: #f0f2f6; padding: 0.5rem; }",
        "td { padding: 0.5rem; border-bottom: 1px solid #e6e9ef; }",
        ".footer { margin-top: 5rem; padding-top: 2rem; border-top: 1px solid #e6e9ef; color: #6d7284; font-size: 0.8rem; }",
        ".scroll-table { max-height: 400px; overflow-y: auto; border: 1px solid #e6e9ef; border-radius: 0.5rem; }",
        "</style>",
        "</head>",
        "<body>",
        "<div class='sidebar'>",
        "<h2>🛡️ Dashboard de Seguridad</h2>",
        "<p><strong>Proyecto: Cybersecurity Log Analyzer</strong></p>",
        "<p style='font-size: 0.8rem;'>Herramienta de análisis forense y detección de intrusiones basada en logs de autenticación.</p>",
        "<hr>",
        "<h3>Estado del Sistema</h3>",
        "<div class='st-alert st-success'>Analizador: Activo</div>",
        "<div class='st-alert st-info'>Fuente: logs sintéticos</div>",
        "<div class='st-alert st-warning'>⚠️ <strong>Aviso</strong>: Los datos, IPs y usuarios mostrados son ficticios generados para fines de demostración técnica.</div>",
        "</div>",
        
        "<div class='main-content'>",
        "<h1>🔐 Cybersecurity Log Analyzer</h1>",
        "<p>Este panel presenta un análisis profundo de los intentos de acceso al servidor, permitiendo identificar ataques de fuerza bruta, direcciones IP maliciosas y cuentas de usuario bajo riesgo.</p>",
        
        "<h2>📌 Indicadores Clave de Seguridad (KPIs)</h2>",
        _metrics_table(metrics, len(suspicious_ips)),
        
        "<h2>📊 Visualización de Amenazas</h2>",
        "<div class='grid'>",
        "<div>",
        "<h3>Tipos de Eventos</h3>",
        pio.to_html(charts["failed_vs_success"], full_html=False, include_plotlyjs="cdn"),
        "</div>",
        "<div>",
        "<h3>Top IPs Atacantes</h3>",
        pio.to_html(charts["top_ips"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</div>",

        "<h2>🔍 Registro de Eventos Detectados</h2>",
        "<p style='font-size: 0.8rem; color: #6d7284;'>Muestra resumida de la matriz forense y riesgo por IP.</p>",
        "<div class='scroll-table'>",
        _attack_summary_table(metrics.get("attack_summary")),
        "</div>",

        "<div class='grid' style='margin-top: 3rem;'>",
        "<div>",
        "<h2>💡 Hallazgos Críticos</h2>",
        "<p>Top 5 IPs con comportamiento malicioso:</p>",
        _list_block(suspicious_ips[:5], "No se detectaron IPs sospechosas."),
        "</div>",
        "<div>",
        "<h2>📄 Reporte Generado</h2>",
        "<div class='st-alert st-success'>Análisis forense finalizado con éxito.</div>",
        "<p>Este archivo HTML contiene el dataset completo procesado el " + datetime.now().strftime("%Y-%m-%d") + ".</p>",
        "</div>",
        "</div>",

        "<h2>🌍 Contexto Global</h2>",
        "<div class='grid'>",
        "<div>",
        "<h3>Geopolítica de Amenazas</h3>",
        pio.to_html(charts["attacks_by_country"], full_html=False, include_plotlyjs=False),
        "</div>",
        "<div>",
        "<h3>Actividad por Horario</h3>",
        pio.to_html(charts["heatmap"], full_html=False, include_plotlyjs=False),
        "</div>",
        "</div>",

        "<div class='footer'>",
        "<p>Resumen: Se recomienda implementar políticas de bloqueo (Fail2Ban) para las " + str(len(suspicious_ips)) + " IPs detectadas.</p>",
        "<p>Cybersecurity Log Analyzer - Demo de Portafolio Profesional</p>",
        "</div>",
        "</div>",
        "</body>",
        "</html>",
    ]

    output_path.write_text("\n".join(html), encoding="utf-8")
