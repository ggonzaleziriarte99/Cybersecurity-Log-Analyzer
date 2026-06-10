import streamlit as st
import pandas as pd
from pathlib import Path
import os
import logging
from src.parser.log_parser import parse_log_file
from src.detection.attack_patterns import analyze_attack_patterns
from src.analysis.security_metrics import compute_security_metrics
from src.visualization.charts import build_charts
from config import (
    LOG_FILE, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_MINUTES,
    SUSPICIOUS_IP_MIN_FAILED, REPORT_PATH
)

logging.basicConfig(level=logging.INFO)

# Configuración de la página
st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar
with st.sidebar:
    st.title("🛡️ Dashboard de Seguridad")
    st.markdown("""
    **Proyecto: Cybersecurity Log Analyzer**
    
    Herramienta de análisis forense y detección de intrusiones basada en logs de autenticación.
    
    ---
    ### Estado del Sistema
    """)
    st.success("Analizador: Activo")
    st.info("Fuente: logs sintéticos")
    st.divider()
    st.warning("⚠️ **Aviso**: Los datos, IPs y usuarios mostrados son ficticios generados para fines de demostración técnica.")

# Título y Descripción
st.title("🔐 Cybersecurity Log Analyzer")
st.markdown("""
Este panel presenta un análisis profundo de los intentos de acceso al servidor, permitiendo identificar ataques de fuerza bruta, 
direcciones IP maliciosas y cuentas de usuario bajo riesgo.
""")

# Procesamiento de datos (reutilizando la lógica de main.py)
@st.cache_data
def load_security_data(log_path):
    """
    Carga y procesa los datos de seguridad.
    Recibe log_path para invalidar caché si el archivo cambia.
    """
    if not os.path.exists(LOG_FILE):
        return None, None, None, None
    
    # Aseguramos que el path sea un string o Path object válido
    df = parse_log_file(Path(log_path))
    if df.empty:
        return df, None, None, None

    patterns = analyze_attack_patterns(
        df,
        brute_threshold=BRUTE_FORCE_THRESHOLD,
        window_minutes=BRUTE_FORCE_WINDOW_MINUTES,
        suspicious_min_failed=SUSPICIOUS_IP_MIN_FAILED,
    )
    
    metrics = compute_security_metrics(df, geo_df=None) # Geo deshabilitado para demo básica
    charts = build_charts(df, metrics)
    
    return df, patterns, metrics, charts

df, patterns, metrics, charts = load_security_data(str(LOG_FILE))

if df is None or df.empty:
    st.error("No se pudo cargar el archivo 'data/auth.log'. Por favor verifica la ruta.")
else:
    # KPIs Principales
    st.subheader("📌 Indicadores Clave de Seguridad (KPIs)")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total de Eventos", len(df))
    m2.metric("Intentos Fallidos", len(df[df["status"].str.lower().str.contains("failed", na=False)]))
    m3.metric("IPs Sospechosas", len(patterns["suspicious_ips"]))
    m4.metric("Usuarios Targeted", df["user"].nunique())

    st.divider()

    # Gráficos
    st.subheader("📊 Visualización de Amenazas")
    g1, g2 = st.columns(2)
    if charts:
        c_events = charts.get("event_types")
        c_severity = charts.get("severity")
        if c_events:
            g1.plotly_chart(c_events, width="stretch")
        if c_severity:
            g2.plotly_chart(c_severity, width="stretch")

    # Tabla de eventos
    st.subheader("🔍 Registro de Eventos Detectados")
    st.dataframe(df, width="stretch")

    # Sección de Hallazgos
    st.divider()
    h1, h2 = st.columns(2)
    with h1:
        st.header("💡 Hallazgos Críticos")
        st.write("Top 5 IPs con comportamiento malicioso:")
        st.table(patterns["suspicious_ips"][:5])
    with h2:
        st.header("📄 Reporte Generado")
        if os.path.exists(REPORT_PATH):
            st.success("Se ha detectado un reporte HTML generado previamente.")
            with open(REPORT_PATH, "rb") as f:
                st.download_button("Descargar Reporte Completo", f, "security_report.html", "text/html")
        else:
            st.info("Ejecuta 'python main.py' para generar el reporte estático.")

# Conclusiones finales
st.header("📝 Resumen de Análisis")
st.info(f"Se recomienda implementar políticas de bloqueo (Fail2Ban) para las {len(patterns['suspicious_ips'])} IPs detectadas con patrones de ataque.")

st.divider()
st.caption("Cybersecurity Log Analyzer - Demo de Portafolio Profesional")