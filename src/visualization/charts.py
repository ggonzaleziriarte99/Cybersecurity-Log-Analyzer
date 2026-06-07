from typing import Dict, Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def _empty_fig(title: str, message: str = "No data") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, x=0.5, y=0.5, showarrow=False)
    fig.update_layout(title=title)
    return fig


def chart_top_ips(top_ips_df: pd.DataFrame) -> go.Figure:
    if top_ips_df.empty:
        return _empty_fig("Top attacking IPs")
    fig = px.bar(
        top_ips_df,
        x="ip_address",
        y="failed_attempts",
        title="Top attacking IPs",
        labels={"failed_attempts": "Failed attempts", "ip_address": "IP address"},
    )
    return fig


def chart_failed_vs_success(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return _empty_fig("Failed vs Successful logins")
    counts = df["status"].value_counts().rename_axis("status").reset_index(name="count")
    fig = px.bar(
        counts,
        x="status",
        y="count",
        title="Failed vs Successful logins",
        labels={"count": "Total", "status": "Status"},
    )
    return fig


def chart_attacks_over_time(attacks_per_hour: pd.DataFrame) -> go.Figure:
    if attacks_per_hour.empty:
        return _empty_fig("Attacks over time")
    fig = px.line(
        attacks_per_hour,
        x="timestamp",
        y="failed_attempts",
        title="Attacks over time",
        labels={"failed_attempts": "Failed attempts", "timestamp": "Time"},
    )
    return fig


def chart_top_users(top_users_df: pd.DataFrame) -> go.Figure:
    if top_users_df.empty:
        return _empty_fig("Most targeted users")
    fig = px.bar(
        top_users_df,
        x="user",
        y="failed_attempts",
        title="Most targeted users",
        labels={"failed_attempts": "Failed attempts", "user": "User"},
    )
    return fig


def chart_attacks_by_country(country_df: pd.DataFrame) -> go.Figure:
    if country_df.empty:
        return _empty_fig("Attacks by country")
    fig = px.bar(
        country_df,
        x="country",
        y="failed_attempts",
        title="Attacks by country",
        labels={"failed_attempts": "Failed attempts", "country": "Country"},
    )
    return fig


def chart_activity_heatmap(heatmap_df: pd.DataFrame) -> go.Figure:
    if heatmap_df.empty:
        return _empty_fig("Activity heatmap (hour vs day)")

    pivot = heatmap_df.pivot(index="day", columns="hour", values="failed_attempts").fillna(0)
    day_labels = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ]
    pivot = pivot.reindex(range(7))
    pivot.index = [day_labels[i] for i in pivot.index]

    fig = px.imshow(
        pivot,
        aspect="auto",
        title="Activity heatmap (hour vs day)",
        labels={"x": "Hour", "y": "Day", "color": "Failed attempts"},
    )
    return fig


def build_charts(df: pd.DataFrame, metrics: Dict[str, Any]) -> Dict[str, go.Figure]:
    return {
        "top_ips": chart_top_ips(metrics["top_attacking_ips"]),
        "failed_vs_success": chart_failed_vs_success(df),
        "attacks_over_time": chart_attacks_over_time(metrics["attacks_per_hour"]),
        "top_users": chart_top_users(metrics["most_targeted_users"]),
        "attacks_by_country": chart_attacks_by_country(metrics["attacks_by_country"]),
        "heatmap": chart_activity_heatmap(metrics["heatmap"]),
    }
