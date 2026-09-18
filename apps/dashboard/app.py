"""Thin Streamlit adapter for the read-only supervisor dashboard."""

from __future__ import annotations

from typing import Any


def _render(snapshot: Any, summary: Any, st: Any, px: Any) -> None:
    st.title("SecureEdgeVision Supervisor")
    st.caption(
        "Read-only metadata view. Heartbeats are unsigned advisory liveness; "
        "detections are model output, not semantic truth."
    )
    st.metric("Aggregator", snapshot.health.status)
    st.metric("Registered nodes", snapshot.health.registered_nodes)
    st.metric("Accepted events", snapshot.health.accepted_events)
    st.metric("Security alerts", snapshot.health.security_alerts)

    if st.button("Refresh"):
        st.rerun()

    st.subheader("Nodes")
    if snapshot.nodes:
        st.dataframe(
            [
                {
                    "node_id": node.node_id,
                    "registered_at_utc": node.registered_at_utc.isoformat(),
                    "last_seen_at_utc": (
                        node.last_seen_at_utc.isoformat()
                        if node.last_seen_at_utc is not None
                        else None
                    ),
                    "health_status": node.health_status,
                }
                for node in snapshot.nodes
            ],
            use_container_width=True,
        )
    else:
        st.info("No registered nodes.")

    st.subheader("Recent events")
    if snapshot.events:
        st.dataframe(
            [
                {
                    "accepted_at_utc": item.accepted_at_utc.isoformat(),
                    "event_id": item.event.event_id,
                    "node_id": item.event.node_id,
                    "camera_id": item.event.camera_id,
                    "detections": len(item.event.detections),
                }
                for item in snapshot.events
            ],
            use_container_width=True,
        )
    else:
        st.info("No accepted events.")

    st.subheader("Security alerts")
    if snapshot.alerts:
        st.dataframe(
            [
                {
                    "occurred_at_utc": alert.occurred_at_utc.isoformat(),
                    "category": alert.category,
                    "reason": alert.reason,
                    "node_id": alert.node_id,
                    "event_id": alert.event_id,
                }
                for alert in snapshot.alerts
            ],
            use_container_width=True,
        )
    else:
        st.info("No security alerts.")

    st.subheader("Summaries")
    st.plotly_chart(
        px.bar(
            x=[name for name, _ in summary.detection_class_counts],
            y=[count for _, count in summary.detection_class_counts],
            labels={"x": "class", "y": "detections"},
            title="Detection classes",
        ),
        use_container_width=True,
    )
    st.plotly_chart(
        px.bar(
            x=[name for name, _ in summary.node_status_counts],
            y=[count for _, count in summary.node_status_counts],
            labels={"x": "status", "y": "nodes"},
            title="Node advisory status",
        ),
        use_container_width=True,
    )
    st.plotly_chart(
        px.bar(
            x=[name for name, _ in summary.alert_reason_counts],
            y=[count for _, count in summary.alert_reason_counts],
            labels={"x": "category:reason", "y": "alerts"},
            title="Security alert reasons",
        ),
        use_container_width=True,
    )


def main() -> int:
    """Run Streamlit only when explicitly invoked."""
    import plotly.express as px
    import streamlit as st

    from secureedge.config import load_settings
    from secureedge.dashboard import DashboardClient, DashboardDataError, summarize

    st.set_page_config(page_title="SecureEdgeVision Supervisor", layout="wide")
    try:
        settings = load_settings("config/system.yaml")
        with DashboardClient(
            str(settings.aggregator_url),
            settings.transport.request_timeout_seconds,
        ) as client:
            snapshot = client.snapshot()
        _render(snapshot, summarize(snapshot), st, px)
        return 0
    except DashboardDataError:
        st.error("Dashboard data is currently unavailable.")
        return 1
    except Exception:
        st.error("Dashboard configuration is unavailable.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
