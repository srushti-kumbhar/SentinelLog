import streamlit as st
import pandas as pd

from log_analyzer import (
    load_logs,
    analyze_logs,
    generate_alerts
)


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="SentinelLog - Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# TITLE
# ---------------------------------------------------------

st.title("🛡️ SentinelLog")
st.subheader("Security Log Analysis and Intrusion Detection System")

st.write(
    "Educational SOC-style dashboard for analyzing "
    "authentication and security logs."
)

st.info(
    "Educational use only: SentinelLog analyzes supplied log files "
    "and does not scan or attack real systems."
)


# ---------------------------------------------------------
# LOAD LOG FILE
# ---------------------------------------------------------

st.sidebar.header("📂 Log File")

uploaded_file = st.sidebar.file_uploader(
    "Upload a security log CSV file",
    type=["csv"]
)


# Use uploaded file if available.
# Otherwise use the educational sample dataset.

if uploaded_file is not None:

    log_source = uploaded_file

    st.sidebar.success(
        "Uploaded log file selected."
    )

else:

    log_source = "data/sample_security_logs.csv"

    st.sidebar.info(
        "Using educational sample logs."
    )


# ---------------------------------------------------------
# ANALYZE LOGS
# ---------------------------------------------------------

try:

    df = load_logs(log_source)

    analysis_df = analyze_logs(df)

    alerts_df = generate_alerts(analysis_df)


except Exception as e:

    st.error(
        f"Unable to analyze the log file: {e}"
    )

    st.stop()


# ---------------------------------------------------------
# CALCULATE DASHBOARD METRICS
# ---------------------------------------------------------

total_events = len(df)

successful_logins = len(
    df[
        (df["event_type"].str.lower() == "login")
        &
        (df["status"].str.lower() == "success")
    ]
)

failed_logins = len(
    df[
        (df["event_type"].str.lower() == "login")
        &
        (df["status"].str.lower() == "failed")
    ]
)

suspicious_ips = int(
    analysis_df["suspicious"].sum()
)

high_risk = len(
    analysis_df[
        analysis_df["risk_level"] == "HIGH"
    ]
)

medium_risk = len(
    analysis_df[
        analysis_df["risk_level"] == "MEDIUM"
    ]
)

low_risk = len(
    analysis_df[
        analysis_df["risk_level"] == "LOW"
    ]
)


# ---------------------------------------------------------
# SECURITY METRICS
# ---------------------------------------------------------

st.header("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Total Events",
        total_events
    )

with col2:

    st.metric(
        "Successful Logins",
        successful_logins
    )

with col3:

    st.metric(
        "Failed Logins",
        failed_logins
    )

with col4:

    st.metric(
        "Suspicious IPs",
        suspicious_ips
    )


# ---------------------------------------------------------
# RISK SUMMARY
# ---------------------------------------------------------

st.header("🚦 Risk Levels")

risk_col1, risk_col2, risk_col3 = st.columns(3)

with risk_col1:

    st.metric(
        "🟢 LOW",
        low_risk
    )

with risk_col2:

    st.metric(
        "🟡 MEDIUM",
        medium_risk
    )

with risk_col3:

    st.metric(
        "🔴 HIGH",
        high_risk
    )


# ---------------------------------------------------------
# ALERTS
# ---------------------------------------------------------

st.header("🚨 Security Alerts")

if alerts_df.empty:

    st.success(
        "No suspicious activity detected."
    )

else:

    st.dataframe(
        alerts_df,
        use_container_width=True,
        hide_index=True
    )


# ---------------------------------------------------------
# SUSPICIOUS IP ADDRESSES
# ---------------------------------------------------------

st.header("🔍 Suspicious IP Addresses")

suspicious_df = analysis_df[
    analysis_df["suspicious"] == True
].copy()


if suspicious_df.empty:

    st.success(
        "No suspicious IP addresses detected."
    )

else:

    st.dataframe(
        suspicious_df,
        use_container_width=True,
        hide_index=True
    )


# ---------------------------------------------------------
# CHARTS
# ---------------------------------------------------------

st.header("📈 Security Charts")

chart_col1, chart_col2 = st.columns(2)


# Risk distribution chart

with chart_col1:

    st.subheader("Risk Distribution")

    risk_counts = (
        analysis_df["risk_level"]
        .value_counts()
        .reindex(
            ["LOW", "MEDIUM", "HIGH"],
            fill_value=0
        )
    )

    st.bar_chart(risk_counts)


# Failed login chart

with chart_col2:

    st.subheader("Failed Login Attempts by IP")

    failed_chart = (
        analysis_df[
            analysis_df["failed_attempts"] > 0
        ][
            ["ip_address", "failed_attempts"]
        ]
        .set_index("ip_address")
    )

    if failed_chart.empty:

        st.info(
            "No failed login activity found."
        )

    else:

        st.bar_chart(
            failed_chart
        )


# ---------------------------------------------------------
# LOG DATA
# ---------------------------------------------------------

st.header("📋 Security Log Data")

st.dataframe(
    df,
    use_container_width=True,
    hide_index=True
)


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.divider()

st.caption(
    "SentinelLog | Educational cybersecurity project | "
    "Synthetic/sample logs only"
)