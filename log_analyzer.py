
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp",
    "ip_address",
    "username",
    "event_type",
    "status",
]


def load_logs(file):
    """Load and validate a security log CSV file."""

    try:
        df = pd.read_csv(file)
    except Exception as e:
        raise ValueError(f"Unable to read the CSV file: {e}")

    df.columns = [column.strip().lower() for column in df.columns]

    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(missing_columns)
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    df = df.dropna(subset=["timestamp"]).copy()

    text_columns = [
        "ip_address", "username", "event_type", "status"
    ]

    for column in text_columns:
        df[column] = df[column].fillna("").astype(str).str.strip()

    # Remove rows without an IP address
    df = df[df["ip_address"] != ""].copy()

    return df


def detect_failed_login_patterns(df, threshold=5):
    """Find IP addresses with repeated failed login attempts."""

    failed = df[
        (df["event_type"].str.lower() == "login")
        & (df["status"].str.lower() == "failed")
    ]

    failed_counts = (
        failed.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
    )

    return failed_counts[
        failed_counts["failed_attempts"] >= threshold
    ].copy()


def detect_request_frequency(df, threshold=10):
    """Find IP addresses generating many events."""

    request_counts = (
        df.groupby("ip_address")
        .size()
        .reset_index(name="event_count")
    )

    return request_counts[
        request_counts["event_count"] >= threshold
    ].copy()


def assign_risk_level(
    failed_attempts=0,
    event_count=0,
    suspicious_activity=False
):
    """Assign a risk level based on observed activity."""

    if failed_attempts >= 10:
        return "HIGH"

    if failed_attempts >= 5:
        return "MEDIUM"

    if event_count >= 10 or suspicious_activity:
        return "MEDIUM"

    return "LOW"


def analyze_logs(df):
    """Analyze all IP addresses and assign risk levels."""

    failed_patterns = detect_failed_login_patterns(df)

    # Count every event for every IP, including normal IPs
    event_counts = df["ip_address"].value_counts().to_dict()

    failed_lookup = dict(
        zip(
            failed_patterns["ip_address"],
            failed_patterns["failed_attempts"]
        )
    )

    analysis = []

    for ip_address in df["ip_address"].unique():
        failed_attempts = int(
            failed_lookup.get(ip_address, 0)
        )

        event_count = int(
            event_counts.get(ip_address, 0)
        )

        suspicious_activity = (
            failed_attempts >= 5 or event_count >= 10
        )

        risk_level = assign_risk_level(
            failed_attempts=failed_attempts,
            event_count=event_count,
            suspicious_activity=suspicious_activity
        )

        analysis.append({
            "ip_address": ip_address,
            "failed_attempts": failed_attempts,
            "event_count": event_count,
            "risk_level": risk_level,
            "suspicious": suspicious_activity,
        })

    return pd.DataFrame(analysis)


def generate_alerts(analysis_df):
    """Generate alerts for potentially suspicious activity."""

    alerts = []

    for _, row in analysis_df.iterrows():
        failed_attempts = int(row["failed_attempts"])
        event_count = int(row["event_count"])
        ip_address = row["ip_address"]

        if failed_attempts >= 10:
            alerts.append({
                "ip_address": ip_address,
                "alert": "Possible brute-force attack",
                "reason": (
                    f"{failed_attempts} failed login attempts"
                ),
                "risk_level": "HIGH",
            })

        elif failed_attempts >= 5:
            alerts.append({
                "ip_address": ip_address,
                "alert": "Repeated failed login attempts",
                "reason": (
                    f"{failed_attempts} failed login attempts"
                ),
                "risk_level": "MEDIUM",
            })

        elif event_count >= 10:
            alerts.append({
                "ip_address": ip_address,
                "alert": "Unusual request frequency",
                "reason": f"{event_count} events from this IP",
                "risk_level": "MEDIUM",
            })

    return pd.DataFrame(
        alerts,
        columns=[
            "ip_address", "alert", "reason", "risk_level"
        ]
    )
