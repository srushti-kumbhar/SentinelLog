import csv
import os
import random
from datetime import datetime, timedelta


OUTPUT_FILE = os.path.join(
    "data",
    "sample_security_logs.csv"
)


def generate_logs():
    """
    Generate an educational sample security log dataset.

    This dataset is completely synthetic and is intended
    only for cybersecurity learning and log-analysis practice.
    """

    random.seed(42)

    logs = []

    base_time = datetime(2026, 10, 18, 9, 0, 0)

    normal_ips = [
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30",
    ]

    suspicious_ip = "192.168.1.50"

    high_risk_ip = "192.168.1.99"

    usernames = [
        "alice",
        "bob",
        "charlie",
        "admin",
    ]

    # ---------------------------------------------------------
    # Normal successful login activity
    # ---------------------------------------------------------

    for i in range(15):

        timestamp = base_time + timedelta(
            minutes=i * 3
        )

        logs.append(
            {
                "timestamp": timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip_address": random.choice(normal_ips),
                "username": random.choice(usernames),
                "event_type": "login",
                "status": "success",
            }
        )

    # ---------------------------------------------------------
    # Normal failed login activity
    # ---------------------------------------------------------

    for i in range(5):

        timestamp = base_time + timedelta(
            minutes=60 + i * 5
        )

        logs.append(
            {
                "timestamp": timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip_address": "192.168.1.20",
                "username": "alice",
                "event_type": "login",
                "status": "failed",
            }
        )

    # ---------------------------------------------------------
    # Suspicious repeated failed login attempts
    # ---------------------------------------------------------

    for i in range(7):

        timestamp = base_time + timedelta(
            minutes=100 + i
        )

        logs.append(
            {
                "timestamp": timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip_address": suspicious_ip,
                "username": "admin",
                "event_type": "login",
                "status": "failed",
            }
        )

    # ---------------------------------------------------------
    # High-risk possible brute-force activity
    # ---------------------------------------------------------

    for i in range(12):

        timestamp = base_time + timedelta(
            minutes=130 + i
        )

        logs.append(
            {
                "timestamp": timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip_address": high_risk_ip,
                "username": "admin",
                "event_type": "login",
                "status": "failed",
            }
        )

    # ---------------------------------------------------------
    # Unusually high request frequency
    # ---------------------------------------------------------

    for i in range(12):

        timestamp = base_time + timedelta(
            minutes=160,
            seconds=i * 5
        )

        logs.append(
            {
                "timestamp": timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip_address": "192.168.1.77",
                "username": "guest",
                "event_type": "request",
                "status": "success",
            }
        )

    # Sort events by timestamp
    logs.sort(
        key=lambda item: item["timestamp"]
    )

    return logs


def save_logs(logs):
    """
    Save the generated logs as a CSV file.
    """

    os.makedirs("data", exist_ok=True)

    fieldnames = [
        "timestamp",
        "ip_address",
        "username",
        "event_type",
        "status",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(logs)


if __name__ == "__main__":

    sample_logs = generate_logs()

    save_logs(sample_logs)

    print(
        "Educational sample security logs created successfully."
    )

    print(
        f"File location: {OUTPUT_FILE}"
    )

    print(
        f"Total events generated: {len(sample_logs)}"
    )