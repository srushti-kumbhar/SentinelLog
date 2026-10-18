
from pathlib import Path

import pandas as pd

from log_analyzer import load_logs, analyze_logs, generate_alerts


def main():
    data_path = Path("data/sample_security_logs.csv")
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    logs = load_logs(data_path)
    analysis = analyze_logs(logs)
    alerts = generate_alerts(analysis)

    # Save detailed IP risk analysis
    analysis_path = output_dir / "ip_risk_analysis.csv"
    analysis.to_csv(analysis_path, index=False)

    # Save security alerts
    alerts_path = output_dir / "security_alerts.csv"
    alerts.to_csv(alerts_path, index=False)

    # Display summary
    successful = (
        (logs["event_type"].str.lower() == "login")
        & (logs["status"].str.lower() == "success")
    ).sum()

    failed = (
        (logs["event_type"].str.lower() == "login")
        & (logs["status"].str.lower() == "failed")
    ).sum()

    print("\n=== SENTINELLOG SECURITY REPORT ===")
    print(f"Total events: {len(logs)}")
    print(f"Successful logins: {successful}")
    print(f"Failed logins: {failed}")
    print(f"IP addresses analyzed: {len(analysis)}")
    print(f"Security alerts generated: {len(alerts)}")

    print("\n=== IP RISK ANALYSIS ===")
    print(analysis.to_string(index=False))

    print("\n=== SECURITY ALERTS ===")
    if alerts.empty:
        print("No alerts generated.")
    else:
        print(alerts.to_string(index=False))

    print("\nReports saved successfully:")
    print(analysis_path)
    print(alerts_path)


if __name__ == "__main__":
    main()
