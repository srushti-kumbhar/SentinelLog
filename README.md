

\# SentinelLog: Security Log Analysis and Intrusion Detection System



\## Project Overview



SentinelLog is a Python-based cybersecurity project that analyzes security logs to identify potentially suspicious activity. It detects repeated failed login attempts, unusual event frequency, and assigns risk levels to IP addresses.



The project uses sample security logs for educational and demonstration purposes.



\## Features



\- Upload security log CSV files.

\- Validate required CSV columns.

\- Count successful and failed login events.

\- Detect repeated failed login attempts.

\- Identify IP addresses with unusually high event counts.

\- Assign LOW, MEDIUM, and HIGH risk levels.

\- Generate security alerts for suspicious patterns.

\- Display results through an interactive Streamlit dashboard.

\- Visualize security events and risk levels with charts.



\## Technologies Used



\- Python

\- Pandas

\- Streamlit

\- Matplotlib

\- CSV



\## Project Structure



```text

SentinelLog/

├── app.py

├── log\_analyzer.py

├── generate\_sample\_logs.py

├── test\_analyzer.py

├── requirements.txt

├── README.md

├── data/

│   └── sample\_security\_logs.csv

├── outputs/

└── venv/

```



\## Installation



\### 1. Install Python



Install Python 3.10 or a compatible newer version.



\### 2. Open the project directory



Open Command Prompt inside the SentinelLog folder.



\### 3. Create a virtual environment



```bash

python -m venv venv

```



\### 4. Activate the environment on Windows



```bat

venv\\Scripts\\activate.bat

```



\### 5. Install dependencies



```bash

pip install -r requirements.txt

```



\## Generate Sample Logs



Run:



```bash

python generate\_sample\_logs.py

```



This creates sample security events in:



`data/sample\_security\_logs.csv`



\## Run the Application



Start the dashboard with:



```bash

python -m streamlit run app.py

```



Open the local URL shown in the terminal, usually:



`http://localhost:8501`



Use the sidebar to upload a compatible security log CSV file or analyze the included sample logs.



\## Required CSV Format



The uploaded CSV must contain these columns:



| Column | Description |

|---|---|

| timestamp | Date and time of the event |

| ip\_address | IP address associated with the event |

| username | Username associated with the event |

| event\_type | Type of event, such as login or request |

| status | Event status, such as success or failed |



\## Detection Rules



| Condition | Result |

|---|---|

| 0–4 failed login attempts | LOW risk, unless other rules apply |

| 5–9 failed login attempts | MEDIUM risk |

| 10 or more failed login attempts | HIGH risk |

| 10 or more total events from an IP | At least MEDIUM risk |



These are basic educational rules and can be improved for production use.



\## Testing



Run the analyzer test script:



```bash

python test\_analyzer.py

```



The included sample dataset contains 51 events, including successful logins, failed logins, and high-frequency activity.



\## Limitations



\- Uses rule-based detection rather than a trained machine learning model.

\- Analyzes the logs provided by the user; it does not continuously monitor a live network.

\- High event frequency or repeated failed logins may have legitimate explanations.

\- The sample logs are synthetic and do not represent real attacks.



\## Future Enhancements



\- Add real-time log monitoring.

\- Add email or other alert notifications.

\- Export analysis results and alerts to CSV.

\- Add configurable detection thresholds.

\- Integrate threat intelligence feeds.

\- Add more detection rules and automated tests.



\## Disclaimer



SentinelLog is an educational cybersecurity project. Use it only with logs and systems you are authorized to analyze.



