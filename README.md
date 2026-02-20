OpenGuard
Wi-Fi Eavesdropping Detection System

OpenGuard is a lightweight Wi-Fi security monitoring system designed to detect potential wireless eavesdropping and reconnaissance activities. The system focuses on analyzing three critical IEEE 802.11 management frame indicators: Beacon frames, Probe requests, and Deauthentication frames.

The objective of OpenGuard is to identify early-stage wireless threats before they escalate into credential capture, session hijacking, or traffic interception attacks.

Problem Statement

Wireless networks are inherently vulnerable to both passive and active reconnaissance techniques. Attackers attempting Wi-Fi eavesdropping commonly:

Deploy rogue access points (Evil Twin attacks)

Perform probe-based network scanning

Launch deauthentication attacks to force client reconnections

Capture traffic during authentication handshakes

OpenGuard is designed to detect these behaviors by analyzing structured Wi-Fi frame datasets and identifying anomalies based on predefined thresholds and pattern comparison logic.

Core Detection Indicators
1. Beacon Frame Analysis (Rogue Access Point Detection)

The system detects:

Multiple MAC addresses broadcasting the same SSID

SSID–MAC inconsistencies

Duplicate network identity patterns

Rogue access points are frequently used to impersonate legitimate networks and intercept user traffic.

2. Probe Request Monitoring (Reconnaissance Detection)

The system detects:

Excessive probe requests from a single source

High-frequency scanning activity

Abnormal request repetition patterns

Repeated probe requests may indicate pre-attack reconnaissance behavior.

3. Deauthentication Frame Detection (Forced Reconnection Attack)

The system detects:

Repeated deauthentication frames from a single source

Deauthentication flooding beyond normal thresholds

Deauthentication attacks are commonly used to disconnect clients and force reauthentication, enabling packet capture.

Detection Methodology

OpenGuard implements a rule-based anomaly detection approach consisting of:

Threshold-Based Analysis

Predefined frequency limits are applied to:

Probe request counts

Deauthentication packet counts

SSID repetition patterns

When thresholds are exceeded, the activity is classified as suspicious.

Pattern Comparison Logic

The system validates:

SSID-to-MAC mapping consistency

Source repetition behavior

Frame frequency anomalies

This approach allows lightweight detection without requiring machine learning models.

System Architecture

Wi-Fi Frame Dataset (CSV)
↓
Frame Classification Engine
↓
Indicator-Based Analysis
(Beacon | Probe | Deauthentication)
↓
Threat Severity Assessment
↓
Console Logging and Telegram Alert Notification

Technology Stack

Python 3.x

Flask (Web Interface)

Requests (Telegram API Integration)

CSV-Based Dataset Processing

Project Structure
openguard/
│
├── data/
│   ├── beacon.csv
│   ├── probe.csv
│   └── deauthenticate.csv
│
├── templates/
├── app.py
├── run_core.py
├── wifi_ids_core.py
├── telegram_config.py
└── README.md
Installation

Clone the repository:

git clone https://github.com/Jukisha04/openguard.git
cd openguard

Create a virtual environment (recommended):

python -m venv venv

Activate the environment:

Windows:

venv\Scripts\activate

Linux/macOS:

source venv/bin/activate

Install dependencies:

pip install flask requests
Configuration

Update telegram_config.py with your Telegram Bot Token and Chat ID to enable alert notifications.

Running the Application

Start the Flask application:

python app.py

Access the web interface at:

http://localhost:5000
Example Output
ALERT: Deauthentication Flood Detected
Source MAC: 34:12:AB:CD:EF:98
Severity: HIGH

Medium and high severity alerts are forwarded to Telegram.

Scope and Limitations

OpenGuard is designed for:

Academic research

Ethical security testing

Demonstration and prototype environments

The current implementation processes structured datasets rather than live packet capture. It does not perform packet injection or exploitation; it is strictly a detection and alerting system.

Future Enhancements

Live packet capture using monitor mode

Real-time traffic analysis

Dashboard-based analytics visualization

Integration with SIEM platforms

Machine learning-based anomaly detection