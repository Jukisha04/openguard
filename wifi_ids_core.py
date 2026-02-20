# wifi_ids_core.py

from collections import defaultdict
from telegram_config import TELEGRAM_TOKEN, CHAT_ID
import requests
import os

# -----------------------------
# File path (FIXED)
# Always save alerts beside this script
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_LOG_FILE = os.path.join(BASE_DIR, "alerts_log.txt")

# -----------------------------
# Data storage
# -----------------------------
deauth_count = defaultdict(int)
probe_count = defaultdict(int)
beacon_map = {}

alerted_beacons = set()
alerted_deauths = set()
alerted_probes = set()

# Thresholds
THRESHOLD_DEAUTH = 2
THRESHOLD_PROBE = 3

# -----------------------------
# Severity emoji
# -----------------------------
SEVERITY_EMOJI = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🟠",
    "Critical": "🔴"
}

# -----------------------------
# Telegram alert + file logging
# -----------------------------
def telegram_alert(msg, severity="Low"):
    """
    Send alert to Telegram + log to file.
    Works even if Telegram unavailable.
    """

    emoji = SEVERITY_EMOJI.get(severity, "")
    text = f"{emoji} [{severity}] {msg}"

    # --- Telegram send ---
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": text}

    try:
        requests.post(url, data=data, timeout=3, verify=False)
    except Exception:
        pass  # Ignore Telegram errors

    # --- File logging ---
    try:
        with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception as e:
        print("File write error:", e)

# -----------------------------
# Severity calculation
# -----------------------------
def get_severity(count, threshold):
    ratio = count / threshold
    if ratio >= 3:
        return "Critical"
    elif ratio >= 2:
        return "High"
    elif ratio >= 1.5:
        return "Medium"
    else:
        return "Low"

# -----------------------------
# Detection: Rogue AP
# -----------------------------
def detect_beacon(ssid, src):
    if ssid in beacon_map and beacon_map[ssid] != src:
        if src not in alerted_beacons:
            msg = f"Rogue AP detected: {ssid} from {src}"
            telegram_alert(msg, "Critical")
            alerted_beacons.add(src)
        return True
    else:
        beacon_map[ssid] = src
        return False

# -----------------------------
# Detection: Deauth flood
# -----------------------------
def detect_deauth(src):
    deauth_count[src] += 1

    if deauth_count[src] >= THRESHOLD_DEAUTH:
        if src not in alerted_deauths:
            severity = get_severity(deauth_count[src], THRESHOLD_DEAUTH)
            msg = f"Deauth flood detected from {src} ({deauth_count[src]} packets)"
            telegram_alert(msg, severity)
            alerted_deauths.add(src)
        return True

    return False

# -----------------------------
# Detection: Probe anomaly
# -----------------------------
def detect_probe(src):
    probe_count[src] += 1

    if probe_count[src] >= THRESHOLD_PROBE:
        if src not in alerted_probes:
            severity = get_severity(probe_count[src], THRESHOLD_PROBE)
            msg = f"Abnormal probe detected from {src} ({probe_count[src]} requests)"
            telegram_alert(msg, severity)
            alerted_probes.add(src)
        return True

    return False

# -----------------------------
# Show logged alerts (demo)
# -----------------------------
def show_alerts():
    if not os.path.exists(ALERT_LOG_FILE):
        print("No alerts yet.")
        return

    print("\n--- Logged Alerts ---")
    with open(ALERT_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            print(line.strip())
    print("--- End of Alerts ---\n")

# -----------------------------
# Demo test mode
# -----------------------------
if __name__ == "__main__":
    print("Running IDS core demo...")

    test_macs = ["00:11:22:33:44:AA", "00:11:22:33:44:BB"]

    # Rogue AP simulation
    for mac in test_macs:
        detect_beacon("HomeWiFi", mac)
        detect_beacon("OfficeWiFi", mac)

    # Probe flood simulation
    for _ in range(4):
        for mac in test_macs:
            detect_probe(mac)

    # Deauth flood simulation
    for _ in range(3):
        for mac in test_macs:
            detect_deauth(mac)

    show_alerts()