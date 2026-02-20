# wifi_ids_core.py
from collections import defaultdict
from telegram_config import TELEGRAM_TOKEN, CHAT_ID
import requests

# -----------------------------
# Data storage
# -----------------------------
deauth_count = defaultdict(int)
probe_count = defaultdict(int)
beacon_map = {}

# Thresholds
THRESHOLD_DEAUTH = 2
THRESHOLD_PROBE = 3

# -----------------------------
# Telegram alert with severity emoji
# -----------------------------
SEVERITY_EMOJI = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🟠",
    "Critical": "🔴"
}

def telegram_alert(msg, severity="Low"):
    """
    Send alert to Telegram with severity level and emoji.
    """
    emoji = SEVERITY_EMOJI.get(severity, "")
    text = f"{emoji} [{severity}] {msg}"
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": text}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"Failed Telegram alert: {e}")

# -----------------------------
# Helper: determine severity
# -----------------------------
def get_severity(count, threshold):
    """
    Determines severity based on how much count exceeds threshold.
    Returns one of: Low, Medium, High, Critical
    """
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
# Detection functions
# -----------------------------
def detect_beacon(ssid, src):
    """
    Detect rogue APs.
    Returns True if suspicious.
    """
    if ssid in beacon_map and beacon_map[ssid] != src:
        msg = f"Rogue AP detected: {ssid} from {src}"
        telegram_alert(msg, severity="Critical")  # Rogue APs are always critical
        return True
    else:
        beacon_map[ssid] = src
        return False

def detect_deauth(src):
    """
    Detect deauthentication flood.
    Returns True if suspicious.
    """
    deauth_count[src] += 1
    if deauth_count[src] >= THRESHOLD_DEAUTH:
        severity = get_severity(deauth_count[src], THRESHOLD_DEAUTH)
        msg = f"Deauth flood detected from {src} ({deauth_count[src]} packets)"
        telegram_alert(msg, severity=severity)
        return True
    return False

def detect_probe(src):
    """
    Detect abnormal probe requests.
    Returns True if suspicious.
    """
    probe_count[src] += 1
    if probe_count[src] >= THRESHOLD_PROBE:
        severity = get_severity(probe_count[src], THRESHOLD_PROBE)
        msg = f"Abnormal probe detected from {src} ({probe_count[src]} requests)"
        telegram_alert(msg, severity=severity)
        return True
    return False