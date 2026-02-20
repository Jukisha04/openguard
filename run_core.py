# run_core.py
import csv
import time
from wifi_ids_core import detect_beacon, detect_deauth, detect_probe

# Global stop flag
stop_flag = False

# -----------------------------
# Dataset files
# -----------------------------
datasets = {
    "beacon": "data/beacon.csv",
    "probe": "data/probe.csv",
    "deauth": "data/deauthenticate.csv"
}

# -----------------------------
# Helper function to check stop
# -----------------------------
def check_stop():
    global stop_flag
    if stop_flag:
        print("Detection stopped by user.")
        return True
    return False

# -----------------------------
# Process each dataset
# -----------------------------
def process_beacon(file_path):
    print("\n--- Processing Beacon Frames ---")
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if check_stop(): return
                ssid = row.get('ssid', 'unknown')
                src = row.get('src_mac', 'unknown')
                suspicious = detect_beacon(ssid, src)
                status = "SUSPICIOUS" if suspicious else "OK"
                print(f"Beacon | SSID: {ssid} | MAC: {src} | {status}")
                time.sleep(0.05)
    except FileNotFoundError:
        print(f"{file_path} not found!")

def process_probe(file_path):
    print("\n--- Processing Probe Frames ---")
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if check_stop(): return
                src = row.get('src_mac', 'unknown')
                suspicious = detect_probe(src)
                status = "SUSPICIOUS" if suspicious else "OK"
                print(f"Probe  | MAC: {src} | {status}")
                time.sleep(0.05)
    except FileNotFoundError:
        print(f"{file_path} not found!")

def process_deauth(file_path):
    print("\n--- Processing Deauth Frames ---")
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if check_stop(): return
                src = row.get('src_mac', 'unknown')
                suspicious = detect_deauth(src)
                status = "SUSPICIOUS" if suspicious else "OK"
                print(f"Deauth | MAC: {src} | {status}")
                time.sleep(0.05)
    except FileNotFoundError:
        print(f"{file_path} not found!")

# -----------------------------
# Main function
# -----------------------------
def main():
    global stop_flag
    stop_flag = False  # reset flag when starting
    process_beacon(datasets["beacon"])
    process_probe(datasets["probe"])
    process_deauth(datasets["deauth"])
    print("\nProcessing completed.")

# Function to stop detection
def stop_detection():
    global stop_flag
    stop_flag = True
