#!/usr/bin/env python3
import requests
from pathlib import Path
from datetime import datetime
import re
import socket
import signal
import sys
import tailer
import time
import os
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = Path("/var/log/snort/snort.alert.fast")
CHAT_ID = os.getenv("CHAT_ID")
TOKEN = os.getenv("TOKEN")
THROTTLE_INTERVAL = 5
HOSTNAME = socket.gethostname()
last_alert_time = 0


def send_alert(message: str):
    global last_alert_time
    now = time.time()
    if now - last_alert_time < THROTTLE_INTERVAL:
        return
    last_alert_time = now

    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        response = requests.post(url, data=data, timeout=5)
        if response.status_code != 200:
            print(f"⚠️ Failed to send alert: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error sending alert: {e}")


def parse_snort_line(line: str) -> str:
    # Full pattern
    pattern = (
        r"(\d{2}/\d{2}-[\d:.]+)\s+"             # timestamp
        r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"       # alert ID
        r"(.+?)\s+\[\*+\]\s+"                   # message
        r"(?:\[Classification:\s*(.+?)\]\s+)?"  # optional classification
        r"\[Priority:\s*(\d+)\]\s+"             # priority
        r"\{([\w\-]+)\}\s+"                     # protocol
        r"(.+?)\s+->\s+(.+)"                    # source -> destination
    )

    match = re.match(pattern, line.strip())
    if not match:
        return None

    _, _, alert_msg, classification, priority, protocol, src, dst = match.groups()
    classification = classification or "N/A"

    prio_icon = {"1": "🟥 HIGH", "2": "🟧 MEDIUM", "3": "🟨 LOW"}.get(priority, "⬜ INFO")

    return (
        f"⚠️ Message: {alert_msg}\n"
        f"📖 Classification: {classification}\n"
        f"{prio_icon} (Priority {priority})\n"
        f"📡 Protocol: {protocol}\n"
        f"➡️ {src} → {dst}\n"
        f"🖥️ Server Time: {datetime.now().strftime('%d %b %Y %H:%M:%S')}"
    )


def exit_handler(signal_received, frame):
    print("\n🛑 Bot stopped by user. Goodbye!")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, exit_handler)
    print("🚀 Snort Telegram Alert Bot running...")

    if not LOG_FILE.exists():
        print(f"❌ Log file not found: {LOG_FILE}")
        return

    with open(LOG_FILE) as f:
        for line in tailer.follow(f):
            alert = parse_snort_line(line.strip())
            if alert:
                caption = f"🚨 ALERT SNORT ({HOSTNAME}) 🚨\n\n{alert}"
                send_alert(caption)


if __name__ == "__main__":
    main()
