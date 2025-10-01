#!/usr/bin/env python3
import requests
from pathlib import Path
from datetime import datetime
import re
import socket
import signal
import sys
import tailer

LOG_FILE = Path("/var/log/snort/snort.alert.fast")
CHAT_ID = "your_chat_id"
TOKEN = "your_telegram_bot_token"
THROTTLE_INTERVAL = 5
HOSTNAME = socket.gethostname()
last_alert_time = 0


def send_alert(message: str):
    global last_alert_time
    import time
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
    # Pattern 1
    pattern = (
        r"(\d{2}/\d{2}-[\d:.]+)\s+"               # timestamp
        r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"         # alert ID
        r"(.+?)\s+\[\*+\]\s+"                     # message
        r"\[Classification:\s*(.+?)\]\s+"         # classification
        r"\[Priority:\s*(\d+)\]\s+"               # priority
        r"\{([\w\-]+)\}\s+"                       # protocol
        r"(.+?)\s+->\s+(.+)"                      # source -> destination
    )

    # Pattern 2
    pattern_loose = (
        r"(\d{2}/\d{2}-[\d:.]+)\s+"               # timestamp
        r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"         # alert ID
        r"(.+?)\s+\[\*+\]\s+"                     # message
        r"\[Classification:\s*(.+?)\]\s+"         # classification
        r"\[Priority:\s*(\d+)\]\s+"               # priority
        r"\{([\w\-]+)\}\s+(.+?)\s+->\s+(.+)"     # protocol + src -> dst
    )

    # Pattern 3
    pattern_no_class = (
        r"(\d{2}/\d{2}-[\d:.]+)\s+"               # timestamp
        r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"         # alert ID
        r"(.+?)\s+\[\*+\]\s+"                     # message
        r"\[Priority:\s*(\d+)\]\s+"               # priority
        r"\{([\w\-]+)\}\s+"                       # protocol
        r"(.+?)\s+->\s+(.+)"                      # source -> destination
    )

    match = re.match(pattern, line.strip())
    if not match:
        match = re.match(pattern_loose, line.strip())
    if not match:
        match = re.match(pattern_no_class, line.strip())
        if match:
            _, _, alert_msg, priority, protocol, src, dst = match.groups()
            classification = "N/A"
        else:
            return None
    else:
        _, _, alert_msg, classification, priority, protocol, src, dst = match.groups()

    prio_icon = {"1": "🟥 HIGH", "2": "🟧 MEDIUM", "3": "🟨 LOW"}.get(priority, "⬜ INFO")

    return (
        f"⚠️ Message   : {alert_msg}\n"
        f"📖 Classification: {classification}\n"
        f"{prio_icon} (Priority {priority})\n"
        f"📡 Protocol  : {protocol}\n"
        f"➡️ Source → Destination: {src} → {dst}"
        + f"\n🖥️ Server Time: {datetime.now().strftime('%d %b %Y %H:%M:%S')}"
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

    for line in tailer.follow(open(LOG_FILE)):
        alert = parse_snort_line(line.strip())
        if alert:
            caption = f"🚨 ALERT SNORT ({HOSTNAME}) 🚨\n\n" + alert
            send_alert(caption)


if __name__ == "__main__":
    main()