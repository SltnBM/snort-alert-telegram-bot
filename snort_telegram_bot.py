#!/usr/bin/env python3
import time
import requests
from pathlib import Path
from datetime import datetime
import re
import socket
import signal
import sys

LOG_FILE = Path("/var/log/snort/snort.alert.fast")
CHAT_ID = "your_chat_id"
TOKEN = "your_telegram_bot_token"
CHECK_INTERVAL = 2
THROTTLE_INTERVAL = 10
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
    pattern = (
        r"(\d{2}/\d{2}-[\d:.]+)\s+"              # timestamp
        r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"        # alert id
        r"(.+?)\s+\[\*+\]\s+"                     # message
        r"\[Classification:\s*(.+?)\]\s+"        # classification
        r"\[Priority:\s*(\d+)\]\s+"               # priority
        r"\{([\w\-]+)\}\s+"                       # protocol
        r"(.+?)\s+->\s+(.+)"                      # src -> dst
    )
    match = re.match(pattern, line.strip())
    if not match:
        # fallback pattern for slight log variations
        pattern_loose = (
            r"(\d{2}/\d{2}-[\d:.]+)\s+"
            r"\[\*+\]\s+\[(\d+:\d+:\d+)\]\s+"
            r"(.+?)\s+\[\*+\]\s+"
            r"\[Classification:\s*(.+?)\]\s+"
            r"\[Priority:\s*(\d+)\]\s+"
            r"\{([\w\-]+)\}\s+(.+?)\s+->\s+(.+)"
        )
        match = re.match(pattern_loose, line.strip())

    if match:
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
    return None

def exit_handler(signal_received, frame):
    print("\n🛑 Bot stopped by user. Goodbye!")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, exit_handler)
    print("🚀 Snort Telegram Alert Bot running...")
    if not LOG_FILE.exists():
        print(f"❌ Log file not found: {LOG_FILE}")
        return

    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(CHECK_INTERVAL)
                f.seek(where)
            else:
                alert = parse_snort_line(line.strip())
                if alert:
                    caption = f"🚨 ALERT SNORT ({HOSTNAME}) 🚨\n\n" + alert
                    send_alert(caption)
                else:
                    print(f"DEBUG: Line does not match regex → {line.strip()}")

if __name__ == "__main__":
    main()