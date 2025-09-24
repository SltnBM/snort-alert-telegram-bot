# Snort Telegram Alert Bot
A simple Python script to forward **Snort IDS alerts** to **Telegram** in real-time.  
This bot continuously monitors the `snort.alert.fast` log file and sends detected alerts directly to your Telegram chat.

## Features
- Real-time monitoring of Snort alerts.
- Instant forwarding of alerts to Telegram.
- Includes alert details: message, classification, priority, protocol, source, and destination.
- Throttling to prevent spam (configurable interval).
- Displays server hostname and local timestamp in each alert.
- Graceful shutdown with `Ctrl + C`.

## Requirements
- Python 3.x
- Required libraries:
  - `requests`

Install dependency:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests
```

## How to Use
1. Make sure you have Python installed (Python 3 or higher recommended). Download it from [python.org](https://www.python.org/downloads/).
2. Clone this repository
```bash
git clone https://github.com/SltnBM/snort-alert-bot.git
```
3. Navigate to the project directory
```bash
cd snort-alert-bot
```
4. Edit the script and set your Telegram Bot Token and Chat ID:
```bash
CHAT_ID = "your_chat_id"
TOKEN = "your_telegram_bot_token"
```
5. Run the script using terminal or command prompt
```bash
python snort_telegram_bot.py
```

## Example Alert (Telegram)
```bash
🚨 ALERT SNORT (server01) 🚨

⚠️ Message   : NMAP HTTP Scan detected
📖 Classification: Attempted Information Leak
🟧 MEDIUM (Priority 2)
📡 Protocol  : TCP
➡️ Source → Destination: 192.168.1.100:54321 → 192.168.1.10:80
🖥️ Server Time: 24 Sep 2025 22:15:42
```

# Contributing
Pull requests are welcome! Feel free to improve regex parsing, add new features, or optimize the alert system.

## Connect With Me
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sultan%20Badra-blue?logo=linkedin\&logoColor=white\&style=flat-square)](https://www.linkedin.com/in/sultan-badra)

## License
This project is open-source and free to use.