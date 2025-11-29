# Snort Telegram Alert Bot
<p align="center">
  <img src="assets/snort.png" width="120" style="border:0" alt="Snort Logo">
  <img src="assets/python.png" width="120" style="border:0" alt="Python Logo">
  <img src="assets/telegram.webp" width="60" style="border:0" alt="Telegram Logo">
</p>

A simple Python script to forward **Snort IDS alerts** to **Telegram** in real-time.  
This bot continuously monitors the `snort.alert.fast` log file and sends detected alerts directly to your Telegram chat.

---

## Features
- Real-time monitoring of Snort alerts.
- Instant forwarding of alerts to Telegram.
- Includes alert details: message, classification, priority, protocol, source, and destination.
- Throttling to prevent spam (configurable interval).
- Displays server hostname and local timestamp in each alert.
- Graceful shutdown with `Ctrl + C`.
- Supports custom Snort rules via `local.rules` file.

---

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
pip install requests tailer python-dotenv
```

---

## How to Use
1. Make sure you have Python installed (Python 3 or higher recommended). Download it from [python.org](https://www.python.org/downloads/).
2. Clone this repository
```bash
git clone https://github.com/SltnBM/snort-alert-telegram-bot.git
```
3. Navigate to the project directory
```bash
cd snort-alert-telegram-bot
```
4. Configure your environment variables
  - Copy `.env.example` to `.env`
    ```bash
    Copy .env.example to .env
    ```

  - Open `.env` and set your Telegram Bot Token and Chat ID:
    ```bash
    CHAT_ID=your_chat_id
    TOKEN=your_telegram_bot_token
    ```

How to Get Your Telegram Chat ID
You need your Chat ID to let the bot know where to send Snort alerts.
- For Personal Chat
  - Open Telegram and search for @userinfobot.
  - Type /start.
  - The bot will reply with your Chat ID.
- For Group Chat
  - Add your bot to the group.
  - Send any message in the group.
  - Run this command to see the latest updates (replace <YOUR_TOKEN> with your bot token):
    ```bash
    curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
    ```
  - Look for "chat":{"id": ... } → that number is your group Chat ID.
  - Use that Chat ID in the script config.
5. Add your custom Snort rules:
  - A sample `local.rules` file is already provided in this repository.
  - Open `/etc/snort/rules/local.rules` with a text editor:
     ```bash
     sudo nano /etc/snort/rules/local.rules
     ```
   - Add your detection rules following Snort syntax.
   - Save and exit the editor.
6. Run the script using terminal or command prompt
```bash
python snort_telegram_bot.py
```

---

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

---

## Contributing
Pull requests are welcome! Feel free to improve regex parsing, add new features, or optimize the alert system.

---

## Connect With Me
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sultan%20Badra-blue?logo=linkedin\&logoColor=white\&style=flat-square)](https://www.linkedin.com/in/sultan-badra)

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
