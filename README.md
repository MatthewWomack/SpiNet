# SpiNet

SpiNet is a lightweight, customizable network monitoring and vulnerability scanner designed to run on a Raspberry Pi (tested on Raspberry Pi 3 and newer). It periodically scans your local network, detects new or rogue devices by comparing against a stored baseline, performs basic vulnerability checks using Nmap's scripting engine, and sends email alerts when suspicious activity is detected.

Great as a standalone home network watchdog or as a building block for a larger Raspberry Pi security hub.

## Features

- Host discovery across your local network
- Detection of new devices (potential unauthorized connections)
- Basic vulnerability detection using Nmap NSE vulnerability scripts
- Email alerts for new devices and detected vulnerabilities
- Persistent baseline (JSON file) for reliable change detection
- Console logging for real-time monitoring and debugging
- Low resource usage – runs comfortably 24/7 on a Raspberry Pi 3

## Requirements

- Raspberry Pi with Raspberry Pi OS (Lite recommended for headless use)
- Python 3
- Nmap
- Internet access (for setup and sending email alerts)

## Installation

1. Update your system
   ```bash
   sudo apt update && sudo apt upgrade -y

2. Install dependencies
   sudo apt install nmap python3-pip -y
   pip3 install python-nmap

3. Create the project directory and script
   mkdir ~/SpiNet && cd ~/SpiNet
   nano spinet.py
Paste the script code and save

## Configuration

Edit the configuration variables near the top of spinet.py:
- Network: Your local subnet (e.g., '192.168.1.0/24')
- Email Settings (Gmail example):
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USER = 'your@gmail.com'
    SMTP_PASS = 'your-16-character-app-password'
Gmail Setup Tip:
- Enable 2-Step Verification on your Google account.
- Generate an App Password at https://myaccount.google.com/apppasswords.
- Use the generated 16-character password (never your regular password).

Security Note: For long-term use, consider moving credentials to environment variables or a separate config file instead of hardcoding them.

## Running SpiNet

Manual Test Run
    python3 spinet.py
(Press Ctrl+C to stop)

Scheduling with Cron (Recommended)
Option 1: Run continuously on boot (ideal for frequent scans)
The script uses an infinite loop with time.sleep(). Start it automatically:
    Bashcrontab -e
Add this line:
    text@reboot /usr/bin/python3 /home/pi/SpiNet/spinet.py >> /home/pi/SpiNet/spinet.log 2>&1
This launches SpiNet on every reboot and logs output to spinet.log.
Option 2: Periodic scheduled runs
If you prefer discrete scans (e.g., every 30 minutes), modify the script to run once (remove the infinite loop) or add a command-line flag.
Then schedule:
    Bashcrontab -e
Add:
    text*/30 * * * * /usr/bin/python3 /home/pi/SpiNet/spinet.py >> /home/pi/SpiNet/spinet.log 2>&1

## Files Generated

- baseline.json – Stores the last known network state
- spinet.log (optional) – Log file when output is redirected

## Customization Ideas

- Replace email alerts with Telegram, Discord, or Pushover notifications
- Add a Flask web dashboard for viewing results
- Store historical scans in SQLite
- Whitelist trusted devices to reduce false positives
- Include MAC vendor lookup for better device identification

## Important Notes

- Only scan networks you own or have explicit permission to scan.
- Nmap vulnerability scripts can generate network traffic – use responsibly.
- Adjust scan parameters for larger networks to avoid overloading the Pi.
- Test email configuration separately before relying on alerts.