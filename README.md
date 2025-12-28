# PiNetScan

PiNetScan is a lightweight network monitoring and vulnerability scanner built for the Raspberry Pi. It scans your local network for connected devices, detects new or unauthorized devices by comparing against a previous baseline, checks for known vulnerabilities using Nmap's scripting engine, and sends email alerts when issues are found.

All activity is logged with timestamps for easy review.

## Features
- Host discovery (ping scan) across your local network
- Detection of new devices compared to a stored baseline
- Vulnerability scanning using Nmap NSE vuln scripts
- Email alerts for:
  - New devices detected
  - Vulnerabilities discovered
- Timestamped logging of:
  - Network changes (`network_activity.log`)
  - Vulnerabilities (`network_vulnerability.log`)
- Timezone-aware logging
- Single-run execution (ideal for scheduling via cron)

## Requirements
- Raspberry Pi running Raspberry Pi OS
- Python 3
- Nmap installed
- Internet access for sending email alerts

## Installation
1. Update your system
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. Install dependencies
   ```bash
   sudo apt install nmap python3-pip -y
   pip3 install python-nmap
   pip3 install tqdm
   ```
3. Create the project directory and script
   ```bash
   mkdir ~/PiNetScan && cd ~/PiNetScan
   nano PiNetScan.py
   ```
Paste the script code and save

## Configuration
Edit the configuration variables near the top of PiNetScan.py:
   ```python
   NETWORK_RANGE = '192.168.1.0/24'     # Your local network range
   EMAIL_TO = 'you@example.com'        # Where alerts are sent
   EMAIL_FROM = 'pi-alerts@example.com' # Sender (Gmail address)
   SMPT_SRVR = 'smtp.gmail.com'        # Usually leave as-is for Gmail
   SMTP_PORT = 587                     # Standard for TLS
   SMTP_PASS = 'your-16-char-app-password'  # Gmail App Password
   TIME_ZONE = 'America/New_York'      # e.g., 'Europe/London', 'Asia/Tokyo' (see note below)
   ```

### Gmail Setup (Recommended)
- Enable 2-Step Verification on your Google account.
- Go to: https://myaccount.google.com/apppasswords
- Generate an App Password (select "Mail" or "Custom").
- Use that 16-character password as SMTP_PASS.

### Time Zone
Set TIME_ZONE to a valid IANA time zone name (e.g., 'America/Los_Angeles', 'Europe/Paris').
List available zones with: 
   ```python
   python3 -c "from zoneinfo import available_timezones; print(sorted(available_timezones()))"
   ```
Leave blank ('') to use system default time.

## Running PiNetScan
### Manual Test Run
   ```bash
   python3 PiNetScan.py
   ```
This performs one full scan cycle and exits.

### Scheduling with Cron (Recommended)
Option 1: Run continuously on boot (ideal for frequent scans)
Since the script runs once and exits, it's perfect for cron scheduling.
Edit your crontab:
   ```bash
   crontab -e
   ```
**Examples:**
- Every 15 minutes:
   ```text
   */15 * * * * /usr/bin/python3 /home/pi/PiNetScan/PiNetScan.py >> /home/pi/PiNetScan/PiNetScan.log 2>&1
   ```
- Every hour:
   ```text
   0 * * * * /usr/bin/python3 /home/pi/PiNetScan/PiNetScan.py >> /home/pi/PiNetScan/PiNetScan.log 2>&1
   ```
- Twice a day (8 AM and 8 PM):
   ```text
   0 8,20 * * * /usr/bin/python3 /home/pi/PiNetScan/PiNetScan.py >> /home/pi/PiNetScan/PiNetScan.log 2>&1
   ```

## Files Generated
- baseline.json – Stores the last known network state (automatically managed)
- network_activity.log – Log of new device detections with timestamps
- network_vulnerability.log – Log of discovered vulnerabilities
- PiNetScan.log (optional) – Console output when run via cron

## Important Notes
- **Only scan networks you own or have explicit permission to scan.**
- Nmap --script vuln can be noisy and may trigger alerts on some networks - use responsibly.
- The first run will establish the baseline (no "new device" alerts on first execution).
- Test email delivery with a manual run before relying on alerts.

## Future Ideas
- Add device whitelisting to reduce false positives
- Telegram or Pushover notifications
- Web dashboard for viewing logs
- MAC address vendor lookup for better device identification