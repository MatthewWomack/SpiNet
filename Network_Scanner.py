import nmap
import smtplib
from email.mime.text import MIMEText # Multipurpose Internet Mail Extensions
import json
from datetime import datetime
from zoneinfo import ZoneInfo

# Configuration
NETWORK_RANGE = ''              # IP address range on local network
EMAIL_TO = ''                   # Your email
EMAIL_FROM = ''                 # Setup an email for the pi
SMPT_SRVR = 'smtp.gmail.com'    # SMTP server for gmail
SMTP_PORT = 587                 # Uses TLS
SMTP_PASS = ''                  # Setup an app password
TIME_ZONE = ''                  # Current time zone (for keeping logs)


def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts=NETWORK_RANGE, arguments='-sn') # Host discovery only; no port scanning
    hosts=[]
    # Populate hosts with all currently connected hosts
    for host in nm.all_hosts():
        hosts.append({
            'ip': host,
            'hostname': nm[host].hostname(),
            'status': nm[host].state()
        })
    return hosts


def check_vulnerabilities(host_ip):
    nm = nmap.PortScanner()
    nm.scan(host_ip, arguments='-sV --script vuln') # Runs nmap's vulnerability scanning scripts
    vulns=[]
    # Iterate through every protocol (usually just tcp)
    for proto in nm[host_ip].all_protocols():
        # Iterate through every port
        for port in nm[host_ip][proto]:
            # For each port, Nmap may have run NSE (Nmap Scripting Engine) scripts
            if 'script' in nm[host_ip][proto][port]:
                # Loop through each script that was run on the port
                for script_id, output in nm[host_ip][proto][port]['script'].items():
                    # Only include vulnerability-related scripts
                    if 'vuln' in script_id.lower():
                        # Append the vulnerability found and on which port it was found
                        vulns.append(f"Port {port}: {output}")
    # Log vulnerabilities and send an email alert
    if vulns:
        log_vulns(vulns)
        alert_msg=f"Vulnerabilities have been discovered on the network: {vulns}"
        send_alert("Vulnerabilities Found", alert_msg)


def load_baseline():
    try:
        # Read from baseline.json
        with open('baseline.json', 'r') as bl:
            results=json.load(bl)
    except FileNotFoundError:
        results=[]
    return results


def save_baseline(data):
    # Overwrite baseline.json
    with open('baseline.json', 'w') as file:
        json.dump(data, file)


def detect_changes(current, baseline):
    new_hosts=[]
    old_hosts=[]

    # Get all previously connected IP addresses
    for b in baseline:
        old_hosts.append(b['ip'])
    
    # If any current host was not previously connected to the network, add it to the list
    for h in current:
        if h['ip'] not in old_hosts:
            new_hosts.append(h)
    
    # If new host list is not empty, alert the user
    if new_hosts:
        alert_msg=f"New device(s) detected: {new_hosts}"
        send_alert("New Device Alert", alert_msg)
        print(alert_msg)
        log_changes(new_hosts)


def send_alert(subject, msg):
    email=MIMEText(msg)
    email['Subject']=subject
    email['From']=EMAIL_FROM
    email['To']=EMAIL_TO

    with smtplib.SMTP(SMPT_SRVR, SMTP_PORT) as smtp_serv:
        smtp_serv.login(EMAIL_FROM, SMTP_PASS)
        smtp_serv.sendmail(EMAIL_FROM, EMAIL_TO, email.as_string())


def log_changes(changes):
    try:
        # Append changes in network activity to network_activity.log
        with open('network_activity.log', 'a') as log:
            # Set current time zone
            if TIME_ZONE:
                current_time = datetime.now(ZoneInfo(TIME_ZONE))
            log_msg=f"\n\n{current_time}\n{changes}"
            log.write(log_msg)
    except (OSError, IOError) as e:
        print(f"Error appending to file: {e}")


def log_vulns(vulns):
    try:
        # Append network vulnerabilities to network_vulnerability.log
        with open('network_vulnerability.log', 'a') as log:
            # Set current time zone
            if TIME_ZONE:
                current_time = datetime.now(ZoneInfo(TIME_ZONE))
            log_msg=f"\n\n{current_time}\n{vulns}"
            log.write(log_msg)
    except (OSError, IOError) as e:
        print(f"Error appending to file: {e}")


def main():
    baseline=load_baseline()
    current=scan_network()
    
    save_baseline(current)
    detect_changes(current, baseline)

    for host in current:
        check_vulnerabilities(host['ip'])


if __name__ == "__main__":
    main()