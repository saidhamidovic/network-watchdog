import subprocess
import json
import os
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

# Global config
TARGETS = os.environ.get("SCAN_TARGETS", "192.168.0.0/24")
# 3 times a day = every 8 hours (28800 seconds)
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "28800"))
DATA_DIR = "/data"
BASELINE_FILE = os.path.join(DATA_DIR, "baseline.xml")
LOG_FILE = os.path.join(DATA_DIR, "watchdog.log")

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] {message}"
    print(msg, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"Failed to write to log: {e}", flush=True)

def send_notification(message, title="Network Alert"):
    topic = os.environ.get("NTFY_TOPIC", "")
    if not topic:
        log("No NTFY_TOPIC configured")
        return
    
    try:
        url = f"https://ntfy.sh/{topic}"
        data = message.encode('ascii', 'ignore') # Ensure plain text for stability
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header("Title", title)
        req.add_header("Priority", "high")
        
        with urllib.request.urlopen(req) as response:
            log(f"Notification sent to {topic}")
    except Exception as e:
        log(f"Notification failed: {e}")

def parse_nmap_xml(xml_content):
    """Parses nmap XML and returns a simplified dict of hosts and their open ports."""
    try:
        root = ET.fromstring(xml_content)
        network_data = {}
        
        for host in root.findall('host'):
            addr_elem = host.find('address')
            if addr_elem is None: continue
            ip = addr_elem.get('addr')
            
            ports = []
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else "unknown"
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else "unknown"
                
                if state == 'open':
                    ports.append(f"{port_id}/{service}")
            
            network_data[ip] = sorted(ports)
        return network_data
    except Exception as e:
        log(f"Error parsing XML: {e}")
        return None

def run_scan():
    log(f"Scanning {TARGETS}...")
    cmd = ["nmap", "-sV", "--script", "vuln", "-oX", "-", TARGETS]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        log(f"Scan failed: {e}")
        return None

def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    topic = os.environ.get("NTFY_TOPIC", "NOT SET")
    log(f"Watchdog 2.0 starting. Frequency: 3/day. Topic: {topic}")
    
    send_notification("Watchdog 2.0 is online. Intelligent change detection active.", title="Watchdog Online")
    
    while True:
        current_xml = run_scan()
        if current_xml:
            current_data = parse_nmap_xml(current_xml)
            if current_data is None:
                log("Failed to parse scan data.")
                time.sleep(60)
                continue
            
            if not os.path.exists(BASELINE_FILE):
                log("Saving initial baseline.")
                with open(BASELINE_FILE, "w") as f:
                    f.write(current_xml)
                send_notification(f"Baseline established. Found {len(current_data)} active hosts.", title="Baseline OK")
            else:
                with open(BASELINE_FILE, "r") as f:
                    baseline_xml = f.read()
                
                baseline_data = parse_nmap_xml(baseline_xml)
                if baseline_data is None:
                    log("Baseline file corrupted, recreating.")
                    os.remove(BASELINE_FILE)
                    continue

                changes = []
                for ip in current_data:
                    if ip not in baseline_data:
                        changes.append(f"NEW DEVICE: {ip} ports: {', '.join(current_data[ip])}")
                    else:
                        new_ports = set(current_data[ip]) - set(baseline_data[ip])
                        if new_ports:
                            changes.append(f"NEW PORTS on {ip}: {', '.join(new_ports)}")
                
                if changes:
                    alert_msg = " | ".join(changes)
                    log(f"ALERT: {alert_msg}")
                    send_notification(alert_msg, title="Network Security Alert")
                    with open(BASELINE_FILE, "w") as f:
                        f.write(current_xml)
                else:
                    log("No changes detected.")
        
        log(f"Waiting {SCAN_INTERVAL}s for next scan...")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
