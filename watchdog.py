import subprocess
import json
import os
import time
import urllib.request
import xml.etree.ElementTree as ET
import threading
import re
from datetime import datetime

# --- Configuration ---
TARGETS = os.environ.get("SCAN_TARGETS", "192.168.0.0/24")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "28800"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
BASELINE_FILE = os.path.join(DATA_DIR, "baseline.xml")
LOG_FILE = os.path.join(DATA_DIR, "watchdog.log")

AUTH_LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
AUDIT_LOG = os.environ.get("AUDIT_LOG", "/var/log/audit/audit.log")
FAIL2BAN_LOG = os.environ.get("FAIL2BAN_LOG", "/var/log/fail2ban.log")
SECURITY_LOG = os.environ.get("SECURITY_LOG", "/var/log/securityguardian.log")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.0.1")
ARP_INTERVAL = int(os.environ.get("ARP_INTERVAL", "60"))
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")

# --- Helper Functions ---
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] {message}"
    print(msg, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"Failed to write to log: {e}", flush=True)

def send_notification(message, title="WatchDog Alert"):
    if not NTFY_TOPIC:
        return
    
    try:
        url = f"https://ntfy.sh/{NTFY_TOPIC}"
        data = message.encode('ascii', 'ignore')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header("Title", title)
        req.add_header("Priority", "high")
        
        with urllib.request.urlopen(req) as response:
            pass
    except Exception as e:
        log(f"Notification failed: {e}")

# --- Feature 1: Network Scanner (Periodic & Targeted) ---
def parse_nmap_xml(xml_content):
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

def run_scan(specific_target=None):
    target = specific_target if specific_target else TARGETS
    log(f"Scanning {target}...")
    cmd = ["nmap", "-sV", "--script", "vuln", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        log(f"Scan failed for {target}: {e}")
        return None

def network_monitor():
    log(f"Network monitor started. Frequency: {SCAN_INTERVAL}s")
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
                    log("No network changes detected.")
        
        time.sleep(SCAN_INTERVAL)

# --- Feature 2: SSH Monitor (Real-time) ---
def ssh_monitor():
    log(f"Starting SSH monitor on {AUTH_LOG}...")
    if not os.path.exists(AUTH_LOG):
        log(f"SSH Monitor standby: {AUTH_LOG} not found.")
        return

    try:
        process = subprocess.Popen(["tail", "-F", AUTH_LOG], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        fail_re = re.compile(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
        success_re = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

        for line in process.stdout:
            match_fail = fail_re.search(line)
            if match_fail:
                user = match_fail.group(2)
                ip = match_fail.group(3)
                msg = f"FAILED SSH LOGIN: User '{user}' from {ip}"
                log(msg)
                send_notification(msg, title="SSH Intrusion Alert")

            match_success = success_re.search(line)
            if match_success:
                user = match_success.group(1)
                ip = match_success.group(2)
                msg = f"SUCCESSFUL SSH LOGIN: User '{user}' from {ip}"
                log(msg)
                send_notification(msg, title="SSH Login Success")
    except Exception as e:
        log(f"SSH Monitor Error: {e}")

# --- Feature 3: ARP Monitor (Real-time & Discovery) ---
def get_all_neighbors():
    """Returns a dict of IP -> MAC from the system ARP table."""
    neighbors = {}
    try:
        # Quick ping sweep to populate ARP table silently
        subprocess.run(["nmap", "-sn", TARGETS], capture_output=True)
        res = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        for line in lines:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})", line)
            if match:
                neighbors[match.group(1)] = match.group(2).lower()
    except Exception as e:
        log(f"Error fetching neighbors: {e}")
    return neighbors

def arp_monitor():
    log(f"Starting ARP/Discovery monitor for {TARGETS}...")
    known_ips = set()
    gateway_baseline_mac = None
    
    # Load known IPs from baseline
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r") as f:
                data = parse_nmap_xml(f.read())
                if data:
                    known_ips.update(data.keys())
                    log(f"Loaded {len(known_ips)} known IPs from baseline.")
        except: pass

    while True:
        current_neighbors = get_all_neighbors()
        
        # 1. Gateway Spoofing Check
        if GATEWAY_IP in current_neighbors:
            current_gw_mac = current_neighbors[GATEWAY_IP]
            if gateway_baseline_mac is None:
                gateway_baseline_mac = current_gw_mac
                log(f"ARP Baseline set: {GATEWAY_IP} is at {gateway_baseline_mac}")
            elif current_gw_mac != gateway_baseline_mac:
                msg = f"ARP SPOOFING DETECTED! Gateway {GATEWAY_IP} changed from {gateway_baseline_mac} to {current_gw_mac}"
                log(msg)
                send_notification(msg, title="MITM Attack Alert")

        # 2. New Device Check (Immediate Scan)
        for ip in current_neighbors:
            if ip not in known_ips:
                log(f"DISCOVERY: New IP {ip} detected. Triggering immediate scan.")
                send_notification(f"New device {ip} appeared. Performing deep scan...", title="Device Discovery")
                
                scan_xml = run_scan(specific_target=ip)
                if scan_xml:
                    scan_data = parse_nmap_xml(scan_xml)
                    if scan_data and ip in scan_data:
                        ports = ", ".join(scan_data[ip])
                        alert = f"SCAN RESULT for {ip}: MAC {current_neighbors[ip]} | Ports: {ports}"
                        log(alert)
                        send_notification(alert, title="New Device Details")
                        known_ips.add(ip)
        
        time.sleep(ARP_INTERVAL)

# --- Feature 4: Fail2ban Monitor (Real-time) ---
def fail2ban_monitor():
    log(f"Starting Fail2ban monitor on {FAIL2BAN_LOG}...")
    if not os.path.exists(FAIL2BAN_LOG):
        # Create it if it doesn't exist to avoid tail error
        try: open(FAIL2BAN_LOG, 'a').close()
        except: pass

    try:
        process = subprocess.Popen(["tail", "-F", FAIL2BAN_LOG], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ban_re = re.compile(r"NOTICE\s+\[(\S+)\]\s+Ban\s+(\d+\.\d+\.\d+\.\d+)")
        for line in process.stdout:
            match = ban_re.search(line)
            if match:
                jail = match.group(1)
                ip = match.group(2)
                msg = f"IP BANNED: {ip} (Jail: {jail})"
                log(msg)
                send_notification(msg, title="Fail2ban Action")
    except Exception as e:
        log(f"Fail2ban Monitor Error: {e}")

# --- Feature 5: Auditd Monitor (Kernel Events) ---
def audit_monitor():
    log(f"Starting Auditd monitor on {AUDIT_LOG}...")
    if not os.path.exists(AUDIT_LOG):
        log(f"Auditd Monitor standby: {AUDIT_LOG} not found. (Install auditd on host!)")
        return

    try:
        # Use stdbuf or bufsize=1 to avoid buffering issues
        process = subprocess.Popen(["tail", "-F", AUDIT_LOG], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        for line in process.stdout:
            # Detect file modifications to sensitive files
            if "type=PATH" in line:
                name_match = re.search(r'name="([^"]+)"', line)
                if name_match:
                    file_path = name_match.group(1)
                    if any(x in file_path for x in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/authorized_keys"]):
                        msg = f"CRITICAL FILE MODIFIED: {file_path}"
                        log(msg)
                        send_notification(msg, title="Kernel Audit Alert")

            # Detect execution of high-risk commands
            if "type=EXECVE" in line:
                cmd_match = re.search(r'argc=\d+(.*)', line)
                if cmd_match:
                    # Clean up the arguments for readability
                    cmd_args = re.sub(r'a\d+="([^"]+)"', r'\1', cmd_match.group(1)).replace('a0=', '').replace('a1=', ' ').replace('a2=', ' ')
                    if any(x in cmd_args for x in ["useradd", "usermod", "chmod 777", "chown", "passwd"]):
                        msg = f"SENSITIVE COMMAND EXECUTED: {cmd_args.strip()}"
                        log(msg)
                        send_notification(msg, title="Privilege Activity")
    except Exception as e:
        log(f"Auditd Monitor Error: {e}")

# --- Main ---
def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    # Ensure security log exists for fail2ban to read
    if not os.path.exists(SECURITY_LOG):
        try:
            open(SECURITY_LOG, 'a').close()
            os.chmod(SECURITY_LOG, 0o666)
        except: pass

    log(f"WatchDog Unified starting. Topic: {NTFY_TOPIC}")
    send_notification("WatchDog Unified is online. All security modules (Network, SSH, ARP, Fail2ban, Audit) active.", title="WatchDog Online")

    threads = [
        threading.Thread(target=network_monitor, daemon=True),
        threading.Thread(target=ssh_monitor, daemon=True),
        threading.Thread(target=arp_monitor, daemon=True),
        threading.Thread(target=fail2ban_monitor, daemon=True),
        threading.Thread(target=audit_monitor, daemon=True)
    ]
    
    for t in threads:
        t.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
