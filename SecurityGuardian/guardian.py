import os
import time
import subprocess
import re
import threading
import urllib.request
from datetime import datetime

# Config
AUTH_LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
FAIL2BAN_LOG = os.environ.get("FAIL2BAN_LOG", "/var/log/fail2ban.log")
SECURITY_LOG = os.environ.get("SECURITY_LOG", "/var/log/securityguardian.log")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.0.1")
ARP_INTERVAL = int(os.environ.get("ARP_INTERVAL", "60"))
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")

def log_msg(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)

def send_notification(message, title="Security Alert"):
    if not NTFY_TOPIC: return
    try:
        url = f"https://ntfy.sh/{NTFY_TOPIC}"
        data = message.encode('ascii', 'ignore')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header("Title", title)
        req.add_header("Priority", "high")
        
        with urllib.request.urlopen(req) as response:
            pass
    except Exception as e:
        log_msg(f"Notification failed: {e}")

def request_ban(ip, reason="Manual trigger"):
    """Writes a ban request to the security log for fail2ban to process."""
    try:
        with open(SECURITY_LOG, "a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] BAN_REQUEST IP={ip} REASON=\"{reason}\"\n")
        log_msg(f"Ban requested for {ip} (Reason: {reason})")
    except Exception as e:
        log_msg(f"Failed to write to {SECURITY_LOG}: {e}")

# --- Feature 1: SSH Monitor ---
def monitor_ssh():
    log_msg(f"Starting SSH monitor on {AUTH_LOG}...")
    if not os.path.exists(AUTH_LOG):
        log_msg(f"ERROR: {AUTH_LOG} not found. Ensure it is mounted correctly.")
        return

    try:
        # Use tail -F (follow by name, retry if file rotated)
        process = subprocess.Popen(["tail", "-F", AUTH_LOG], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Regex for SSH events
        # Example: Apr 21 09:35:01 ubuntu sshd[1234]: Failed password for root from 192.168.0.50 port 54321 ssh2
        fail_re = re.compile(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
        success_re = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

        for line in process.stdout:
            # Check for failure
            match_fail = fail_re.search(line)
            if match_fail:
                user = match_fail.group(2)
                ip = match_fail.group(3)
                msg = f"FAILED SSH LOGIN: User '{user}' from {ip}"
                log_msg(msg)
                send_notification(msg, title="SSH Intrusion Alert")

            # Check for success
            match_success = success_re.search(line)
            if match_success:
                user = match_success.group(1)
                ip = match_success.group(2)
                msg = f"SUCCESSFUL SSH LOGIN: User '{user}' from {ip}"
                log_msg(msg)
                send_notification(msg, title="SSH Login Success")
                
    except Exception as e:
        log_msg(f"SSH Monitor Error: {e}")

# --- Feature 2: ARP Monitor ---
def get_mac(ip):
    """Uses the 'ip neighbor' command to find the MAC address for an IP."""
    try:
        # We ping first to populate the ARP table
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
        res = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True)
        # Output looks like: 192.168.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", res.stdout)
        return match.group(1) if match else None
    except Exception:
        return None

def monitor_arp():
    log_msg(f"Starting ARP monitor for Gateway {GATEWAY_IP}...")
    baseline_mac = None
    
    while True:
        current_mac = get_mac(GATEWAY_IP)
        if current_mac:
            if baseline_mac is None:
                baseline_mac = current_mac
                log_msg(f"ARP Baseline set: {GATEWAY_IP} is at {baseline_mac}")
            elif current_mac.lower() != baseline_mac.lower():
                msg = f"ARP SPOOFING DETECTED! Gateway {GATEWAY_IP} changed from {baseline_mac} to {current_mac}"
                log_msg(msg)
                send_notification(msg, title="MITM Attack Alert")
                # Update baseline if you want to silence future alerts for this new MAC
                # baseline_mac = current_mac 
        
        time.sleep(ARP_INTERVAL)

# --- Feature 3: Fail2ban Monitor ---
def monitor_fail2ban():
    log_msg(f"Starting Fail2ban monitor on {FAIL2BAN_LOG}...")
    
    # Ensure log file exists so tail doesn't fail immediately
    if not os.path.exists(FAIL2BAN_LOG):
        try:
            open(FAIL2BAN_LOG, 'a').close()
        except Exception:
            pass

    try:
        process = subprocess.Popen(["tail", "-F", FAIL2BAN_LOG], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Regex for Fail2ban events
        # Example: 2023-10-21 15:30:00,123 fail2ban.actions [123]: NOTICE [sshd] Ban 192.168.0.50
        ban_re = re.compile(r"NOTICE\s+\[(\S+)\]\s+Ban\s+(\d+\.\d+\.\d+\.\d+)")

        for line in process.stdout:
            match = ban_re.search(line)
            if match:
                jail = match.group(1)
                ip = match.group(2)
                msg = f"IP BANNED: {ip} (Jail: {jail})"
                log_msg(msg)
                send_notification(msg, title="Fail2ban Action")
    except Exception as e:
        log_msg(f"Fail2ban Monitor Error: {e}")

def main():
    if not NTFY_TOPIC:
        log_msg("WARNING: NTFY_TOPIC not set. Alerts will only show in logs.")
    
    # Ensure security log exists
    if not os.path.exists(SECURITY_LOG):
        try:
            open(SECURITY_LOG, 'a').close()
            # Set permissions to allow writing if mounted from host
            os.chmod(SECURITY_LOG, 0o666)
        except Exception:
            pass

    # Start threads
    threads = [
        threading.Thread(target=monitor_ssh, daemon=True),
        threading.Thread(target=monitor_arp, daemon=True),
        threading.Thread(target=monitor_fail2ban, daemon=True)
    ]
    
    for t in threads:
        t.start()
    
    # Keep main alive
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
