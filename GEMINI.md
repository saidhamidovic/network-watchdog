# Home Network Security Project

This project aims to monitor and secure the home network using automated scanning and alerting.

## 🛡️ Security Audit Results (April 17, 2026)

### Initial Findings:
*   **Router (192.168.0.1):** Multiple vulnerabilities in `dnsmasq` (DNS poisoning/DoS) and `MiniUPnP 2.0` (Critical 9.8 vulnerability).
*   **Home Assistant (192.168.0.106):** Outdated Samba version (4.6.2) with critical vulnerabilities (ZeroLogon, SambaCry).

### Actions Taken:
*   ✅ **Home Assistant Hardening:** Updated Home Assistant and removed the Samba service. Follow-up scan confirmed ports are closed and vulnerabilities resolved.
*   ✅ **Network Watchdog Deployed:** A Dockerized Python application was built and deployed to `cako@192.168.0.150` to provide continuous monitoring.

## 🛰️ Network Watchdog 2.0 (Scanner Application)

The Watchdog performs periodic `nmap` vulnerability scans and alerts the user of any changes in the network structure or security posture.

### Features:
*   **Intelligent Monitoring:** Now parses XML results to identify specifically **what** changed.
*   **Smart Alerts:** Instead of generic alerts, it tells you exactly what happened (e.g., "NEW DEVICE: 192.168.0.45").
*   **Optimized Frequency:** Scans the `192.168.0.0/24` range **3 times a day** (every 8 hours) to reduce network noise.
*   **Baseline Comparison:** Compares each scan against a "known safe" baseline (`baseline.xml`).
*   **Real-time Alerts:** Sends push notifications to the user's phone via **ntfy.sh** if a change is detected.

### Deployment Details:
*   **Location:** `cako@192.168.0.150:~/networkscanner/`
*   **Stack:** Docker, Python 3, Alpine Linux, Nmap.
*   **Notification Topic:** `hamidovic-scan-network8350`

### Maintenance:
To view logs or check status on the remote server:
```bash
cd ~/networkscanner
docker compose logs -f
```

## 📋 Outstanding Recommendations:
1.  **Router Firmware:** Update router firmware to patch `dnsmasq` and `apache` vulnerabilities.
2.  **Disable UPnP:** Manually disable UPnP in the router settings to close the `MiniUPnP` security hole.
3.  **RPC Hardening:** Consider disabling `rpcbind` (Port 111) on Home Assistant if not required.
