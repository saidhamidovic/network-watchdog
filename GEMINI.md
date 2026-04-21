# Home Network Security Suite

This workspace contains two independent security applications for monitoring and protecting the home network.

## 1. 🛰️ Network Watchdog 2.0
Periodic `nmap` vulnerability scanning and network change detection.

### Features:
*   **Intelligent Monitoring:** Parses XML results to identify specifically **what** changed.
*   **Baseline Comparison:** Compares scans against `baseline.xml`.
*   **Real-time Alerts:** Sends push notifications via **ntfy.sh**.
*   **Deployment:** `docker compose up -d` in the root directory.

---

## 2. 🛡️ Security Guardian (NEW)
Real-time monitoring for server intrusions and network attacks.

### Features:
*   **SSH Login Guard:** Tails `/var/log/auth.log` for failed/successful logins.
*   **ARP Spoofing Detector:** Monitors Gateway MAC address to prevent MITM attacks.
*   **Real-time Alerts:** High-priority notifications via **ntfy.sh**.
*   **Deployment:** `docker compose up -d` inside the `SecurityGuardian/` directory.

---

## 📁 Project Structure
```text
/home/cako/gemini_projects/HomeNetwork/
├── scanner.py             # Watchdog scanning logic
├── Dockerfile             # Watchdog container config
├── docker-compose.yml     # Watchdog service orchestration
├── README.md              # Watchdog documentation
└── SecurityGuardian/      # Dedicated directory for Guardian
    ├── guardian.py        # SSH & ARP monitoring logic
    ├── Dockerfile         # Guardian container config
    ├── docker-compose.yml # Guardian service orchestration
    └── README.md          # Guardian documentation
```

## 🛡️ Security Audit History
*   **Router (192.168.0.1):** Multiple vulnerabilities in `dnsmasq` and `MiniUPnP 2.0`.
*   **Home Assistant (192.168.0.106):** Outdated Samba service (Removed).
*   **Status:** Hardened. Both Watchdog and Guardian are deployed for continuous protection.

## 📋 Outstanding Recommendations:
1.  **Router Firmware:** Update to patch `dnsmasq` vulnerabilities.
2.  **Disable UPnP:** Close the `MiniUPnP` security hole in router settings.
3.  **RPC Hardening:** Disable `rpcbind` (Port 111) on Home Assistant.
