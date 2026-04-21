# Security Guardian

A real-time security monitor and active defense system for your Linux server and network.

## Features
- **SSH Monitor:** Alerts on failed and successful SSH logins by watching `/var/log/auth.log`.
- **ARP Monitor:** Detects ARP spoofing (Man-in-the-Middle) attacks by monitoring your Gateway's MAC address.
- **Fail2ban Integration:** 
    - **Notifications:** Real-time push notifications when an IP is banned.
    - **Active Banning:** `guardian.py` can trigger bans by writing to a shared security log.
- **ntfy.sh Integration:** Sends high-priority push notifications to your phone.

## Architecture
This application uses a multi-container setup:
1.  **Guardian:** A Python service that monitors logs and network state.
2.  **Fail2ban:** A standard Fail2ban service that manages the host's firewall (`iptables`).

The two services communicate via shared volumes in `/var/log`.

## Setup
1. Copy `.env.example` to `.env` and configure your settings.
2. Ensure `/var/log/auth.log` exists on your host (standard on Debian/Ubuntu).
3. Run with Docker:
   ```bash
   docker compose up -d
   ```

## Active Banning
The system is configured with a custom Fail2ban jail called `securityguardian`. If the Python script detects a high-severity threat, it writes a `BAN_REQUEST` to `/var/log/securityguardian.log`. Fail2ban picks this up immediately and bans the offending IP for 24 hours.
