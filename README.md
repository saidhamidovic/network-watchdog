# 🛰️ WatchDog Unified

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Security-IDS%20%2F%20Monitoring-E03C11?style=flat-square" alt="Security" />
  <img src="https://img.shields.io/badge/Scanner-Nmap-0052CC?style=flat-square" alt="Nmap" />
  <img src="https://img.shields.io/badge/Alerts-ntfy.sh-88171A?style=flat-square" alt="ntfy" />
</p>

A comprehensive home network security suite that combines proactive scanning with real-time intrusion detection.

## Features

- **Network Scanning:** Periodic `nmap` scans to detect new devices and open ports/vulnerabilities.
- **SSH Login Guard:** Real-time monitoring of `/var/log/auth.log` for failed and successful logins.
- **ARP Spoofing Detector:** Continuous monitoring of the Gateway MAC address to prevent MITM attacks.
- **Fail2ban Integration:** Monitors and alerts on Fail2ban actions.
- **Real-time Alerts:** Instant push notifications via **ntfy.sh**.

## Setup

1. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your network details and ntfy topic
   ```
2. **Run with Docker Compose:**
   ```bash
   docker compose up -d
   ```

## Configuration (.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `SCAN_TARGETS` | IP range to scan | `192.168.0.0/24` |
| `SCAN_INTERVAL` | Seconds between network scans | `28800` (8h) |
| `NTFY_TOPIC` | Your ntfy.sh topic | (required) |
| `GATEWAY_IP` | Your router's IP for ARP monitoring | `192.168.0.1` |
| `ARP_INTERVAL` | Seconds between ARP checks | `60` |

## Maintenance

View real-time security logs:
```bash
docker compose logs -f
```
Check the internal log file:
```bash
tail -f data/watchdog.log
```
