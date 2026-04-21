# Network Watchdog 2.0

A Dockerized Python application that monitors your home network for security changes. It performs periodic `nmap` scans and alerts you via **ntfy.sh** if new devices or open ports are detected.

## Features

- **Intelligent Monitoring:** Parses XML results to identify specifically what changed in your network.
- **Smart Alerts:** Provides detailed notifications (e.g., "NEW DEVICE: 192.168.0.45").
- **Baseline Comparison:** Compares each scan against a "known safe" baseline (`baseline.xml`).
- **Real-time Alerts:** Sends push notifications via **ntfy.sh** if a change is detected.

## Requirements

- Docker and Docker Compose
- `nmap` (installed inside the container)
- Python 3.x (installed inside the container)

## Setup

1.  **Clone the repository.**
2.  **Configure environment variables:**
    Copy the `.env.example` file to `.env` and fill in your values.
    ```bash
    cp .env.example .env
    ```
3.  **Run with Docker Compose:**
    ```bash
    docker compose up -d
    ```

## Configuration

The following environment variables can be set in your `.env` file:

- `SCAN_TARGETS`: The IP range to scan (e.g., `192.168.1.0/24`).
- `SCAN_INTERVAL`: How often to scan (in seconds). Default is 28800 (8 hours).
- `NTFY_TOPIC`: Your private **ntfy.sh** topic for receiving alerts.

## Maintenance

To view logs or check status:
```bash
docker compose logs -f
```
