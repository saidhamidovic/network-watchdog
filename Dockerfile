FROM alpine:latest

# Install security and network tools
# nmap: For network scanning
# iproute2: For 'ip neigh' (ARP monitoring)
# iputils: For 'ping' (populating ARP table)
# python3: For the application
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    python3 \
    iproute2 \
    iputils \
    ca-certificates

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /data /var/log

# Copy the unified watchdog script
COPY watchdog.py .

# Force python output to be unbuffered for real-time logs
ENV PYTHONUNBUFFERED=1

# Default environment variables
ENV SCAN_TARGETS="192.168.0.0/24"
ENV SCAN_INTERVAL="28800"
ENV NTFY_TOPIC=""
ENV GATEWAY_IP="192.168.0.1"

# Run the unified watchdog
CMD ["python3", "watchdog.py"]
