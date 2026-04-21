FROM alpine:latest

# Install nmap, python3, requests, and CA certificates
RUN apk add --no-cache nmap nmap-scripts python3 py3-requests ca-certificates

# Set working directory
WORKDIR /app

# Create data directory
RUN mkdir /data

# Copy the scanner script
COPY scanner.py .

# Force python output to be unbuffered
ENV PYTHONUNBUFFERED=1

# Environment variables
ENV SCAN_TARGETS="192.168.0.0/24"
ENV SCAN_INTERVAL="3600"
ENV NTFY_TOPIC=""

# Run the scanner
CMD ["python3", "scanner.py"]
