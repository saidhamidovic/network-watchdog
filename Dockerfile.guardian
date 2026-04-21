FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY guardian.py .

CMD ["python", "guardian.py"]
