FROM python:3.9-slim

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    strace \
    net-tools \
    iputils-ping \
    traceroute \
    curl \
    iproute2 \
    iptables \
    autoconf \
    automake \
    libtool \
    build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY receiver-wolfssl.py receiver-openssl.py requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# Expose necessary ports
EXPOSE 80 443

# Copy and set up entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]