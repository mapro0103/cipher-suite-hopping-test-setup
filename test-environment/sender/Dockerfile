FROM python:3.9-slim

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
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
COPY sender-openssl.py sender-wolfssl.py requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy and set up entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
