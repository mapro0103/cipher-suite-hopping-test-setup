FROM python:3.13-slim

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano \
    git \
    net-tools \
    iputils-ping \
    traceroute \
    curl \
    iproute2 \
    iptables \
    autoconf \
    libtool \
    automake \
    build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY receiver-wolfssl.py requirements.txt .

# Clone custom wolfssl-py
RUN git clone --recurse-submodules https://github.com/mapro0103/wolfssl-py-aesccm.git /app/wolfssl-py

# Install wolfssl-py using setup.py
WORKDIR /app/wolfssl-py
RUN pip3 install .

# Set working directory for the application
WORKDIR /app

# Install additional Python dependencies
RUN pip3 install -r requirements.txt

# Expose necessary ports
EXPOSE 80 443

# Copy and set up entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
