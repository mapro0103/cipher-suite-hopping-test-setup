FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    curl \
    iproute2 \
    iptables \
    libpcap-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY permutations_5x5.json monitor.py requirements.txt .
RUN pip install -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]