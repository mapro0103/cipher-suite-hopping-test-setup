FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping traceroute curl tcpdump libpcap-dev iproute2 iptables && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY monitor.py requirements.txt .
RUN pip install -r requirements.txt

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
