FROM python:3.13-slim

WORKDIR /app

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

COPY receiver-wolfssl.py requirements.txt .

RUN git clone --recurse-submodules https://github.com/mapro0103/wolfssl-py-aesccm.git /app/wolfssl-py

WORKDIR /app/wolfssl-py
RUN pip3 install .

WORKDIR /app

RUN pip3 install -r requirements.txt

EXPOSE 80 443

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
