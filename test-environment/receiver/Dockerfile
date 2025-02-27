FROM python:3.13-slim

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano \
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
    python3-dev \
    libffi-dev \
    pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY receiver-wolfssl.py receiver-openssl.py requirements.txt .

# Clone wolfssl-py
RUN git clone --recurse-submodules https://github.com/mapro0103/wolfssl-py-aesccm.git /app/wolfssl-py

# # Modify _build_ffi.py to include --enable-aesccm
# RUN sed -i '/flags.append("--enable-dtls13")/a\    flags.append("--enable-aesccm")' /app/wolfssl-py/wolfssl/_build_ffi.py

# # Build wolfSSL with AESCCM enabled before installing wolfssl-py
# WORKDIR /app/wolfssl-py/lib/wolfssl
# RUN autoreconf -i && \
#     ./configure \
#       --enable-all \
#       --enable-aesccm \
#       --enable-aesgcm \
#       --enable-tls13 \
#       --enable-dtls \
#       --enable-opensslextra \
#       --enable-debug \
#       --enable-certgen \
#       --enable-certreq \
#       --enable-crl \
#       --enable-ocsp \
#       --enable-session-ticket \
#       --enable-sni && \
#     make -j$(nproc) && \
#     make install

# Install wolfssl-py using setup.py
WORKDIR /app/wolfssl-py
RUN pip install .

# Set working directory for the application
WORKDIR /app

# Install additional Python dependencies
RUN pip install -r requirements.txt

# Expose necessary ports
EXPOSE 80 443

# Copy and set up entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
