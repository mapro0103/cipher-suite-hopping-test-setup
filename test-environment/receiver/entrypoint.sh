#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Intermediate IP: ${IP_INTERMEDIATE}"
echo "Monitor IP: ${IP_MONITOR}"

ip route add ${IP_SENDER} via ${IP_INTERMEDIATE}

python3 receiver-wolfssl.py
tail -f /dev/null