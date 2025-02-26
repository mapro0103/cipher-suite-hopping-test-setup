#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Intermediate IP: ${IP_INTERMEDIATE}"
echo "Monitor IP: ${IP_MONITOR}"

ip route add ${IP_RECEIVER} via ${IP_INTERMEDIATE}

python3 sender-wolfssl.py
tail -f /dev/null