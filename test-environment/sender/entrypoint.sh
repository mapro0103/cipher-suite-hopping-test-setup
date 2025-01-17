#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Monitor IP: ${IP_MONITOR}"

ip route add ${IP_RECEIVER} via ${IP_MONITOR}

python3 sender.py
tail -f /dev/null