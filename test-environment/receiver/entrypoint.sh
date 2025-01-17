#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Monitor IP: ${IP_MONITOR}"

ip route add ${IP_SENDER} via ${IP_MONITOR}

python3 receiver.py
tail -f /dev/null