#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Monitor IP: ${IP_MONITOR}"

# # ip route add ${IP_SENDER} via ${IP_MONITOR}

# # iptables -A FORWARD -s ${IP_SENDER} -d ${IP_RECEIVER} -j ACCEPT
# # iptables -A FORWARD -s ${IP_RECEIVER} -d ${IP_SENDER} -j ACCEPT

# # iptables -t nat -A POSTROUTING -s ${IP_SENDER} -d ${IP_RECEIVER} -j MASQUERADE
# # iptables -t nat -A POSTROUTING -s ${IP_RECEIVER} -d ${IP_SENDER} -j MASQUERADE

echo Starting tcpdump capturing...
tcpdump -i eth0 tcp -w /tmp/capture.pcap 2>&1 | tee /dev/stderr &

python3 monitor.py
