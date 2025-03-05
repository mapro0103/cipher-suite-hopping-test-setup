#!/bin/bash

# Allow forwarding of packets between sender and receiver
# -P: Set default policy for a chain (FORWARD in this case)
echo "Setting up iptables rules..."
iptables -P FORWARD ACCEPT  # Allow all forwarded packets

# Mirror packets from sender to receiver to the monitoring container
# -t mangle: Modify packet headers
# -A PREROUTING: Apply rule before routing decisions
# -s: Match packets with the given source IP
# -d: Match packets with the given destination IP
# -j TEE: Duplicate packets to another gateway
# --gateway: The IP address to send the mirrored packets to
# echo "Mirroring packets to the monitor..."
iptables -t mangle -A POSTROUTING -s ${IP_SENDER} -d ${IP_RECEIVER} -j TEE --gateway ${IP_MONITOR}
iptables -t mangle -A POSTROUTING -s ${IP_RECEIVER} -d ${IP_SENDER} -j TEE --gateway ${IP_MONITOR}

tail -f /dev/null
