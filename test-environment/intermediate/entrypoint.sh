#!/bin/bash

# # Clear any existing iptables rules
# # This ensures that previous rules do not interfere with the new setup
# # -F: Flush all rules from the specified table (default is filter)
# # echo "Clearing previous iptables rules..."
# iptables -F  # Flush all rules from the default filter table
# iptables -t nat -F  # Flush NAT table rules
# iptables -t mangle -F  # Flush mangle table rules (used for packet modification)

# Allow forwarding of packets between sender and receiver
# -P: Set default policy for a chain (FORWARD in this case)
echo "Setting up iptables rules..."
iptables -P FORWARD ACCEPT  # Allow all forwarded packets

# # Uncomment the following lines if NAT (Network Address Translation) is required
# # NAT can be useful when the intermediate node is acting as a gateway
# # -A: Append a rule to the specified table and chain
# # -t nat: Operate on the NAT table
# # -A POSTROUTING: Modify packets after routing decisions have been made
# # -s: Match packets with the given source IP
# # -d: Match packets with the given destination IP
# # -j MASQUERADE: Change source IP to the router's IP (useful for dynamic IPs)
# iptables -t nat -A POSTROUTING -s ${IP_SENDER} -d ${IP_RECEIVER} -j MASQUERADE
# iptables -t nat -A POSTROUTING -s ${IP_RECEIVER} -d ${IP_SENDER} -j MASQUERADE

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

# Keep the container running
# `tail -f /dev/null` prevents the script from exiting, keeping the container alive
tail -f /dev/null
