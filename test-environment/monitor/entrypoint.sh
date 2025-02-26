#!/bin/bash

echo "Sender IP: ${IP_SENDER}"
echo "Receiver IP: ${IP_RECEIVER}"
echo "Intermediate IP: ${IP_INTERMEDIATE}"
echo "Monitor IP: ${IP_MONITOR}"

python3 monitor.py
