#!/bin/bash

ip route add ${IP_RECEIVER} via ${IP_INTERMEDIATE}

python3 sender-wolfssl.py
tail -f /dev/null