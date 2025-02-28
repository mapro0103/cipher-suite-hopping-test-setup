#!/bin/bash

ip route add ${IP_SENDER} via ${IP_INTERMEDIATE}

python3 receiver-wolfssl.py
tail -f /dev/null