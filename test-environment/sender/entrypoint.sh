#!/bin/bash

ip route add ${IP_RECEIVER} via ${IP_INTERMEDIATE}

tail -f /dev/null