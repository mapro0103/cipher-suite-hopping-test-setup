#!/bin/bash

echo "Cleaning up sender and monitor data..."
rm -f ./bandwidth* ./transmission* ./metrics_rsa* ./metrics_ecc* ./metrics_password* ./password_* ./rsa_* ./ecc_*

echo "Folders have been emptied!"
