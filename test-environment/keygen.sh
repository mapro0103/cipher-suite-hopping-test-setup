#!/bin/bash

CERT_NAME="cert.pem"
KEY_NAME="key.pem"
DAYS_VALID=1000

openssl req -x509 -newkey rsa:4096 -keyout "$KEY_NAME" -out "$CERT_NAME" -days "$DAYS_VALID" -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"

echo "TLS Certificate and Key successfully generated:"
echo "- Certificate: $CERT_NAME"
echo "- Key: $KEY_NAME"
