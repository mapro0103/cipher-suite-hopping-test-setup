#!/bin/bash

echo "Cleaning up sender_keys and monitor_pcap_data..."
rm -rf ./sender_keys/* ./monitor_pcap_data/*

echo "Ensuring folders still exist..."
mkdir -p ./sender_keys ./monitor_pcap_data

echo "Folders have been emptied!"
