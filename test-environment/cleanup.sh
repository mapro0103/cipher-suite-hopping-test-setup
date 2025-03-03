#!/bin/bash

echo "Cleaning up sender and monitor data..."
rm -rf ./sender_data/* ./monitor_data/*

echo "Ensuring folders still exist..."
mkdir -p ./sender_data ./monitor_data

echo "Folders have been emptied!"
