#!/bin/bash

green='\033[0;32m'
nc='\033[0m'

messages=(
  "==============================================="
  "  WARNING: This tool is for authorized use only!"
  "  Any misuse is your full responsibility."
  "==============================================="
  "Starting mhker tool..."
)

for msg in "${messages[@]}"; do
  echo -e "${green}$msg${nc}"
  sleep 1
done

ALLOW_RUN=true python mhker_protected.py
