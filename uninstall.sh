#!/bin/bash
# HAZARUS Uninstallation Script

set -e

echo "========================================="
echo "HAZARUS Uninstallation Script"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

read -p "This will uninstall HAZARUS. Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Stop and disable systemd service
if systemctl is-active --quiet hazarus-dashboard; then
    echo "Stopping HAZARUS dashboard service..."
    systemctl stop hazarus-dashboard
    systemctl disable hazarus-dashboard
    rm /etc/systemd/system/hazarus-dashboard.service
    systemctl daemon-reload
fi

# Uninstall Python package
echo "Uninstalling HAZARUS package..."
pip uninstall -y hazarus 2>/dev/null || true

# Remove HAZARUS directories
read -p "Remove HAZARUS configuration and data directories? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing HAZARUS directories..."
    rm -rf ~/.hazarus
fi

echo "========================================="
echo "Uninstallation complete!"
echo "========================================="
