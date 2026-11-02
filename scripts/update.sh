#!/bin/bash
# HAZARUS Update Script
Updates HAZARUS and its dependencies.

set -e

echo "========================================="
echo "HAZARUS Update Script"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Updating HAZARUS..."

# Update Python dependencies
if [ -d "venv" ]; then
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
fi

# Update system tools
apt update
apt install -y nmap anonsurf nikto

# Update external tools
echo "Updating external tools..."

# Update Nuclei if installed
if command -v nuclei &> /dev/null; then
    nuclei -update &> /dev/null || true
fi

# Update Trivy if installed
if command -v trivy &> /dev/null; then
    trivy image --download-db-only &> /dev/null || true
fi

echo "========================================="
echo "Update complete!"
echo "========================================="
