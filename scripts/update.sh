#!/bin/bash
# HAZARUS Update Script
Updates HAZARUS dependencies and reinstalls the package.

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
    echo "Updating Python dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Reinstall HAZARUS package
    echo "Reinstalling HAZARUS package..."
    pip install -e .
    
    deactivate
else
    echo "Warning: Virtual environment not found at ./venv"
    echo "Please run the install script first: sudo ./install.sh"
fi

# Update system tools
echo "Updating system tools..."
apt update
apt install -y nmap anonsurf nikto

# Update external tools
echo "Updating external tools..."

# Update Nuclei if installed
if command -v nuclei &> /dev/null; then
    echo "Updating Nuclei..."
    nuclei -update &> /dev/null || true
fi

# Update Trivy if installed
if command -v trivy &> /dev/null; then
    echo "Updating Trivy..."
    trivy image --download-db-only &> /dev/null || true
fi

echo "========================================="
echo "Update complete!"
echo "========================================="
echo ""
echo "Note: To update the repository from GitHub, run:"
echo "  ./scripts/update_repo.sh"
echo ""
echo "Then run this script to update dependencies:"
echo "  sudo ./scripts/update.sh"
