#!/bin/bash
# HAZARUS Installation Script
# For Parrot Security OS and Debian-based Linux distributions

set -e

echo "========================================="
echo "HAZARUS Security Assessment Framework"
echo "Installation Script v2.0.0"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"

# Install system dependencies
echo "Installing system dependencies..."

if [ "$OS" = "parrot" ] || [ "$OS" = "debian" ] || [ "$OS" = "ubuntu" ]; then
    apt update
    apt install -y \
        python3 \
        python3-pip \
        python3-venv \
        git \
        nmap \
        anonsurf \
        nikto \
        curl \
        wget \
        dnsutils \
        whois \
        xmlstarlet \
        xsltproc
else
    echo "Unsupported OS. Please install dependencies manually."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install optional development dependencies
echo "Installing development dependencies..."
pip install pytest pytest-asyncio pytest-cov ruff mypy black isort

# Create HAZARUS directories
echo "Creating HAZARUS directories..."

mkdir -p ~/.hazarus/{state,audit_logs,authorization,reports,evidence,logs}

# Set up environment
echo "Setting up environment..."

# Create config directory
mkdir -p ~/.hazarus/config

# Copy scope template if not exists
if [ ! -f ~/.hazarus/config/scope.yaml ]; then
    cp config/scope.yaml ~/.hazarus/config/scope.yaml 2>/dev/null || true
fi

# Install HAZARUS as a package
echo "Installing HAZARUS package..."
pip install -e .

# Create systemd service for dashboard (optional)
read -p "Install HAZARUS dashboard as systemd service? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Creating systemd service..."

    cat > /etc/systemd/system/hazarus-dashboard.service <<EOF
[Unit]
Description=HAZARUS Security Assessment Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/hazarus dashboard --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hazarus-dashboard
    echo "Dashboard service installed. Start with: sudo systemctl start hazarus-dashboard"
fi

# Set permissions
echo "Setting permissions..."
chmod 755 ~/.hazarus
chmod 700 ~/.hazarus/{state,audit_logs,authorization}

echo "========================================="
echo "Installation complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Initialize a project: hazarus init"
echo "2. Configure scope: nano ~/.hazarus/config/scope.yaml"
echo "3. Validate scope: hazarus scope validate"
echo "4. Check privacy: hazarus privacy check"
echo ""
echo "For more information, see README.md"
