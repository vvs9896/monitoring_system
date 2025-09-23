#!/bin/bash

set -e

echo "[INFO] Installing Container Security Response Module..."

# Check if running as root for some operations
if [[ $EUID -eq 0 ]] && [[ -z "$SUDO_USER" ]]; then
    echo "[ERROR] This script should not be run as root directly"
    echo "[INFO] Use: make install (which will use sudo when needed)"
    exit 1
fi

# Check dependencies
echo "[INFO] Checking dependencies..."
if ! command -v docker &> /dev/null; then
    echo "[INFO] Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io
    sudo systemctl enable docker
    sudo systemctl start docker
    # Add user to docker group
    sudo usermod -aG docker $USER
    echo "[INFO] Docker installed. You may need to log out and back in for group changes to take effect."
fi

if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

echo "[INFO] Dependencies check completed"

# Create system user and group
echo "[INFO] Creating system user and group..."
if ! id "response-module" &>/dev/null; then
    sudo useradd -r -s /bin/false -d /opt/response-module response-module
    echo "[INFO] Created user: response-module"
else
    echo "[INFO] User response-module already exists"
fi

# Create directories
echo "[INFO] Creating directories..."
sudo mkdir -p /opt/response-module
sudo mkdir -p /etc/response-module
sudo mkdir -p /var/log/response-module

echo "[INFO] Directories created"

# Install binary
echo "[INFO] Installing response module binary..."
if [ ! -f "response-module" ]; then
    echo "[ERROR] response-module binary not found. Run 'make build' first."
    exit 1
fi

sudo cp response-module /opt/response-module/
sudo chmod +x /opt/response-module/response-module
sudo chown response-module:response-module /opt/response-module/response-module

echo "[INFO] Binary installed"

# Install configuration
echo "[INFO] Installing configuration..."
sudo cp config.json /etc/response-module/
sudo chown response-module:response-module /etc/response-module/config.json
sudo chmod 600 /etc/response-module/config.json

echo "[INFO] Configuration installed"

# Set permissions
echo "[INFO] Setting permissions..."
sudo chown -R response-module:response-module /opt/response-module
sudo chown -R response-module:response-module /var/log/response-module
sudo chmod 755 /opt/response-module
sudo chmod 755 /var/log/response-module

# Install systemd service
echo "[INFO] Installing systemd service..."
sudo cp response-module.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable response-module

echo "[INFO] Systemd service installed and enabled"

# Check RabbitMQ
echo "[INFO] Checking RabbitMQ..."
if ! systemctl is-active --quiet rabbitmq-server; then
    echo "[WARNING] RabbitMQ is not running. Starting it..."
    sudo systemctl start rabbitmq-server || echo "[WARNING] Could not start RabbitMQ"
else
    echo "[INFO] RabbitMQ is running"
fi

echo "[INFO] Installation completed successfully!"
echo ""
echo "Service management commands:"
echo "  Start:   systemctl start response-module"
echo "  Stop:    systemctl stop response-module"
echo "  Status:  systemctl status response-module"
echo "  Logs:    journalctl -u response-module -f"
echo ""
echo "Configuration file: /etc/response-module/config.json"
echo "Service files: /opt/response-module"
echo ""
echo "IMPORTANT: Configure email settings in /etc/response-module/config.json before starting the service" 