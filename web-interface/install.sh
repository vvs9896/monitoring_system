#!/bin/bash

set -e

echo "[INFO] Installing Container Security Monitoring Web Interface..."

# Check if running as root for some operations
if [[ $EUID -eq 0 ]] && [[ -z "$SUDO_USER" ]]; then
    echo "[ERROR] This script should not be run as root directly"
    echo "[INFO] Use: make install (which will use sudo when needed)"
    exit 1
fi

# Check dependencies
echo "[INFO] Checking dependencies..."
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "[INFO] Installing curl..."
    sudo apt update
    sudo apt install -y curl
fi

echo "[INFO] Dependencies check completed"

# Create system user and group
echo "[INFO] Creating system user and group..."
if ! id "web-interface" &>/dev/null; then
    sudo useradd -r -s /bin/false -d /opt/web-interface web-interface
    echo "[INFO] Created user: web-interface"
else
    echo "[INFO] User web-interface already exists"
fi

# Create directories
echo "[INFO] Creating directories..."
sudo mkdir -p /opt/web-interface
sudo mkdir -p /etc/web-interface
sudo mkdir -p /var/log/web-interface

echo "[INFO] Directories created"

# Install binary and static files
echo "[INFO] Installing web interface files..."
if [ ! -f "web-interface" ]; then
    echo "[ERROR] web-interface binary not found. Run 'make build' first."
    exit 1
fi

sudo cp web-interface /opt/web-interface/
sudo chmod +x /opt/web-interface/web-interface
sudo chown web-interface:web-interface /opt/web-interface/web-interface

# Copy static files and templates
sudo cp -r static /opt/web-interface/
sudo cp -r templates /opt/web-interface/
sudo chown -R web-interface:web-interface /opt/web-interface/

echo "[INFO] Files installed"

# Set permissions
echo "[INFO] Setting permissions..."
sudo chown -R web-interface:web-interface /opt/web-interface
sudo chown -R web-interface:web-interface /var/log/web-interface
sudo chmod 755 /opt/web-interface
sudo chmod 755 /var/log/web-interface

# Install systemd service
echo "[INFO] Installing systemd service..."
sudo cp web-interface.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable web-interface

echo "[INFO] Systemd service installed and enabled"

# Check database connection
echo "[INFO] Checking database connection..."
if ! sudo -u postgres psql -d monitoring -c "SELECT 1;" > /dev/null 2>&1; then
    echo "[WARNING] Cannot connect to monitoring database. Make sure PostgreSQL is running and the database exists."
else
    echo "[INFO] Database connection OK"
fi

# Open firewall port if ufw is active
if command -v ufw &> /dev/null && sudo ufw status | grep -q "Status: active"; then
    echo "[INFO] Opening firewall port 8080..."
    sudo ufw allow 8080/tcp
    echo "[INFO] Firewall rule added"
fi

echo "[INFO] Installation completed successfully!"
echo ""
echo "Service management commands:"
echo "  Start:   systemctl start web-interface"
echo "  Stop:    systemctl stop web-interface"
echo "  Status:  systemctl status web-interface"
echo "  Logs:    journalctl -u web-interface -f"
echo ""
echo "Web Interface will be available at:"
echo "  http://localhost:8080"
echo "  http://$(hostname):8080"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "To start the service now, run: systemctl start web-interface" 