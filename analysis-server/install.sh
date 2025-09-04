#!/bin/bash

# Container Security Analysis Engine Installation Script

set -e

# Configuration
SERVICE_NAME="analysis-engine"
BINARY_NAME="analysis-engine"
INSTALL_DIR="/opt/analysis-engine"
CONFIG_DIR="/etc/analysis-engine"
LOG_DIR="/var/log/analysis-engine"
SYSTEMD_DIR="/etc/systemd/system"
USER="analysis"
GROUP="analysis"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Check dependencies
print_info "Checking dependencies..."
if ! command -v go &> /dev/null; then
    print_error "Go is not installed"
    exit 1
fi

# Create system user and group
print_info "Creating system user and group..."
if ! getent group "$GROUP" > /dev/null 2>&1; then
    groupadd --system "$GROUP"
    print_info "Created group: $GROUP"
fi

if ! getent passwd "$USER" > /dev/null 2>&1; then
    useradd --system --gid "$GROUP" --home-dir "$INSTALL_DIR" --shell /bin/false "$USER"
    print_info "Created user: $USER"
fi

# Create directories
print_info "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

chown -R "$USER:$GROUP" "$INSTALL_DIR"
chown -R "$USER:$GROUP" "$CONFIG_DIR"
chown -R "$USER:$GROUP" "$LOG_DIR"

# Install binary
print_info "Installing binary..."
if [[ ! -f "$BINARY_NAME" ]]; then
    print_error "Binary $BINARY_NAME not found. Run 'make build' first."
    exit 1
fi

cp "$BINARY_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
chown "$USER:$GROUP" "$INSTALL_DIR/$BINARY_NAME"

# Install configuration
print_info "Installing configuration..."
cp "configs/analysis.json" "$CONFIG_DIR/config.json"
chown "$USER:$GROUP" "$CONFIG_DIR/config.json"
chmod 644 "$CONFIG_DIR/config.json"

# Install systemd service
print_info "Installing systemd service..."
cp "systemd/analysis.service" "$SYSTEMD_DIR/$SERVICE_NAME.service"
chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME.service"

# Configure systemd
print_info "Configuring systemd..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

print_success "Installation completed successfully!"
echo ""
echo "Service management commands:"
echo "  Start:   systemctl start $SERVICE_NAME"
echo "  Stop:    systemctl stop $SERVICE_NAME"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo ""
echo "Configuration file: $CONFIG_DIR/config.json"
echo "Service files: $INSTALL_DIR" 