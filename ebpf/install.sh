#!/bin/bash

# eBPF Container Security Monitor Installation Script
set -e

INSTALL_DIR="/opt/ebpf-monitor"
CONFIG_DIR="/etc/ebpf-monitor"
SERVICE_NAME="ebpf-monitor"
SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check if pip3 is installed
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
        exit 1
    fi
    
    # Check BCC installation
    if ! python3 -c "import bcc" 2>/dev/null; then
        log_warn "BCC (Berkeley Packet Filter Compiler Collection) not found"
        log_info "Installing BCC..."
        apt-get update
        apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
    fi
    
    # Check pika (RabbitMQ client)
    if ! python3 -c "import pika" 2>/dev/null; then
        log_info "Installing pika (RabbitMQ client)..."
        pip3 install pika
    fi
    
    log_info "Dependencies check completed"
}

create_directories() {
    log_info "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/var/log/ebpf-monitor"
    mkdir -p "/var/cache/bcc"
    
    log_info "Directories created"
}

install_files() {
    log_info "Installing eBPF monitor files..."
    
    # Copy main files
    cp ebpf_monitor.py "$INSTALL_DIR/"
    cp ebpf_agent.c "$INSTALL_DIR/"
    cp util.py "$INSTALL_DIR/"
    
    # Copy configuration
    cp config.json "$CONFIG_DIR/"
    
    # Set permissions
    chmod +x "$INSTALL_DIR/ebpf_monitor.py"
    chown -R root:root "$INSTALL_DIR"
    chown -R root:root "$CONFIG_DIR"
    chmod 644 "$CONFIG_DIR/config.json"
    
    log_info "Files installed successfully"
}

install_systemd_service() {
    log_info "Installing systemd service..."
    
    # Copy service file
    cp ebpf-monitor.service "$SYSTEMD_DIR/"
    chmod 644 "$SYSTEMD_DIR/ebpf-monitor.service"
    
    # Reload systemd
    systemctl daemon-reload
    
    log_info "Systemd service installed"
}

configure_service() {
    log_info "Configuring service..."
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log_info "Service configured and enabled"
}

show_status() {
    log_info "Installation completed successfully!"
    echo ""
    echo "Service management commands:"
    echo "  Start:   systemctl start $SERVICE_NAME"
    echo "  Stop:    systemctl stop $SERVICE_NAME"
    echo "  Status:  systemctl status $SERVICE_NAME"
    echo "  Logs:    journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "Configuration file: $CONFIG_DIR/config.json"
    echo "Service files: $INSTALL_DIR"
    echo ""
    
    # Check if RabbitMQ is running
    if systemctl is-active --quiet rabbitmq-server; then
        log_info "RabbitMQ is running"
    else
        log_warn "RabbitMQ is not running. Please start it before starting the monitor:"
        echo "  sudo systemctl start rabbitmq-server"
    fi
}

uninstall() {
    log_info "Uninstalling eBPF Container Security Monitor..."
    
    # Stop and disable service
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Remove files
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -f "$SYSTEMD_DIR/ebpf-monitor.service"
    rm -rf "/var/log/ebpf-monitor"
    
    # Reload systemd
    systemctl daemon-reload
    
    log_info "Uninstallation completed"
}

main() {
    case "${1:-install}" in
        "install")
            log_info "Installing eBPF Container Security Monitor..."
            check_root
            check_dependencies
            create_directories
            install_files
            install_systemd_service
            configure_service
            show_status
            ;;
        "uninstall")
            check_root
            uninstall
            ;;
        "reinstall")
            check_root
            uninstall
            sleep 2
            check_dependencies
            create_directories
            install_files
            install_systemd_service
            configure_service
            show_status
            ;;
        *)
            echo "Usage: $0 {install|uninstall|reinstall}"
            echo ""
            echo "Commands:"
            echo "  install    - Install the eBPF monitor service"
            echo "  uninstall  - Remove the eBPF monitor service"
            echo "  reinstall  - Uninstall and then install the service"
            exit 1
            ;;
    esac
}

main "$@" 