#!/bin/bash

# Container Security Analysis Services Installation Script
set -e

INSTALL_DIR_AE="/opt/analysis-engine"
INSTALL_DIR_DP="/opt/data-persistence"
CONFIG_DIR_AE="/etc/analysis-engine"
CONFIG_DIR_DP="/etc/data-persistence"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_AE="analysis-engine"
SERVICE_DP="data-persistence"
USER="analysis"
GROUP="analysis"

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
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        log_error "Go is required but not installed. Please install Go 1.19 or later"
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    if [ "$(printf '%s\n' "1.19" "$GO_VERSION" | sort -V | head -n1)" != "1.19" ]; then
        log_error "Go 1.19 or later is required. Current version: $GO_VERSION"
        exit 1
    fi
    
    # Check if PostgreSQL client libraries are available
    if ! ldconfig -p | grep -q libpq; then
        log_warn "PostgreSQL client libraries not found. Installing..."
        apt-get update
        apt-get install -y libpq-dev postgresql-client
    fi
    
    log_info "Dependencies check completed"
}

create_user() {
    log_info "Creating system user and group..."
    
    if ! getent group "$GROUP" >/dev/null; then
        groupadd --system "$GROUP"
        log_info "Created group: $GROUP"
    fi
    
    if ! getent passwd "$USER" >/dev/null; then
        useradd --system --gid "$GROUP" --home-dir /var/lib/analysis \
                --shell /usr/sbin/nologin --comment "Analysis Services User" "$USER"
        log_info "Created user: $USER"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    mkdir -p "$INSTALL_DIR_AE"
    mkdir -p "$INSTALL_DIR_DP"
    mkdir -p "$CONFIG_DIR_AE"
    mkdir -p "$CONFIG_DIR_DP"
    mkdir -p "/var/log/analysis-engine"
    mkdir -p "/var/log/data-persistence"
    mkdir -p "/var/lib/analysis"
    
    # Set ownership
    chown -R "$USER:$GROUP" "$INSTALL_DIR_AE" "$INSTALL_DIR_DP"
    chown -R "$USER:$GROUP" "$CONFIG_DIR_AE" "$CONFIG_DIR_DP"
    chown -R "$USER:$GROUP" "/var/log/analysis-engine" "/var/log/data-persistence"
    chown -R "$USER:$GROUP" "/var/lib/analysis"
    
    log_info "Directories created"
}

install_analysis_engine() {
    log_info "Installing Analysis Engine..."
    
    # Copy binary
    if [ ! -f "analysis-engine" ]; then
        log_error "Analysis Engine binary not found. Run 'make build-ae' first"
        exit 1
    fi
    
    cp analysis-engine "$INSTALL_DIR_AE/"
    chmod +x "$INSTALL_DIR_AE/analysis-engine"
    chown "$USER:$GROUP" "$INSTALL_DIR_AE/analysis-engine"
    
    # Copy configuration
    cp configs/analysis-engine.json "$CONFIG_DIR_AE/config.json"
    chmod 644 "$CONFIG_DIR_AE/config.json"
    chown "$USER:$GROUP" "$CONFIG_DIR_AE/config.json"
    
    # Copy systemd service file
    cp systemd/analysis-engine.service "$SYSTEMD_DIR/"
    chmod 644 "$SYSTEMD_DIR/analysis-engine.service"
    
    log_info "Analysis Engine installed successfully"
}

install_data_persistence() {
    log_info "Installing Data Persistence Service..."
    
    # Copy binary
    if [ ! -f "data-persistence" ]; then
        log_error "Data Persistence binary not found. Run 'make build-dp' first"
        exit 1
    fi
    
    cp data-persistence "$INSTALL_DIR_DP/"
    chmod +x "$INSTALL_DIR_DP/data-persistence"
    chown "$USER:$GROUP" "$INSTALL_DIR_DP/data-persistence"
    
    # Copy configuration
    cp configs/data-persistence.json "$CONFIG_DIR_DP/config.json"
    chmod 644 "$CONFIG_DIR_DP/config.json"
    chown "$USER:$GROUP" "$CONFIG_DIR_DP/config.json"
    
    # Copy systemd service file
    cp systemd/data-persistence.service "$SYSTEMD_DIR/"
    chmod 644 "$SYSTEMD_DIR/data-persistence.service"
    
    log_info "Data Persistence Service installed successfully"
}

configure_services() {
    log_info "Configuring services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable services
    systemctl enable "$SERVICE_AE"
    systemctl enable "$SERVICE_DP"
    
    log_info "Services configured and enabled"
}

show_status() {
    log_info "Installation completed successfully!"
    echo ""
    echo "Service management commands:"
    echo "  Start:   systemctl start $SERVICE_AE $SERVICE_DP"
    echo "  Stop:    systemctl stop $SERVICE_AE $SERVICE_DP"
    echo "  Status:  systemctl status $SERVICE_AE $SERVICE_DP"
    echo "  Logs:    journalctl -u $SERVICE_AE -u $SERVICE_DP -f"
    echo ""
    echo "Configuration files:"
    echo "  Analysis Engine: $CONFIG_DIR_AE/config.json"
    echo "  Data Persistence: $CONFIG_DIR_DP/config.json"
    echo ""
    echo "Service files:"
    echo "  Analysis Engine: $INSTALL_DIR_AE"
    echo "  Data Persistence: $INSTALL_DIR_DP"
    echo ""
    
    # Check dependencies
    if systemctl is-active --quiet rabbitmq-server; then
        log_info "RabbitMQ is running"
    else
        log_warn "RabbitMQ is not running. Please start it:"
        echo "  sudo systemctl start rabbitmq-server"
    fi
    
    if systemctl is-active --quiet postgresql; then
        log_info "PostgreSQL is running"
    else
        log_warn "PostgreSQL is not running. Please start it:"
        echo "  sudo systemctl start postgresql"
    fi
}

uninstall() {
    log_info "Uninstalling Container Security Analysis Services..."
    
    # Stop and disable services
    systemctl stop "$SERVICE_AE" 2>/dev/null || true
    systemctl stop "$SERVICE_DP" 2>/dev/null || true
    systemctl disable "$SERVICE_AE" 2>/dev/null || true
    systemctl disable "$SERVICE_DP" 2>/dev/null || true
    
    # Remove files
    rm -rf "$INSTALL_DIR_AE"
    rm -rf "$INSTALL_DIR_DP"
    rm -rf "$CONFIG_DIR_AE"
    rm -rf "$CONFIG_DIR_DP"
    rm -f "$SYSTEMD_DIR/analysis-engine.service"
    rm -f "$SYSTEMD_DIR/data-persistence.service"
    rm -rf "/var/log/analysis-engine"
    rm -rf "/var/log/data-persistence"
    
    # Remove user (optional, commented out to preserve user data)
    # userdel "$USER" 2>/dev/null || true
    # groupdel "$GROUP" 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    
    log_info "Uninstallation completed"
}

main() {
    case "${1:-install}" in
        "install")
            log_info "Installing Container Security Analysis Services..."
            check_root
            check_dependencies
            create_user
            create_directories
            install_analysis_engine
            install_data_persistence
            configure_services
            show_status
            ;;
        "install-ae")
            log_info "Installing Analysis Engine only..."
            check_root
            check_dependencies
            create_user
            create_directories
            install_analysis_engine
            systemctl daemon-reload
            systemctl enable "$SERVICE_AE"
            log_info "Analysis Engine installation completed"
            ;;
        "install-dp")
            log_info "Installing Data Persistence Service only..."
            check_root
            check_dependencies
            create_user
            create_directories
            install_data_persistence
            systemctl daemon-reload
            systemctl enable "$SERVICE_DP"
            log_info "Data Persistence Service installation completed"
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
            create_user
            create_directories
            install_analysis_engine
            install_data_persistence
            configure_services
            show_status
            ;;
        *)
            echo "Usage: $0 {install|install-ae|install-dp|uninstall|reinstall}"
            echo ""
            echo "Commands:"
            echo "  install     - Install both services"
            echo "  install-ae  - Install Analysis Engine only"
            echo "  install-dp  - Install Data Persistence Service only"
            echo "  uninstall   - Remove both services"
            echo "  reinstall   - Uninstall and then install both services"
            exit 1
            ;;
    esac
}

main "$@" 