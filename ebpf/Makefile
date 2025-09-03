.PHONY: install uninstall start stop status logs clean test help

# Variables
SERVICE_NAME = ebpf-monitor
INSTALL_DIR = /opt/ebpf-monitor
CONFIG_DIR = /etc/ebpf-monitor
SYSTEMD_DIR = /etc/systemd/system

# Default target
help:
	@echo "eBPF Container Security Monitor"
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Install the service"
	@echo "  uninstall   - Uninstall the service"
	@echo "  reinstall   - Reinstall the service"
	@echo "  start       - Start the service"
	@echo "  stop        - Stop the service"
	@echo "  restart     - Restart the service"
	@echo "  status      - Show service status"
	@echo "  logs        - Show service logs"
	@echo "  test        - Test the installation"
	@echo "  clean       - Clean build artifacts"
	@echo ""

install:
	@echo "Installing eBPF Container Security Monitor..."
	@sudo ./install.sh install

uninstall:
	@echo "Uninstalling eBPF Container Security Monitor..."
	@sudo ./install.sh uninstall

reinstall:
	@echo "Reinstalling eBPF Container Security Monitor..."
	@sudo ./install.sh reinstall

start:
	@echo "Starting $(SERVICE_NAME) service..."
	@sudo systemctl start $(SERVICE_NAME)
	@sudo systemctl status $(SERVICE_NAME) --no-pager -l

stop:
	@echo "Stopping $(SERVICE_NAME) service..."
	@sudo systemctl stop $(SERVICE_NAME)

restart:
	@echo "Restarting $(SERVICE_NAME) service..."
	@sudo systemctl restart $(SERVICE_NAME)
	@sudo systemctl status $(SERVICE_NAME) --no-pager -l

status:
	@echo "Service status:"
	@sudo systemctl status $(SERVICE_NAME) --no-pager -l

logs:
	@echo "Service logs (press Ctrl+C to exit):"
	@sudo journalctl -u $(SERVICE_NAME) -f

logs-recent:
	@echo "Recent service logs:"
	@sudo journalctl -u $(SERVICE_NAME) --since "1 hour ago" --no-pager

test:
	@echo "Testing eBPF Container Security Monitor installation..."
	@echo "1. Checking if service is installed..."
	@if [ -f "$(SYSTEMD_DIR)/$(SERVICE_NAME).service" ]; then \
		echo "✓ Service file exists"; \
	else \
		echo "✗ Service file not found"; \
		exit 1; \
	fi
	@echo "2. Checking if files are installed..."
	@if [ -f "$(INSTALL_DIR)/ebpf_monitor.py" ]; then \
		echo "✓ Main program exists"; \
	else \
		echo "✗ Main program not found"; \
		exit 1; \
	fi
	@if [ -f "$(CONFIG_DIR)/config.json" ]; then \
		echo "✓ Configuration file exists"; \
	else \
		echo "✗ Configuration file not found"; \
		exit 1; \
	fi
	@echo "3. Checking service status..."
	@sudo systemctl is-enabled $(SERVICE_NAME) >/dev/null && echo "✓ Service is enabled" || echo "✗ Service is not enabled"
	@sudo systemctl is-active $(SERVICE_NAME) >/dev/null && echo "✓ Service is running" || echo "! Service is not running"
	@echo "4. Checking dependencies..."
	@python3 -c "import bcc; print('✓ BCC is available')" 2>/dev/null || echo "✗ BCC is not available"
	@python3 -c "import pika; print('✓ Pika is available')" 2>/dev/null || echo "✗ Pika is not available"
	@echo "5. Checking RabbitMQ..."
	@sudo systemctl is-active rabbitmq-server >/dev/null && echo "✓ RabbitMQ is running" || echo "! RabbitMQ is not running"
	@echo ""
	@echo "Test completed!"

clean:
	@echo "Cleaning build artifacts..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean completed!"

# Development targets
dev-install:
	@echo "Installing for development..."
	@sudo ./install.sh install
	@echo "Development installation completed!"

dev-test:
	@echo "Running development tests..."
	@python3 -m py_compile ebpf_monitor.py
	@python3 -m py_compile util.py
	@echo "✓ Python syntax check passed"
	@echo "Development tests completed!"

# Service management shortcuts
enable:
	@sudo systemctl enable $(SERVICE_NAME)
	@echo "Service enabled"

disable:
	@sudo systemctl disable $(SERVICE_NAME)
	@echo "Service disabled"

reload:
	@sudo systemctl daemon-reload
	@echo "Systemd configuration reloaded" 