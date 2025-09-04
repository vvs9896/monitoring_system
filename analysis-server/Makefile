.PHONY: build install uninstall start stop status logs clean test

# Variables
SERVICE_NAME = analysis-engine
BINARY_NAME = analysis-engine
INSTALL_DIR = /opt/analysis-engine
CONFIG_DIR = /etc/analysis-engine
SYSTEMD_DIR = /etc/systemd/system

build:
	@echo "Building Analysis Engine..."
	@CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o $(BINARY_NAME) main.go
	@echo "✓ Analysis Engine built successfully"

install: build
	@echo "Installing Analysis Engine..."
	@sudo ./install.sh
	@echo "✓ Installation completed successfully"

uninstall:
	@echo "Uninstalling Analysis Engine..."
	@sudo systemctl stop $(SERVICE_NAME) || true
	@sudo systemctl disable $(SERVICE_NAME) || true
	@sudo rm -f $(SYSTEMD_DIR)/$(SERVICE_NAME).service
	@sudo rm -rf $(INSTALL_DIR)
	@sudo rm -rf $(CONFIG_DIR)
	@sudo systemctl daemon-reload
	@echo "✓ Uninstallation completed"

start:
	@echo "Starting Analysis Engine..."
	@sudo systemctl start $(SERVICE_NAME)
	@make status

stop:
	@echo "Stopping Analysis Engine..."
	@sudo systemctl stop $(SERVICE_NAME)

status:
	@echo "=== Analysis Engine Status ==="
	@sudo systemctl status $(SERVICE_NAME) --no-pager || true

logs:
	@echo "=== Analysis Engine Logs ==="
	@sudo journalctl -u $(SERVICE_NAME) --no-pager -n 50

logs-follow:
	@sudo journalctl -u $(SERVICE_NAME) -f

test:
	@echo "Testing Analysis Engine installation..."
	@echo "1. Checking if service is installed..."
	@if [ -f $(SYSTEMD_DIR)/$(SERVICE_NAME).service ]; then \
		echo "✓ Service file exists"; \
	else \
		echo "✗ Service file missing"; \
	fi
	@echo "2. Checking if binary is installed..."
	@if [ -f $(INSTALL_DIR)/$(BINARY_NAME) ]; then \
		echo "✓ Binary exists"; \
	else \
		echo "✗ Binary missing"; \
	fi
	@echo "3. Checking configuration..."
	@if [ -f $(CONFIG_DIR)/config.json ]; then \
		echo "✓ Config exists"; \
	else \
		echo "✗ Config missing"; \
	fi
	@echo "4. Checking service status..."
	@if sudo systemctl is-enabled $(SERVICE_NAME) >/dev/null 2>&1; then \
		echo "✓ Service is enabled"; \
	else \
		echo "! Service is not enabled"; \
	fi
	@if sudo systemctl is-active $(SERVICE_NAME) >/dev/null 2>&1; then \
		echo "✓ Service is running"; \
	else \
		echo "! Service is not running"; \
	fi
	@echo "5. Checking dependencies..."
	@if sudo systemctl is-active rabbitmq-server >/dev/null 2>&1; then \
		echo "✓ RabbitMQ is running"; \
	else \
		echo "✗ RabbitMQ is not running"; \
	fi
	@if sudo systemctl is-active postgresql >/dev/null 2>&1; then \
		echo "✓ PostgreSQL is running"; \
	else \
		echo "✗ PostgreSQL is not running"; \
	fi

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@echo "✓ Cleaned" 