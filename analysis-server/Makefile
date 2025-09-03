.PHONY: build install uninstall start stop status logs clean test help

# Variables
ANALYSIS_ENGINE_SERVICE = analysis-engine
DATA_PERSISTENCE_SERVICE = data-persistence
INSTALL_DIR_AE = /opt/analysis-engine
INSTALL_DIR_DP = /opt/data-persistence
CONFIG_DIR_AE = /etc/analysis-engine
CONFIG_DIR_DP = /etc/data-persistence
SYSTEMD_DIR = /etc/systemd/system

# Go build settings
GOOS = linux
GOARCH = amd64
CGO_ENABLED = 0

# Default target
help:
	@echo "Container Security Analysis Services"
	@echo ""
	@echo "Available targets:"
	@echo "  build       - Build both services"
	@echo "  install     - Install both services"
	@echo "  uninstall   - Uninstall both services"
	@echo "  start       - Start both services"
	@echo "  stop        - Stop both services"
	@echo "  restart     - Restart both services"
	@echo "  status      - Show services status"
	@echo "  logs        - Show services logs"
	@echo "  test        - Test the installation"
	@echo "  clean       - Clean build artifacts"
	@echo ""
	@echo "Individual service targets:"
	@echo "  build-ae    - Build analysis engine only"
	@echo "  build-dp    - Build data persistence only"
	@echo "  start-ae    - Start analysis engine only"
	@echo "  start-dp    - Start data persistence only"

# Build targets
build: build-ae build-dp

build-ae:
	@echo "Building Analysis Engine..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -o analysis-engine analysis-engine.go
	@echo "✓ Analysis Engine built successfully"

build-dp:
	@echo "Building Data Persistence Service..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -o data-persistence data-persistence.go
	@echo "✓ Data Persistence Service built successfully"

# Installation targets
install: build
	@echo "Installing Container Security Analysis Services..."
	@sudo ./install.sh install

install-ae: build-ae
	@echo "Installing Analysis Engine..."
	@sudo ./install.sh install-ae

install-dp: build-dp
	@echo "Installing Data Persistence Service..."
	@sudo ./install.sh install-dp

uninstall:
	@echo "Uninstalling Container Security Analysis Services..."
	@sudo ./install.sh uninstall

# Service management
start:
	@echo "Starting analysis services..."
	@sudo systemctl start $(ANALYSIS_ENGINE_SERVICE)
	@sudo systemctl start $(DATA_PERSISTENCE_SERVICE)
	@make status

start-ae:
	@echo "Starting Analysis Engine..."
	@sudo systemctl start $(ANALYSIS_ENGINE_SERVICE)
	@sudo systemctl status $(ANALYSIS_ENGINE_SERVICE) --no-pager -l

start-dp:
	@echo "Starting Data Persistence Service..."
	@sudo systemctl start $(DATA_PERSISTENCE_SERVICE)
	@sudo systemctl status $(DATA_PERSISTENCE_SERVICE) --no-pager -l

stop:
	@echo "Stopping analysis services..."
	@sudo systemctl stop $(DATA_PERSISTENCE_SERVICE)
	@sudo systemctl stop $(ANALYSIS_ENGINE_SERVICE)

stop-ae:
	@sudo systemctl stop $(ANALYSIS_ENGINE_SERVICE)

stop-dp:
	@sudo systemctl stop $(DATA_PERSISTENCE_SERVICE)

restart: stop start

restart-ae:
	@sudo systemctl restart $(ANALYSIS_ENGINE_SERVICE)
	@sudo systemctl status $(ANALYSIS_ENGINE_SERVICE) --no-pager -l

restart-dp:
	@sudo systemctl restart $(DATA_PERSISTENCE_SERVICE)
	@sudo systemctl status $(DATA_PERSISTENCE_SERVICE) --no-pager -l

status:
	@echo "=== Analysis Engine Status ==="
	@sudo systemctl status $(ANALYSIS_ENGINE_SERVICE) --no-pager -l
	@echo ""
	@echo "=== Data Persistence Status ==="
	@sudo systemctl status $(DATA_PERSISTENCE_SERVICE) --no-pager -l

logs:
	@echo "Analysis services logs (press Ctrl+C to exit):"
	@sudo journalctl -u $(ANALYSIS_ENGINE_SERVICE) -u $(DATA_PERSISTENCE_SERVICE) -f

logs-ae:
	@echo "Analysis Engine logs (press Ctrl+C to exit):"
	@sudo journalctl -u $(ANALYSIS_ENGINE_SERVICE) -f

logs-dp:
	@echo "Data Persistence logs (press Ctrl+C to exit):"
	@sudo journalctl -u $(DATA_PERSISTENCE_SERVICE) -f

logs-recent:
	@echo "Recent analysis services logs:"
	@sudo journalctl -u $(ANALYSIS_ENGINE_SERVICE) -u $(DATA_PERSISTENCE_SERVICE) --since "1 hour ago" --no-pager

# Testing
test:
	@echo "Testing Analysis Services installation..."
	@echo "1. Checking if services are installed..."
	@if [ -f "$(SYSTEMD_DIR)/$(ANALYSIS_ENGINE_SERVICE).service" ]; then \
		echo "✓ Analysis Engine service file exists"; \
	else \
		echo "✗ Analysis Engine service file not found"; \
		exit 1; \
	fi
	@if [ -f "$(SYSTEMD_DIR)/$(DATA_PERSISTENCE_SERVICE).service" ]; then \
		echo "✓ Data Persistence service file exists"; \
	else \
		echo "✗ Data Persistence service file not found"; \
		exit 1; \
	fi
	@echo "2. Checking if binaries are installed..."
	@if [ -f "$(INSTALL_DIR_AE)/analysis-engine" ]; then \
		echo "✓ Analysis Engine binary exists"; \
	else \
		echo "✗ Analysis Engine binary not found"; \
		exit 1; \
	fi
	@if [ -f "$(INSTALL_DIR_DP)/data-persistence" ]; then \
		echo "✓ Data Persistence binary exists"; \
	else \
		echo "✗ Data Persistence binary not found"; \
		exit 1; \
	fi
	@echo "3. Checking configuration files..."
	@if [ -f "$(CONFIG_DIR_AE)/config.json" ]; then \
		echo "✓ Analysis Engine config exists"; \
	else \
		echo "✗ Analysis Engine config not found"; \
		exit 1; \
	fi
	@if [ -f "$(CONFIG_DIR_DP)/config.json" ]; then \
		echo "✓ Data Persistence config exists"; \
	else \
		echo "✗ Data Persistence config not found"; \
		exit 1; \
	fi
	@echo "4. Checking service status..."
	@sudo systemctl is-enabled $(ANALYSIS_ENGINE_SERVICE) >/dev/null && echo "✓ Analysis Engine is enabled" || echo "✗ Analysis Engine is not enabled"
	@sudo systemctl is-active $(ANALYSIS_ENGINE_SERVICE) >/dev/null && echo "✓ Analysis Engine is running" || echo "! Analysis Engine is not running"
	@sudo systemctl is-enabled $(DATA_PERSISTENCE_SERVICE) >/dev/null && echo "✓ Data Persistence is enabled" || echo "✗ Data Persistence is not enabled"
	@sudo systemctl is-active $(DATA_PERSISTENCE_SERVICE) >/dev/null && echo "✓ Data Persistence is running" || echo "! Data Persistence is not running"
	@echo "5. Checking dependencies..."
	@sudo systemctl is-active rabbitmq-server >/dev/null && echo "✓ RabbitMQ is running" || echo "! RabbitMQ is not running"
	@sudo systemctl is-active postgresql >/dev/null && echo "✓ PostgreSQL is running" || echo "! PostgreSQL is not running"
	@echo ""
	@echo "Test completed!"

# Development targets
dev-build: build

dev-test:
	@echo "Running development tests..."
	@go fmt ./...
	@go vet ./...
	@echo "✓ Code formatting and linting passed"

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	@rm -f analysis-engine data-persistence
	@echo "Clean completed!"

# Service management shortcuts
enable:
	@sudo systemctl enable $(ANALYSIS_ENGINE_SERVICE)
	@sudo systemctl enable $(DATA_PERSISTENCE_SERVICE)
	@echo "Services enabled"

disable:
	@sudo systemctl disable $(ANALYSIS_ENGINE_SERVICE)
	@sudo systemctl disable $(DATA_PERSISTENCE_SERVICE)
	@echo "Services disabled"

reload:
	@sudo systemctl daemon-reload
	@echo "Systemd configuration reloaded" 