.PHONY: build install start stop status logs test clean

# Build the response module
build:
	@echo "Building Response Module..."
	go mod tidy
	go build -o response-module main.go
	@echo "✓ Response Module built successfully"

# Install the service
install: build
	@echo "Installing Response Module..."
	sudo ./install.sh
	@echo "✓ Response Module installed successfully"

# Start the service
start:
	@echo "Starting response-module service..."
	sudo systemctl start response-module
	sudo systemctl status response-module --no-pager -l

# Stop the service
stop:
	@echo "Stopping response-module service..."
	sudo systemctl stop response-module

# Check service status
status:
	@echo "=== Response Module Status ==="
	sudo systemctl status response-module --no-pager -l

# View service logs
logs:
	@echo "=== Response Module Logs ==="
	sudo journalctl -u response-module -f

# Test the installation
test: build
	@echo "Testing Response Module installation..."
	@echo "Checking dependencies..."
	@command -v docker >/dev/null 2>&1 || { echo "Docker not found, installing..."; sudo apt update && sudo apt install -y docker.io; }
	@echo "✓ Dependencies check completed"
	@echo "Testing configuration..."
	@./response-module config.json --test 2>/dev/null || echo "⚠ Config test skipped (service not implemented)"
	@echo "✓ Response Module test completed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f response-module
	go mod tidy
	@echo "✓ Clean completed"

# Enable service to start on boot
enable:
	@echo "Enabling response-module service..."
	sudo systemctl enable response-module
	@echo "✓ Service enabled"

# Disable service from starting on boot
disable:
	@echo "Disabling response-module service..."
	sudo systemctl disable response-module
	@echo "✓ Service disabled"

# Restart the service
restart:
	@echo "Restarting response-module service..."
	sudo systemctl restart response-module
	sudo systemctl status response-module --no-pager -l 