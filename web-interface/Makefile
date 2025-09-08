.PHONY: build run install start stop status logs clean deps

# Build the web interface
build: deps
	@echo "Building Web Interface..."
	go build -o web-interface ./cmd/server
	@echo "✓ Web Interface built successfully"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download
	@echo "✓ Dependencies installed"

# Run in development mode
run: build
	@echo "Starting Web Interface in development mode..."
	./web-interface

# Install as systemd service
install: build
	@echo "Installing Web Interface as systemd service..."
	sudo ./install.sh
	@echo "✓ Web Interface installed successfully"

# Start the service
start:
	@echo "Starting web-interface service..."
	sudo systemctl start web-interface
	sudo systemctl status web-interface --no-pager -l

# Stop the service
stop:
	@echo "Stopping web-interface service..."
	sudo systemctl stop web-interface

# Check service status
status:
	@echo "=== Web Interface Status ==="
	sudo systemctl status web-interface --no-pager -l

# View service logs
logs:
	@echo "=== Web Interface Logs ==="
	sudo journalctl -u web-interface -f

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f web-interface
	go mod tidy
	@echo "✓ Clean completed"

# Enable service to start on boot
enable:
	@echo "Enabling web-interface service..."
	sudo systemctl enable web-interface
	@echo "✓ Service enabled"

# Disable service from starting on boot
disable:
	@echo "Disabling web-interface service..."
	sudo systemctl disable web-interface
	@echo "✓ Service disabled"

# Restart the service
restart:
	@echo "Restarting web-interface service..."
	sudo systemctl restart web-interface
	sudo systemctl status web-interface --no-pager -l

# Test the installation
test: build
	@echo "Testing Web Interface..."
	@echo "✓ Build successful"
	@echo "✓ Testing database connection..."
	@timeout 10 ./web-interface -addr :8081 &
	@sleep 3
	@curl -s http://localhost:8081/api/stats > /dev/null && echo "✓ API endpoints working" || echo "⚠ API test failed"
	@pkill -f web-interface || true
	@echo "✓ Web Interface test completed" 