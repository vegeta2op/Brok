.PHONY: install setup run-api run-dashboard run-tui test clean help

help:
	@echo "JimCrow - Autonomous Pentesting Agent"
	@echo ""
	@echo "Available commands:"
	@echo "  make install        - Install all dependencies"
	@echo "  make setup          - Setup environment and initialize database"
	@echo "  make run-api        - Start FastAPI backend"
	@echo "  make run-dashboard  - Start React dashboard"
	@echo "  make run-tui        - Launch interactive TUI"
	@echo "  make test          - Run tests"
	@echo "  make clean         - Clean generated files"
	@echo ""

install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Installing Playwright browsers..."
	playwright install
	@echo "Installing dashboard dependencies..."
	cd dashboard && npm install
	@echo "✓ Installation complete"

setup:
	@echo "Setting up JimCrow..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "⚠️  Created .env file. Please edit it with your API keys."; \
	fi
	@mkdir -p config
	@if [ ! -f config/authorized_targets.yaml ]; then \
		cp config/authorized_targets.yaml.example config/authorized_targets.yaml; \
		echo "✓ Created authorized targets config"; \
	fi
	@echo "Initializing database..."
	python -m backend.scripts.init_db
	@echo "✓ Setup complete"

run-api:
	@echo "Starting FastAPI backend..."
	python -m backend.api.main

run-dashboard:
	@echo "Starting React dashboard..."
	cd dashboard && npm run dev

run-tui:
	@echo "Launching interactive TUI..."
	python -m cli.main tui

test:
	@echo "Running tests..."
	pytest

clean:
	@echo "Cleaning generated files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/
	cd dashboard && rm -rf dist/ build/ node_modules/.cache/
	@echo "✓ Cleanup complete"

dev:
	@echo "Starting development environment..."
	@make -j 2 run-api run-dashboard

.DEFAULT_GOAL := help

