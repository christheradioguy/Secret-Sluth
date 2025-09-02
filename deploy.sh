#!/bin/bash

# Secret Sluth Deployment Script
# This script installs Secret Sluth as a systemd service

set -e

# Configuration
SERVICE_NAME="secret-sluth"
INSTALL_DIR="/opt/secret-sluth"
SERVICE_USER="secret-sluth"
SERVICE_GROUP="secret-sluth"
SERVICE_FILE="/etc/systemd/system/secret-sluth.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting Secret Sluth deployment..."

# Create service user and group
print_status "Creating service user and group..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --shell /bin/false --home-dir "$INSTALL_DIR" "$SERVICE_USER"
    print_status "Created user: $SERVICE_USER"
else
    print_warning "User $SERVICE_USER already exists"
fi

if ! getent group "$SERVICE_GROUP" &>/dev/null; then
    groupadd --system "$SERVICE_GROUP"
    print_status "Created group: $SERVICE_GROUP"
else
    print_warning "Group $SERVICE_GROUP already exists"
fi

# Add user to group
usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER"

# Create installation directory
print_status "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# Create necessary directories
print_status "Creating log and cache directories..."
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/cache"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/logs"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/cache"
chmod 755 "$INSTALL_DIR/logs"
chmod 755 "$INSTALL_DIR/cache"

# Set up Python virtual environment
print_status "Setting up Python virtual environment..."
cd "$INSTALL_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Created virtual environment"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
print_status "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Copy systemd service file
print_status "Installing systemd service..."
cp secret-sluth.service "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

# Reload systemd and enable service
print_status "Enabling systemd service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# Set proper permissions
print_status "Setting final permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"

print_status "Deployment completed successfully!"
echo
print_status "Next steps:"
echo "1. Configure minimal environment variables in $INSTALL_DIR/.env"
echo "2. Start the service: systemctl start $SERVICE_NAME"
echo "3. Check status: systemctl status $SERVICE_NAME"
echo "4. View logs: journalctl -u $SERVICE_NAME -f"
echo "5. Access web UI and authenticate with your Vault server"
echo
print_status "Service management commands:"
echo "  Start:   systemctl start $SERVICE_NAME"
echo "  Stop:    systemctl stop $SERVICE_NAME"
echo "  Restart: systemctl restart $SERVICE_NAME"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo
print_warning "Vault credentials are provided by users via web UI - no persistent configuration needed!"
