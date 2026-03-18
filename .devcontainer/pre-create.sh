#!/bin/bash

# This script runs on the host machine BEFORE the container is created.
# It ensures the Intel LMS service is running.

# Opt-in gate for host-side privileged LMS setup.
# Values:
#   off     (default): skip host LMS checks/changes
#   start            : start LMS if already installed; never install
#   install          : install LMS if missing, then start
#   on               : backward-compatible alias for "install"
LMS_SETUP_MODE="${DEVCONTAINER_LMS_SETUP:-off}"

# Keep compatibility with previous docs.
if [ "$LMS_SETUP_MODE" = "on" ]; then
    LMS_SETUP_MODE="install"
fi

if [ "$LMS_SETUP_MODE" = "off" ]; then
    echo "Skipping LMS host setup (DEVCONTAINER_LMS_SETUP=$LMS_SETUP_MODE)."
    exit 0
fi

if [ "$LMS_SETUP_MODE" != "start" ] && [ "$LMS_SETUP_MODE" != "install" ]; then
    echo "Invalid DEVCONTAINER_LMS_SETUP value: $LMS_SETUP_MODE"
    echo "Supported values: off, start, install"
    exit 0
fi

echo "Checking LMS service status..."

check_lms_active() {
    if sudo systemctl is-active --quiet lms; then
        echo "LMS service is active."
        return 0
    else
        return 1
    fi
}

if check_lms_active; then
    exit 0
fi

echo "LMS service is not active."

# Check if the service unit exists
if sudo systemctl list-unit-files | grep -q "^lms.service"; then
    echo "LMS service exists but is inactive."

    echo "Attempting to start LMS..."
    sudo systemctl start lms

    # Wait for up to 10 seconds for service to start
    for i in {1..10}; do
        sleep 1
        if check_lms_active; then
            echo "LMS started successfully."
            exit 0
        fi
    done

    echo "ERROR: Failed to start LMS service."
    sudo systemctl status lms
    exit 1
fi

echo "LMS service not found."

if [ "$LMS_SETUP_MODE" = "start" ]; then
    echo "LMS is missing and DEVCONTAINER_LMS_SETUP=start. Skipping install."
    exit 0
fi

echo "Proceeding with LMS install because DEVCONTAINER_LMS_SETUP=install..."

# Install dependencies
echo "Installing dependencies..."
# Update apt cache first (optional but recommended before installing)
# sudo apt-get update 
sudo apt-get install -y cmake libglib2.0-dev libcurl4-openssl-dev libxerces-c-dev \
    libnl-3-dev libnl-route-3-dev libxml2-dev libidn2-0-dev libace-dev build-essential git

# Prepare working directory
WORK_DIR="$HOME/lms_setup"
mkdir -p "$WORK_DIR"
echo "Working directory: $WORK_DIR"

if [ -d "$WORK_DIR/lms" ]; then
    echo "Cleaning up previous LMS source..."
    sudo rm -rf "$WORK_DIR/lms"
fi

# Clone LMS
echo "Cloning LMS repository..."
git clone https://github.com/intel/lms.git "$WORK_DIR/lms"

# Build LMS
echo "Building LMS..."
cd "$WORK_DIR/lms"
mkdir -p build
cd build

# Using dynamic paths based on where we verified the clone
sudo cmake -S .. -B .
sudo cmake --build .

echo "Installing LMS..."
sudo make install

echo "Starting LMS service..."
sudo systemctl daemon-reload
sudo systemctl enable lms
sudo systemctl start lms

# Verify installation
for i in {1..10}; do
    sleep 1
    if check_lms_active; then
        echo "LMS installed and started successfully."
        exit 0
    fi
done

echo "ERROR: Failed to start LMS after installation."
sudo systemctl status lms
exit 1
