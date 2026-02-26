#!/bin/bash

# This script runs on the host machine BEFORE the container is created.
# It ensures the Intel LMS service is running.

echo "Checking LMS service status..."

# Skip LMS checks on non-Linux hosts.
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Non-Linux host detected; skipping LMS service check."
    exit 0
fi

check_lms_active() {
    if sudo systemctl is-active --quiet lms; then
        echo "LMS service is active."
        return 0
    else
        return 1
    fi
}

prompt_timeout() {
    local msg="$1"
    local sec=10
    USER_INPUT=""
    while [ $sec -gt 0 ]; do
        echo -ne "\r$msg (timeout: ${sec}s) "
        if read -t 1 USER_INPUT; then
            echo ""
            return 0
        fi
        ((sec--))
    done
    echo ""
    USER_INPUT="n"
}

if check_lms_active; then
    exit 0
fi

echo "LMS service is not active."

# Check if the service unit exists
if sudo systemctl list-unit-files | grep -q "^lms.service"; then
    echo "LMS service exists but is inactive."

    prompt_timeout "Do you want to start it? (y/n) [n]"
    answer="$USER_INPUT"

    if [[ "$answer" =~ ^[Yy]$ ]]; then
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
    else
        echo "Skipping LMS start. Proceeding with devcontainer creation..."
        exit 0
    fi
fi

echo "LMS service not found."

prompt_timeout "Do you want to install and start it? (y/n) [n]"
answer="$USER_INPUT"

if [[ "$answer" =~ ^[Yy]$ ]]; then
    # Proceed with installation
    echo "Proceeding with installation..."
else
    echo "Skipping LMS installation. Proceeding with devcontainer creation..."
    exit 0
fi

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
