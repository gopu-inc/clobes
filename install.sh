#!/bin/bash
echo "Installing CLOBES PRO v4.0.0..."

# Compile
make clean
make

# Install to /usr/local/bin
sudo cp clobes /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/clobes/

echo "Installation complete!"
echo "Usage: clobes [command]"
