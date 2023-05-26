#!/bin/bash

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "pip is not installed. Please install pip before running this script."
    exit 1
fi

# Check if the requirements.txt file exists
if [ ! -f requirements.txt ]; then
    echo "requirements.txt file not found."
    exit 1
fi

# Install modules using pip
echo "Installing Python modules from requirements.txt..."
pip install -r requirements.txt

echo "All Python modules have been installed successfully."
