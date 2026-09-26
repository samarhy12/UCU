#!/bin/bash
# Database Initialization Script for Production
# This script initializes Flask-Migrate and creates the initial database schema

echo "Initializing database migrations..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please copy .env.example to .env and configure it."
    exit 1
fi

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "Error: Virtual environment not found. Please create one first."
    exit 1
fi

# Initialize Flask-Migrate if migrations directory doesn't exist
if [ ! -d "migrations" ]; then
    echo "Running: flask db init"
    flask db init
else
    echo "Migrations directory already exists, skipping init..."
fi

# Create initial migration
echo "Running: flask db migrate -m 'Initial database schema'"
flask db migrate -m "Initial database schema"

# Apply migrations
echo "Running: flask db upgrade"
flask db upgrade

echo "Database initialization complete!"
echo "You can now start the application with: flask run"
