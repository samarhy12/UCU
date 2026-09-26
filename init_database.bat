@echo off
REM Database Initialization Script for Production (Windows)
REM This script initializes Flask-Migrate and creates the initial database schema

echo Initializing database migrations...

REM Check if .env file exists
if not exist .env (
    echo Error: .env file not found. Please copy .env.example to .env and configure it.
    exit /b 1
)

REM Activate virtual environment
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
) else (
    echo Error: Virtual environment not found. Please create one first.
    exit /b 1
)

REM Initialize Flask-Migrate if migrations directory doesn't exist
if not exist migrations (
    echo Running: flask db init
    flask db init
) else (
    echo Migrations directory already exists, skipping init...
)

REM Create initial migration
echo Running: flask db migrate -m "Initial database schema"
flask db migrate -m "Initial database schema"

REM Apply migrations
echo Running: flask db upgrade
flask db upgrade

echo Database initialization complete!
echo You can now start the application with: flask run
