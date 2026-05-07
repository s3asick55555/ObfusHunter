@echo off
REM Deobfuscator Web Interface - Startup Script (Windows)

color 0B
echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║  Deobfuscator - Web Interface Startup                ║
echo ║  Binary Obfuscation Detection System                 ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo [!] Virtual environment not found. Creating...
    python -m venv .venv
)

REM Activate virtual environment
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install/update dependencies
echo [*] Checking dependencies...
pip install -q -r requirements.txt 2>nul

REM Check Flask
python -c "import flask" 2>nul
if errorlevel 1 (
    echo [!] Installing Flask...
    pip install -q flask werkzeug
)

REM Create uploads directory
if not exist "uploads" (
    echo [*] Creating uploads directory...
    mkdir uploads
)

REM Show startup info
echo.
echo ✓ Setup complete!
echo.
echo Starting Flask server...
echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║  Web Interface will be available at:                   ║
echo ║  → http://localhost:5000                               ║
echo ║  → http://127.0.0.1:5000                               ║
echo ║                                                        ║
echo ║  Press Ctrl+C to stop the server                       ║
echo ╚════════════════════════════════════════════════════════╝
echo.

REM Run Flask app
python app.py
pause
