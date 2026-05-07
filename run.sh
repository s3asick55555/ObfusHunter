#!/bin/bash
# Deobfuscator Web Interface - Startup Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Deobfuscator - Web Interface Startup                ║"
echo "║  Binary Obfuscation Detection System                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[!] Virtual environment not found. Creating...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${BLUE}[*] Activating virtual environment...${NC}"
source .venv/bin/activate

# Install/update dependencies
echo -e "${BLUE}[*] Checking dependencies...${NC}"
pip install -q -r requirements.txt 2>/dev/null

# Check Flask
if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}[!] Installing Flask...${NC}"
    pip install -q flask werkzeug
fi

# Create uploads directory
if [ ! -d "uploads" ]; then
    echo -e "${BLUE}[*] Creating uploads directory...${NC}"
    mkdir -p uploads
fi

# Show startup info
echo -e "${GREEN}"
echo "✓ Setup complete!"
echo -e "${NC}"
echo -e "${YELLOW}Starting Flask server...${NC}"
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Web Interface will be available at:                   ║${NC}"
echo -e "${GREEN}║  → http://localhost:5000                               ║${NC}"
echo -e "${GREEN}║  → http://0.0.0.0:5000                                 ║${NC}"
echo -e "${GREEN}║                                                        ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop the server                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Run Flask app
python3 app.py
