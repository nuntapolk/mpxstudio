#!/bin/bash
# MPX AppPort — Quick Start
# Usage: bash run.sh [port]

PORT=${1:-8099}

echo "=================================="
echo " MPX AppPort EA Portfolio"
echo "=================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8+"
    exit 1
fi

# Install dependencies if needed
echo "📦 Checking dependencies..."
python3 -m pip install -q -r requirements.txt

echo "🚀 Starting server on http://localhost:$PORT"
echo "   Press Ctrl+C to stop"
echo ""

python3 -m uvicorn server:app --host 0.0.0.0 --port $PORT
