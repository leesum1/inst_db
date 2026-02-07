#!/usr/bin/env python3
"""
Instruction Database Web UI Launcher

Usage:
    python start_web_ui.py [--host HOST] [--port PORT] [--debug]
    
Examples:
    python start_web_ui.py
    python start_web_ui.py --port 8080 --debug
    python start_web_ui.py --host 0.0.0.0 --port 5000
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from inst_db.web_ui.app import main

if __name__ == "__main__":
    main()
