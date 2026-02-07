#!/usr/bin/env python3
"""Initialize the instruction database."""

import os
import sys

# Add src to path to import inst_db
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from inst_db.api import InstructionDB

def main():
    """Initialize a fresh database."""
    db_path = "trace.db"
    
    # Create database URL
    db_url = f"sqlite:///{os.path.abspath(db_path)}"
    
    print(f"Initializing database at {db_path}...")
    
    # Initialize the database
    db = InstructionDB(db_url)
    
    print("✓ Database initialized successfully!")
    print(f"Database file: {os.path.abspath(db_path)}")
    print("\nYou can now use the database with:")
    print(f"  db = InstructionDB('{db_url}')")

if __name__ == "__main__":
    main()
