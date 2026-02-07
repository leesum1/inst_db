"""Web UI Configuration."""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
STATIC_FOLDER = BASE_DIR / "static"
TEMPLATE_FOLDER = BASE_DIR / "templates"

# Flask config
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB max upload size
ALLOWED_EXTENSIONS = {"db", "sqlite", "sqlite3"}

# Database config
DB_SESSION_TIMEOUT = 3600  # 1 hour in seconds
CLEANUP_INTERVAL = 3600  # Cleanup every hour

# Pagination
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500

# Dependency query config
DEFAULT_MAX_DEPTH = 10
MAX_DEPTH_LIMIT = 50

# Ensure upload folder exists
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
