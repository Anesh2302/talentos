import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix: Vercel can't write to the project dir, so use /tmp for SQLite
if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite:///"):
        os.environ["DATABASE_URL"] = "sqlite:////tmp/talentos.db"

from talentos import create_app

app = create_app()
