import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix: Vercel can't write to the project dir, so use /tmp for SQLite
if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite:///"):
        pg_url = os.environ.get("POSTGRES_URL", "")
        if pg_url:
            db_url = pg_url.replace("?sslmode=require", "")
            if db_url.startswith("postgres://"):
                db_url = "postgresql" + db_url[len("postgres"):]
            # Try psycopg2 first, fall back to pg8000 (pure Python)
            try:
                __import__("psycopg2")
            except ImportError:
                db_url = db_url.replace("postgresql://", "postgresql+pg8000://")
            os.environ["DATABASE_URL"] = db_url
        else:
            os.environ["DATABASE_URL"] = "sqlite:////tmp/talentos.db"

from talentos import create_app

app = create_app()
