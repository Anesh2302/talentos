import sys
import os
from urllib.parse import quote_plus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _build_pg_url():
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST")
    db = os.environ.get("POSTGRES_DATABASE", "postgres")
    if not all([user, password, host]):
        return ""
    pw_encoded = quote_plus(password)
    driver = "postgresql"
    try:
        __import__("psycopg2")
    except ImportError:
        driver = "postgresql+pg8000"
    return f"{driver}://{user}:{pw_encoded}@{host}:6543/{db}"

# Fix: Vercel can't write to the project dir, so use /tmp for SQLite
if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite:///"):
        pg_url = _build_pg_url()
        os.environ["DATABASE_URL"] = pg_url or "sqlite:////tmp/talentos.db"

from talentos import create_app

app = create_app()
