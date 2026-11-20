"""Local-only service settings. No elevated subprocesses are executed here."""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(os.environ.get("VIRTUALANCHOO_DATA_DIR", ROOT / "data"))
MAX_PACKETS = 100_000
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_SESSION_BYTES = 128 * 1024 * 1024
MAX_STORAGE_BYTES = 1024 * 1024 * 1024
ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8765", "http://127.0.0.1:8765"}

# Explicit extra browser origins only; never accept a wildcard or arbitrary Host.
ALLOWED_ORIGINS.update(origin.strip().rstrip("/") for origin in os.environ.get("VIRTUALANCHOO_ALLOWED_ORIGINS", "").split(",") if origin.strip() and origin.strip() != "*")
