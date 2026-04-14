import os
import zipfile
import tempfile
import shutil
import json
import logging
import logging.config
import requests
import psycopg2
import psycopg2.errors
from datetime import datetime, timezone

# ── Logging ───────────────────────────────────────────────────────────────────
# Fix #9: consistent module-level logger instead of root logger calls
logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        }
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "default"}
    },
    "root": {"level": "INFO", "handlers": ["console"]},
})
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
OSV_ALL_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

# Fix #10: commit interval configurable via env var
COMMIT_INTERVAL = int(os.getenv("SYNC_COMMIT_INTERVAL", "5000"))


# ── Database ──────────────────────────────────────────────────────────────────

def get_db_connection():
    password = os.environ.get("POSTGRES_PASSWORD")
    if not password:
        raise RuntimeError("POSTGRES_PASSWORD environment variable is not set")
    return psycopg2.connect(
        host=os.getenv("PGHOST", "localhost"),
        port=os.getenv("PGPORT", "5432"),
        database=os.getenv("POSTGRES_DB", "osv_db"),
        user=os.getenv("POSTGRES_USER", "osvuser"),
        password=password,
    )


# ── Zip-slip guard ────────────────────────────────────────────────────────────
# Fix #5: validate every entry path before extraction to prevent zip-slip attacks

def _safe_extract(zip_ref: zipfile.ZipFile, dest: str) -> None:
    """Extract zip archive, rejecting any entry that would write outside dest."""
    dest = os.path.realpath(dest)
    for member in zip_ref.infolist():
        member_path = os.path.realpath(os.path.join(dest, member.filename))
        if not member_path.startswith(dest + os.sep):
            raise ValueError(f"Zip-slip detected: {member.filename!r} escapes destination")
        zip_ref.extract(member, dest)


# ── Download & Extract ────────────────────────────────────────────────────────

def download_and_extract_osv_data() -> str:
    logger.info(f"Downloading OSV data from {OSV_ALL_URL}")
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "all.zip")

    # Fix #4: add connect timeout (30s); read timeout left unbounded for large file
    with requests.get(OSV_ALL_URL, stream=True, timeout=(30, None)) as r:
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192 * 4):
                f.write(chunk)

    logger.info("Extracting OSV data to temporary directory")
    with zipfile.ZipFile(zip_path) as zip_ref:
        # Fix #5: use safe extraction instead of extractall
        _safe_extract(zip_ref, temp_dir)

    os.remove(zip_path)
    return temp_dir


# ── Date parsing ──────────────────────────────────────────────────────────────
# Fix #6: parse and validate OSV date strings before passing to psycopg2

def _parse_osv_date(value: str | None) -> datetime | None:
    """Parse an OSV RFC-3339 date string into a timezone-aware datetime, or None."""
    if not value:
        return None
    try:
        # OSV uses "Z" suffix — replace with "+00:00" for fromisoformat (Python < 3.11)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        logger.warning(f"Could not parse date: {value!r} — storing as NULL")
        return None


# ── Sync ──────────────────────────────────────────────────────────────────────

def sync_data(temp_dir: str) -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    count = 0
    skipped = 0
    errors = 0

    # Fix #2: wrap entire function body in try/finally so connection always closes
    try:
        logger.info("Starting database ingestion")
        for file_root, _, files in os.walk(temp_dir):
            for file_name in files:
                if not file_name.endswith(".json"):
                    continue

                file_path = os.path.join(file_root, file_name)

                # Fix #1 & #7: open inside try with explicit UTF-8 encoding
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    vuln_id = data.get("id")

                    # Only ingest MALWARE reports
                    if not vuln_id or not vuln_id.startswith("MAL-"):
                        skipped += 1
                        continue

                    # Fix #6: parse dates before insert
                    modified = _parse_osv_date(data.get("modified"))
                    published = _parse_osv_date(data.get("published"))
                    schema_version = data.get("schema_version", "1.0.0")

                    cur.execute(
                        """
                        INSERT INTO osv_vulnerabilities (id, modified, published, schema_version, data)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            modified       = EXCLUDED.modified,
                            published      = EXCLUDED.published,
                            schema_version = EXCLUDED.schema_version,
                            data           = EXCLUDED.data;
                        """,
                        (vuln_id, modified, published, schema_version, json.dumps(data)),
                    )
                    count += 1

                    # Fix #10: use configurable commit interval
                    if count % COMMIT_INTERVAL == 0:
                        logger.info(f"Ingested {count} records...")
                        conn.commit()

                # Fix #3: separate DB errors (re-raise) from per-file parse errors (log and continue)
                except psycopg2.Error as db_err:
                    logger.error(f"Database error on {file_name} — aborting sync: {db_err}")
                    raise
                except (json.JSONDecodeError, UnicodeDecodeError, OSError) as file_err:
                    logger.error(f"Skipping {file_name} due to file error: {file_err}")
                    errors += 1

        conn.commit()
        logger.info(
            f"Sync complete — ingested: {count}, skipped (non-malware): {skipped}, file errors: {errors}"
        )

    finally:
        # Fix #2: guaranteed cleanup regardless of success or failure
        cur.close()
        conn.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    temp_dir = None
    try:
        temp_dir = download_and_extract_osv_data()
        sync_data(temp_dir)
        logger.info("Sync completed successfully.")
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        exit(1)
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temp directory: {temp_dir}")


if __name__ == "__main__":
    main()
