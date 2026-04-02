import os
import zipfile
import tempfile
import shutil
import json
import logging
import requests
import psycopg2
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

OSV_ALL_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

def get_db_connection():
    password = os.environ.get("POSTGRES_PASSWORD")
    if not password:
        raise RuntimeError("POSTGRES_PASSWORD environment variable is not set")
    return psycopg2.connect(
        host=os.getenv("PGHOST", "localhost"),
        port=os.getenv("PGPORT", "5432"),
        database=os.getenv("POSTGRES_DB", "osv_db"),
        user=os.getenv("POSTGRES_USER", "osvuser"),
        password=password
    )

def download_and_extract_osv_data():
    logging.info(f"Downloading OSV data from {OSV_ALL_URL}")
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, 'all.zip')
    
    with requests.get(OSV_ALL_URL, stream=True) as r:
        r.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192*4):
                f.write(chunk)
                
    logging.info("Extracting OSV data to temporary directory")
    with zipfile.ZipFile(zip_path) as zip_ref:
        zip_ref.extractall(temp_dir)
        
    os.remove(zip_path)
    return temp_dir

def sync_data(temp_dir):
    conn = get_db_connection()
    cur = conn.cursor()
    
    logging.info("Starting database ingestion")
    count = 0
    for file_root, _, files in os.walk(temp_dir):
        for file_name in files:
            if not file_name.endswith('.json'):
                continue
                
            file_path = os.path.join(file_root, file_name)
            with open(file_path, 'r') as f:
                try:
                    data = json.load(f)
                    vuln_id = data.get('id')
                    
                    # Only ingest MALWARE reports
                    if not vuln_id or not vuln_id.startswith('MAL-'):
                        continue
                        
                    modified = data.get('modified')
                    published = data.get('published')
                    schema_version = data.get('schema_version', '1.0.0')
                    
                    # Perform UPSERT (Insert or Update if exists)
                    cur.execute("""
                        INSERT INTO osv_vulnerabilities (id, modified, published, schema_version, data)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            modified = EXCLUDED.modified,
                            published = EXCLUDED.published,
                            schema_version = EXCLUDED.schema_version,
                            data = EXCLUDED.data;
                    """, (vuln_id, modified, published, schema_version, json.dumps(data)))
                    count += 1
                    
                    if count % 5000 == 0:
                        logging.info(f"Ingested {count} records...")
                        conn.commit()
                except Exception as e:
                    logging.error(f"Error processing {file_name}: {e}")
                
    conn.commit()
    cur.close()
    conn.close()
    logging.info(f"Finished ingesting {count} records.")

def main():
    temp_dir = None
    try:
        temp_dir = download_and_extract_osv_data()
        sync_data(temp_dir)
        logging.info("Sync completed successfully.")
    except Exception as e:
        logging.error(f"Sync failed: {e}")
        exit(1)
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            logging.info(f"Cleaned up temp directory: {temp_dir}")

if __name__ == "__main__":
    main()
