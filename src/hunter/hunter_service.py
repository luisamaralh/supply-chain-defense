import os
import re
import logging
import logging.config
import concurrent.futures
import requests
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2

# ── Logging ───────────────────────────────────────────────────────────────────
# Fix #10: structured logging config instead of basicConfig at module level
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
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        }
    },
    "root": {"level": "INFO", "handlers": ["console"]},
})
logger = logging.getLogger(__name__)

# ── FastAPI app ───────────────────────────────────────────────────────────────
# Fix #9: full metadata for Swagger UI
app = FastAPI(
    title="Supply Chain Hunter Service",
    description=(
        "Ingests threat intelligence via webhooks, hunts compromised packages "
        "in JFrog Artifactory and CrowdStrike Falcon, and exposes the OSV malware "
        "database as a paginated REST API for the dashboard."
    ),
    version="1.0.0",
    contact={"name": "Supply Chain Defense", "url": "https://github.com/luisamaralh/supply-chain-defense"},
    license_info={"name": "MIT"},
)

# Fix #5: CORS is only needed for direct browser→API calls (local Minikube dev).
# In Docker Compose, Nginx proxies /api → hunter-service, so CORS is irrelevant.
# Restrict to explicit origins instead of the invalid allow_origins=* + credentials combo.
_CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Pydantic models ───────────────────────────────────────────────────────────
# Fix #8: models grouped at the top, before any route definitions

class MalwareReport(BaseModel):
    vulnerability_id: str
    package_name: str
    version: str
    ecosystem: str

class HealthResponse(BaseModel):
    status: str

class Vulnerability(BaseModel):
    id: str
    published: str | None = None
    package_name: str
    affected_versions: list[str]
    ecosystem: str
    summary: str | None = None

class PaginationMeta(BaseModel):
    total: int
    page: int
    total_pages: int
    limit: int

class RecentVulnerabilitiesResponse(BaseModel):
    status: str
    data: list[Vulnerability]
    pagination: PaginationMeta

class StatItem(BaseModel):
    ecosystem: str
    count: int

class StatsResponse(BaseModel):
    status: str
    data: list[StatItem]

# ── Database ──────────────────────────────────────────────────────────────────

def get_db_connection():
    password = os.environ.get("POSTGRES_PASSWORD")
    if not password:
        raise RuntimeError("POSTGRES_PASSWORD environment variable is not set")
    return psycopg2.connect(
        host=os.getenv("PGHOST", "postgres-db"),
        port=os.getenv("PGPORT", "5432"),
        database=os.getenv("POSTGRES_DB", "osv_db"),
        user=os.getenv("POSTGRES_USER", "osvuser"),
        password=password,
    )

# ── AQL sanitization ──────────────────────────────────────────────────────────
# Fix #1: strip characters that have special meaning in JFrog AQL
_AQL_UNSAFE = re.compile(r'["\\\{\}\[\]\*\?]')

def _sanitize_aql(value: str) -> str:
    return _AQL_UNSAFE.sub("", value)

# ── Vendor configurations ─────────────────────────────────────────────────────
# Fix #4: read from os.getenv() inside functions so rotation-safe (env can be
#         refreshed without a restart in some setups). Constants kept for
#         non-sensitive defaults only.

def _jfrog_config():
    return {
        "url": os.getenv("JFROG_URL", ""),
        "user": os.getenv("JFROG_USER", "admin"),
        "token": os.getenv("JFROG_TOKEN", ""),
    }

def _cs_config():
    return {
        "client_id": os.getenv("CS_CLIENT_ID", ""),
        "client_secret": os.getenv("CS_CLIENT_SECRET", ""),
        "base_url": os.getenv("CS_BASE_URL", "https://api.crowdstrike.com"),
    }

# ── Vendor hunts ──────────────────────────────────────────────────────────────

def hunt_in_artifactory(report: MalwareReport):
    """Search JFrog Artifactory using AQL to find the compromised component."""
    cfg = _jfrog_config()
    logger.info(f"[Artifactory] Hunting for {report.package_name}@{report.version} ({report.ecosystem})")

    if not cfg["token"]:
        logger.warning("[Artifactory] JFROG_TOKEN not configured. Skipping.")
        return

    # Fix #1: sanitize before interpolating into AQL
    safe_name = _sanitize_aql(report.package_name)
    safe_ver  = _sanitize_aql(report.version)
    query = f'items.find({{"name": {{"$match":"*{safe_name}*{safe_ver}*"}}}})'

    headers = {"Content-Type": "text/plain"}
    auth = (cfg["user"], cfg["token"])

    try:
        response = requests.post(
            f"{cfg['url']}/api/search/aql",
            headers=headers,
            auth=auth,
            data=query,
            timeout=10,
        )
        response.raise_for_status()
        results = response.json().get("results", [])
        if results:
            # Fix #2: corrected typo "CIRITICAL" → "CRITICAL"
            logger.error(f"[🚨 CRITICAL] Found {len(results)} compromised artifacts in Artifactory!")
            for item in results:
                logger.error(f"  -> Path: {item.get('repo')}/{item.get('path')}/{item.get('name')}")
        else:
            logger.info(f"[Artifactory] No compromised artifacts found for {report.package_name}@{report.version}")
    except Exception as e:
        logger.error(f"[Artifactory] Error querying Artifactory: {e}")


def _get_crowdstrike_token(cfg: dict) -> str:
    payload = {"client_id": cfg["client_id"], "client_secret": cfg["client_secret"]}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    # Fix #3: add timeout (was missing, could block indefinitely)
    response = requests.post(
        f"{cfg['base_url']}/oauth2/token",
        data=payload,
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    return response.json().get("access_token")


def hunt_in_crowdstrike(report: MalwareReport):
    """Search CrowdStrike Falcon for endpoints affected by the compromised package."""
    cfg = _cs_config()
    logger.info(f"[CrowdStrike] Hunting for endpoints affected by {report.package_name}@{report.version}")

    if not cfg["client_id"] or not cfg["client_secret"]:
        logger.warning("[CrowdStrike] Credentials not configured. Skipping.")
        return

    try:
        token = _get_crowdstrike_token(cfg)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        fql_filter = f"hostname:*'*{_sanitize_aql(report.package_name)}*'*"
        params = {"filter": fql_filter, "limit": 10}

        response = requests.get(
            f"{cfg['base_url']}/devices/queries/devices/v1",
            headers=headers,
            params=params,
            timeout=10,
        )
        if response.status_code == 200:
            device_ids = response.json().get("resources", [])
            if device_ids:
                # Fix #2: corrected typo "CIRITICAL" → "CRITICAL"
                logger.error(f"[🚨 CRITICAL] Potential affected endpoints found in CrowdStrike: {device_ids}")
            else:
                logger.info(f"[CrowdStrike] No endpoints found affected by {report.package_name}")
        else:
            logger.warning(f"[CrowdStrike] Non-200 response: {response.status_code} {response.text[:200]}")
    except Exception as e:
        logger.error(f"[CrowdStrike] Error interacting with CrowdStrike API: {e}")


# Fix #7: run both vendor hunts in parallel instead of sequentially
def process_report(report: MalwareReport):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(hunt_in_artifactory, report)
        f2 = pool.submit(hunt_in_crowdstrike, report)
        for f in concurrent.futures.as_completed([f1, f2]):
            exc = f.exception()
            if exc:
                logger.error(f"[process_report] Unhandled error in vendor hunt: {exc}")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post(
    "/webhook/malware",
    tags=["Webhooks"],
    summary="Ingest Threat Intelligence",
    description="Receives incoming malware alerts and begins background hunting across configured vendor APIs.",
)
async def receive_malware_report(report: MalwareReport, background_tasks: BackgroundTasks):
    logger.info(f"Received malware report: {report.vulnerability_id} concerning {report.package_name}")
    background_tasks.add_task(process_report, report)
    return {"status": "accepted", "message": f"Hunting initiated for {report.vulnerability_id}"}


@app.get("/health", response_model=HealthResponse, tags=["Diagnostics"], summary="Check Service Health")
async def health_check():
    return {"status": "healthy"}


@app.get(
    "/api/vulnerabilities/recent",
    response_model=RecentVulnerabilitiesResponse,
    tags=["Dashboard"],
    summary="List recent vulnerabilities",
    description="Retrieve paginated malware intelligence with optional free-text search over package names.",
)
async def get_recent_vulnerabilities(
    # Fix #6: bound page and limit to prevent unbounded queries
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=10, ge=1, le=100, description="Results per page (max 100)"),
    search: str | None = Query(default=None, max_length=100, description="Filter by package name"),
):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        offset = (page - 1) * limit

        count_query = "SELECT COUNT(*) FROM osv_vulnerabilities"
        count_params: list = []
        if search:
            count_query += " WHERE data->'affected'->0->'package'->>'name' ILIKE %s"
            count_params.append(f"%{search}%")

        cur.execute(count_query, tuple(count_params))
        total = cur.fetchone()[0]

        query = """
            SELECT id, published,
                   data->'affected'->0->'package'->>'name'    AS package_name,
                   data->'affected'->0->'versions'            AS affected_versions,
                   data->'affected'->0->'package'->>'ecosystem' AS ecosystem,
                   data->>'summary'                           AS summary
            FROM osv_vulnerabilities
        """
        params: list = []
        if search:
            query += " WHERE data->'affected'->0->'package'->>'name' ILIKE %s"
            params.append(f"%{search}%")

        query += " ORDER BY published DESC NULLS LAST LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, tuple(params))
        rows = cur.fetchall()

        results = [
            {
                "id": row[0],
                "published": row[1].isoformat() if row[1] else None,
                "package_name": row[2] or "Unknown",
                "affected_versions": row[3] or [],
                "ecosystem": row[4] or "Unknown",
                "summary": row[5] or "No summary available.",
            }
            for row in rows
        ]

        total_pages = (total + limit - 1) // limit if limit > 0 else 1

        return {
            "status": "success",
            "data": results,
            "pagination": {
                "total": total,
                "page": page,
                "total_pages": total_pages,
                "limit": limit,
            },
        }
    except Exception as e:
        logger.error(f"Error fetching recent vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.get(
    "/api/vulnerabilities/stats",
    response_model=StatsResponse,
    tags=["Dashboard"],
    summary="Malware Ecosystem Statistics",
    description="Returns the count of malware records grouped by target ecosystem.",
)
async def get_vulnerability_stats():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT data->'affected'->0->'package'->>'ecosystem' AS ecosystem, COUNT(*)
            FROM osv_vulnerabilities
            GROUP BY ecosystem
            ORDER BY COUNT(*) DESC;
        """)
        rows = cur.fetchall()
        stats = [{"ecosystem": row[0] or "Unknown", "count": row[1]} for row in rows]
        return {"status": "success", "data": stats}
    except Exception as e:
        logger.error(f"Error fetching ecosystem stats: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
