import os
import logging
import requests
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Supply Chain Hunter Service")

# Allow CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("PGHOST", "postgres-db"),
        port=os.getenv("PGPORT", "5432"),
        database=os.getenv("POSTGRES_DB", "osv_db"),
        user=os.getenv("POSTGRES_USER", "osvuser"),
        password=os.getenv("POSTGRES_PASSWORD", "CHANGE_ME")
    )

# ----------------- Configurations -----------------
# JFrog
JFROG_URL = os.getenv("JFROG_URL", "https://your-artifactory.jfrog.io/artifactory")
JFROG_USER = os.getenv("JFROG_USER", "admin")
JFROG_TOKEN = os.getenv("JFROG_TOKEN", "")

# CrowdStrike
CS_CLIENT_ID = os.getenv("CS_CLIENT_ID", "")
CS_CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET", "")
CS_BASE_URL = os.getenv("CS_BASE_URL", "https://api.crowdstrike.com")
# --------------------------------------------------

class MalwareReport(BaseModel):
    vulnerability_id: str
    package_name: str
    version: str
    ecosystem: str

def hunt_in_artifactory(report: MalwareReport):
    """
    Search JFrog Artifactory using AQL to find the compromised component.
    """
    logger.info(f"[Artifactory] Hunting for {report.package_name}@{report.version} ({report.ecosystem})")
    if not JFROG_TOKEN:
        logger.warning("[Artifactory] JFROG_TOKEN not configured. Skipping Artifactory hunt.")
        return

    # Basic AQL to find any artifact matching the name and version.
    # We use wildcards as different ecosystems store paths differently.
    query = f'items.find({{"name": {{"$match":"*{report.package_name}*{report.version}*"}}}})'
    
    headers = {"Content-Type": "text/plain"}
    auth = (JFROG_USER, JFROG_TOKEN)
    
    try:
        response = requests.post(f"{JFROG_URL}/api/search/aql", headers=headers, auth=auth, data=query, timeout=10)
        response.raise_for_status()
        
        results = response.json().get('results', [])
        if results:
            logger.error(f"[🚨 CIRITICAL] Found {len(results)} compromised artifacts in Artifactory!")
            for item in results:
                logger.error(f"  -> Path: {item.get('repo')}/{item.get('path')}/{item.get('name')}")
        else:
            logger.info(f"[Artifactory] No compromised artifacts found matching {report.package_name}@{report.version}")
            
    except Exception as e:
        logger.error(f"[Artifactory] Error querying Artifactory: {e}")


def get_crowdstrike_token():
    payload = {
        'client_id': CS_CLIENT_ID,
        'client_secret': CS_CLIENT_SECRET
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(f"{CS_BASE_URL}/oauth2/token", data=payload, headers=headers)
    response.raise_for_status()
    return response.json().get("access_token")

def hunt_in_crowdstrike(report: MalwareReport):
    """
    Search CrowdStrike Falcon for the compromised component.
    Normally, we'd search for hashes, but since we have a package name/version,
    we can search Custom Rules / Indicators of Compromise (IOC) API to alert everywhere.
    """
    logger.info(f"[CrowdStrike] Hunting for endpoints affected by {report.package_name}@{report.version}")
    
    if not CS_CLIENT_ID or not CS_CLIENT_SECRET:
        logger.warning("[CrowdStrike] Credentials not configured. Skipping CrowdStrike hunt.")
        return
        
    try:
        token = get_crowdstrike_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # NOTE: Searching for a specific package binary by name is complex in Falcon without the SHA256.
        # This is a sample on how to list/query endpoint events related to the package name via FQL.
        # Let's hit the Spotlight Vulnerabilities endpoint or generic Host Search.
        # For this example, we mock the search using the hosts endpoint with a generic filter.
        fql_filter = f"hostname:*'*{report.package_name}*'*" # Placeholder FQL
        params = {"filter": fql_filter, "limit": 10}
        
        response = requests.get(f"{CS_BASE_URL}/devices/queries/devices/v1", headers=headers, params=params)
        
        # A 4xx or 5xx will be caught by raise_for_status() if not valid, but since this is a mocked logic, 
        # let's just log success.
        if response.status_code == 200:
            device_ids = response.json().get('resources', [])
            if device_ids:
                logger.error(f"[🚨 CIRITICAL] Potential affected endpoints found in CrowdStrike: {device_ids}")
            else:
                logger.info(f"[CrowdStrike] No endpoints found affected by {report.package_name}")
        else:
             logger.warning(f"[CrowdStrike] Non-200 API response: {response.text}")
             
    except Exception as e:
        logger.error(f"[CrowdStrike] Error interacting with CrowdStrike API: {e}")

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

def process_report(report: MalwareReport):
    hunt_in_artifactory(report)
    hunt_in_crowdstrike(report)

@app.post("/webhook/malware", tags=["Webhooks"], summary="Ingest Threat Intelligence", description="Receives incoming malware alerts and begins background hunting across configured vendor APIs.")
async def receive_malware_report(report: MalwareReport, background_tasks: BackgroundTasks):
    logger.info(f"Received malware report: {report.vulnerability_id} concerning {report.package_name}")
    
    # Run the hunting processes asynchronously so we don't block the webhook response
    background_tasks.add_task(process_report, report)
    
    return {"status": "accepted", "message": f"Hunting initiated for {report.vulnerability_id}"}

@app.get("/health", response_model=HealthResponse, tags=["Diagnostics"], summary="Check Service Health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/vulnerabilities/recent", response_model=RecentVulnerabilitiesResponse, tags=["Dashboard"], summary="List recent vulnerabilities", description="Retrieve paginated malware intelligence with dynamic text search over package names.")
async def get_recent_vulnerabilities(page: int = 1, limit: int = 10, search: str = None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        offset = (page - 1) * limit
        
        # Build counting query First
        count_query = "SELECT COUNT(*) FROM osv_vulnerabilities"
        count_params = []
        if search:
            count_query += " WHERE data->'affected'->0->'package'->>'name' ILIKE %s"
            count_params.append(f"%{search}%")
            
        cur.execute(count_query, tuple(count_params))
        total = cur.fetchone()[0]
        
        # Build matching query 
        query = """
            SELECT id, published, data->'affected'->0->'package'->>'name' AS package_name, data->'affected'->0->'versions' AS affected_versions, data->'affected'->0->'package'->>'ecosystem' AS ecosystem, data->>'summary' AS summary
            FROM osv_vulnerabilities
        """
        params = []
        if search:
            query += " WHERE data->'affected'->0->'package'->>'name' ILIKE %s"
            params.append(f"%{search}%")
            
        query += " ORDER BY published DESC NULLS LAST LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        
        cur.close()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "published": row[1].isoformat() if row[1] else None,
                "package_name": row[2] or "Unknown",
                "affected_versions": row[3] or [],
                "ecosystem": row[4] or "Unknown",
                "summary": row[5] or "No summary available."
            })
            
        total_pages = (total + limit - 1) // limit if limit > 0 else 1
        
        return {
            "status": "success", 
            "data": results,
            "pagination": {
                "total": total,
                "page": page,
                "total_pages": total_pages,
                "limit": limit
            }
        }
    except Exception as e:
        logger.error(f"Error fetching recent: {e}")
        raise HTTPException(status_code=500, detail="Database error")

@app.get("/api/vulnerabilities/stats", response_model=StatsResponse, tags=["Dashboard"], summary="Malware Ecosystem Statistics")
async def get_vulnerability_stats():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Group by ecosystem
        cur.execute("""
            SELECT data->'affected'->0->'package'->>'ecosystem' AS ecosystem, COUNT(*) 
            FROM osv_vulnerabilities
            GROUP BY ecosystem
            ORDER BY COUNT(*) DESC;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        stats = [{"ecosystem": row[0] or "Unknown", "count": row[1]} for row in rows]
        return {"status": "success", "data": stats}
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Database error")
