"""
MPX Studio EA Portfolio — FastAPI + SQLite Backend
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requirements:  pip install fastapi uvicorn

Run:
  python server.py
  หรือ: uvicorn server:app --reload --port 8000

Endpoints:
  GET  /                           -> Frontend (static/index.html)
  GET  /api/version                -> App version info
  GET  /api/stats                  -> Dashboard KPIs
  GET  /api/apps                   -> List apps (filters: status, domain, bcg, ea_group, search, show_decomm)
  GET  /api/apps/{id}              -> Get single app
  POST /api/apps                   -> Create app
  PUT  /api/apps/{id}              -> Update app
  POST /api/apps/{id}/decommission -> Decommission app
  GET  /api/ea/structure           -> EA structure with counts
  GET  /docs                       -> Swagger UI
"""

from __future__ import annotations
import json, os, sqlite3, uuid, time, hmac, hashlib, base64, secrets
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, List, Optional

try:
    from fastapi import FastAPI, HTTPException, Request, Depends
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
    except ImportError:
        from fastapi.middleware.base import BaseHTTPMiddleware
except ImportError:
    print("=" * 60)
    print("ERROR: FastAPI not installed.")
    print("Run: pip install fastapi uvicorn")
    print("=" * 60)
    raise SystemExit(1)

# ─── CONFIG — อ่านจาก mpx-studio.config.json ────────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mpx-studio.config.json")

def _load_config() -> dict:
    defaults = {
        "version":      "V001",
        "app_name":     "MPX Studio",
        "subtitle":     "EA PORTFOLIO",
        "organization": "MPX",
        "description":  "Enterprise Application Portfolio Management",
    }
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                defaults.update(json.load(f))
            print(f"✅ Config loaded from {_CONFIG_PATH}")
        except Exception as e:
            print(f"⚠️  Cannot read config: {e} — using defaults")
    else:
        print(f"ℹ️  mpx-studio.config.json not found — using defaults")
    return defaults

CFG          = _load_config()
APP_VERSION  = CFG["version"]
APP_NAME     = CFG.get("app_name", "MPX Studio")
APP_SUBTITLE = CFG.get("subtitle", "EA PORTFOLIO")

_BASE          = os.path.dirname(os.path.abspath(__file__))
DB_PATH        = os.path.join(_BASE, "mpx-studio.db")
AUDIT_DB_PATH  = os.path.join(_BASE, "mpx-studio_audit.db")
VENDOR_DB_PATH = os.path.join(_BASE, "vendor.db")
PORT           = 8000
STATIC_DIR     = os.path.join(_BASE, "static")


# ─── AUTH CONFIG ───────────────────────────────────────────────────────────────
_USERS_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.config.json")

def _load_users_config() -> dict:
    defaults = {"jwt_secret": secrets.token_hex(32), "token_expire_minutes": 480, "users": []}
    if os.path.exists(_USERS_CONFIG_PATH):
        try:
            with open(_USERS_CONFIG_PATH, "r", encoding="utf-8") as f:
                defaults.update(json.load(f))
            print(f"✅ Users config loaded ({len(defaults.get('users',[]))} users)")
        except Exception as e:
            print(f"⚠️  Cannot read users.config.json: {e}")
    else:
        print("ℹ️  users.config.json not found — auth disabled (open access)")
    return defaults

_UCFG = _load_users_config()
_AUTH_ENABLED = bool(_UCFG.get("users"))

# ─── Password & JWT helpers (stdlib only — no pip needed) ─────────────────────
def _verify_password(password: str, hashed: str) -> bool:
    try:
        parts = hashed.split("$")
        if parts[0] == "pbkdf2" and len(parts) == 5:
            _, algo, iterations, salt_b64, dk_b64 = parts
            salt = base64.b64decode(salt_b64)
            dk_stored = base64.b64decode(dk_b64)
            dk_check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
            return hmac.compare_digest(dk_check, dk_stored)
        return False
    except Exception:
        return False

def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_dec(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4: s += "=" * pad
    return base64.urlsafe_b64decode(s)

def _create_jwt(payload: dict) -> str:
    secret = _UCFG.get("jwt_secret", "fallback-secret")
    expire = _UCFG.get("token_expire_minutes", 480)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {**payload, "iat": int(time.time()), "exp": int(time.time()) + expire * 60}
    h = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_enc(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), digestmod=hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_enc(sig)}"

def _verify_jwt(token: str) -> dict:
    secret = _UCFG.get("jwt_secret", "fallback-secret")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    h, p, sig = parts
    expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_dec(sig), expected):
        raise ValueError("Invalid signature")
    payload = json.loads(_b64url_dec(p))
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expired")
    return payload

def _get_user_dict(username: str) -> Optional[dict]:
    for u in _UCFG.get("users", []):
        if u["username"] == username and u.get("active", True):
            return u
    return None

# ─── FastAPI auth dependency ───────────────────────────────────────────────────
try:
    _bearer_scheme = HTTPBearer(auto_error=False)
except Exception:
    _bearer_scheme = None

def _require_auth(credentials: Optional[Any] = Depends(_bearer_scheme)):
    if not _AUTH_ENABLED:
        return {"sub": "anonymous", "roles": ["admin"], "menus": ["*"]}
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = _verify_jwt(credentials.credentials)
        return payload
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

# Public paths that skip auth (prefix match)
_PUBLIC_PATHS = {"/api/auth/login", "/api/auth/refresh", "/docs", "/openapi.json", "/redoc"}

# ─── FASTAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = f"MPX Studio EA Portfolio {APP_VERSION}",
    description = "Enterprise Application Portfolio Management — REST API",
    version     = APP_VERSION,
)
_ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)
# NOTE: OperationLogMiddleware is added after init_audit_db() at the bottom of this file

# ─── AUDIT DATABASE ────────────────────────────────────────────────────────────
AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    log_id       TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,
    category     TEXT NOT NULL,  -- AUDIT | COMPLIANCE | OPERATION
    event_type   TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'INFO',
    actor_ip     TEXT,
    resource_id  TEXT,
    before_state TEXT,
    after_state  TEXT,
    risk_flags   TEXT,
    extra        TEXT,
    duration_ms  INTEGER,
    status_code  INTEGER,
    message      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_id);
"""

AUDIT_RETENTION = {"AUDIT": 3*365, "COMPLIANCE": 5*365, "OPERATION": 90}  # days

@contextmanager
def get_audit_db():
    conn = sqlite3.connect(AUDIT_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_audit_db():
    with get_audit_db() as conn:
        conn.executescript(AUDIT_DDL)
    print(f"Audit DB ready: {AUDIT_DB_PATH}")

def _purge_old_logs():
    """Remove logs beyond retention period."""
    try:
        with get_audit_db() as conn:
            for cat, days in AUDIT_RETENTION.items():
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
                conn.execute("DELETE FROM audit_log WHERE category=? AND ts<?", (cat, cutoff))
    except Exception as e:
        print(f"  Log purge error: {e}")

# ─── VENDOR DATABASE ───────────────────────────────────────────────────────────
VENDOR_DDL = """
CREATE TABLE IF NOT EXISTS vendors (
    vendor_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT,
    tier            TEXT DEFAULT 'Registered',
    status          TEXT DEFAULT 'Active',
    specializations TEXT DEFAULT '[]',
    certifications  TEXT DEFAULT '[]',
    contact_name    TEXT,
    contact_email   TEXT,
    website         TEXT,
    country         TEXT DEFAULT 'Thailand',
    nda_signed      INTEGER DEFAULT 0,
    insurance_amt   INTEGER DEFAULT 0,
    framework_end   TEXT,
    risk_rating     TEXT DEFAULT 'Medium',
    avg_score       REAL DEFAULT 0,
    notes           TEXT,
    created_at      TEXT,
    updated_at      TEXT
);
CREATE TABLE IF NOT EXISTS vendor_engagements (
    engagement_id       TEXT PRIMARY KEY,
    vendor_id           TEXT NOT NULL,
    app_id              TEXT,
    type                TEXT NOT NULL,
    scope               TEXT,
    start_date          TEXT,
    end_date            TEXT,
    status              TEXT DEFAULT 'Planned',
    critical            INTEGER DEFAULT 0,
    high                INTEGER DEFAULT 0,
    medium              INTEGER DEFAULT 0,
    low                 INTEGER DEFAULT 0,
    info_count          INTEGER DEFAULT 0,
    report_ref          TEXT,
    remediation_by      TEXT,
    remediation_status  TEXT DEFAULT 'Open',
    cost                INTEGER DEFAULT 0,
    score               INTEGER,
    notes               TEXT,
    created_at          TEXT
);
CREATE TABLE IF NOT EXISTS vendor_capabilities (
    cap_id      TEXT PRIMARY KEY,
    vendor_id   TEXT NOT NULL,
    capability  TEXT NOT NULL,
    proficiency INTEGER DEFAULT 3,
    certified   INTEGER DEFAULT 0,
    evidence    TEXT
);
CREATE INDEX IF NOT EXISTS idx_veng_vendor ON vendor_engagements(vendor_id);
CREATE INDEX IF NOT EXISTS idx_veng_app    ON vendor_engagements(app_id);
"""

@contextmanager
def get_vendor_db():
    conn = sqlite3.connect(VENDOR_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_vendor_db():
    with get_vendor_db() as conn:
        conn.executescript(VENDOR_DDL)
        if conn.execute("SELECT COUNT(*) FROM vendors").fetchone()[0] == 0:
            _seed_vendors(conn)
    print(f"Vendor DB ready: {VENDOR_DB_PATH}")

def _vrow(row) -> dict:
    d = dict(row)
    for f in ("specializations","certifications"):
        try: d[f] = json.loads(d.get(f) or "[]")
        except: d[f] = []
    for f in ("nda_signed",):
        if f in d: d[f] = bool(d[f])
    return d

def _erow(row) -> dict:
    d = dict(row)
    for f in ("critical","high","medium","low","info_count","cost","score"):
        d[f] = d.get(f) or 0
    return d

def _seed_vendors(conn):
    today = datetime.now().strftime("%Y-%m-%d")
    vendors = [
        ("VEN-001","CyberShield Thailand Ltd.","Pentest","Preferred","Active",
         json.dumps(["Web App","Mobile","API","Network"]),json.dumps(["CREST","OSCP","CEH","ISO 27001"]),
         "Apirak Suwan","apirak@cybershield.co.th","www.cybershield.co.th","Thailand",
         1,5000000,"2026-12-31","Low",8.7,"Preferred pentest vendor — strong web app coverage",today,today),
        ("VEN-002","SecureCode Asia Co., Ltd.","SAST","Preferred","Active",
         json.dumps(["SAST","DAST","Code Review","DevSecOps"]),json.dumps(["GWAPT","CISSP","ISO 27001"]),
         "Nattapat Lertkrai","nattapat@securecode.asia","www.securecode.asia","Thailand",
         1,3000000,"2026-06-30","Low",8.9,"Specialist in code review & DevSecOps pipeline integration",today,today),
        ("VEN-003","ThreatHunters Thailand","Red Team","Approved","Active",
         json.dumps(["Red Team","Social Engineering","Physical Security"]),json.dumps(["CRTO","OSCP","CEH"]),
         "Weerachai Pongpan","weerachai@threathunters.th","www.threathunters.th","Thailand",
         1,2000000,"2025-12-31","Medium",7.8,"Good red team capability — recommend for annual exercise",today,today),
        ("VEN-004","ComplianceFirst Advisory","Compliance Audit","Approved","Active",
         json.dumps(["ISO 27001","PDPA","PCI DSS","Gap Analysis"]),json.dumps(["CISA","CRISC","ISO 27001 Lead Auditor"]),
         "Sunisa Charoenphol","sunisa@compliancefirst.co.th","www.compliancefirst.co.th","Thailand",
         1,2000000,"2026-03-31","Low",8.2,"Strong PDPA and ISO 27001 expertise",today,today),
        ("VEN-005","NetDefense Solutions","VA","Approved","Active",
         json.dumps(["Vulnerability Assessment","Network Security","Infrastructure"]),json.dumps(["CEH","CompTIA Security+","CISSP"]),
         "Prasit Wannakarn","prasit@netdefense.co.th","www.netdefense.co.th","Thailand",
         1,1500000,"2025-09-30","Medium",7.5,"Reliable for routine VA — consider Preferred upgrade after next engagement",today,today),
        ("VEN-006","CloudSec Partners Ltd.","Cloud Security","Registered","Active",
         json.dumps(["Cloud Security","Azure","AWS","Container Security"]),json.dumps(["AWS Security Specialty","AZ-500","CKS"]),
         "Thanawut Siriporn","thanawut@cloudsec.co.th","www.cloudsec.co.th","Thailand",
         0,0,None,"Medium",0,"New vendor — under evaluation for cloud security engagements",today,today),
    ]
    conn.executemany("""INSERT OR IGNORE INTO vendors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vendors)

    caps = [
        ("CAP-001","VEN-001","pentest_web",5,1,"CREST Registered Tester"),
        ("CAP-002","VEN-001","pentest_mobile",4,1,"CREST Registered"),
        ("CAP-003","VEN-001","pentest_api",5,1,"CREST Registered Tester"),
        ("CAP-004","VEN-001","pentest_network",4,1,"CEH Certified"),
        ("CAP-005","VEN-001","VA_external",4,1,"CEH Certified"),
        ("CAP-006","VEN-002","SAST",5,1,"GWAPT Certified"),
        ("CAP-007","VEN-002","DAST",5,1,"GWAPT Certified"),
        ("CAP-008","VEN-002","code_review",5,1,"CISSP"),
        ("CAP-009","VEN-002","pentest_web",4,1,"GWAPT"),
        ("CAP-010","VEN-003","red_team",5,1,"CRTO Certified"),
        ("CAP-011","VEN-003","social_eng",4,1,"CRTO"),
        ("CAP-012","VEN-003","pentest_web",3,1,"OSCP"),
        ("CAP-013","VEN-003","pentest_network",4,1,"OSCP"),
        ("CAP-014","VEN-004","compliance_iso27001",5,1,"ISO 27001 Lead Auditor"),
        ("CAP-015","VEN-004","compliance_pdpa",5,1,"CISA"),
        ("CAP-016","VEN-004","compliance_pci",4,1,"CISA"),
        ("CAP-017","VEN-004","VA_internal",3,0,"Internal assessment only"),
        ("CAP-018","VEN-005","VA_external",4,1,"CEH"),
        ("CAP-019","VEN-005","VA_internal",5,1,"CEH"),
        ("CAP-020","VEN-005","pentest_network",3,1,"CompTIA Security+"),
        ("CAP-021","VEN-006","cloud_security",5,1,"AWS Security Specialty"),
        ("CAP-022","VEN-006","pentest_web",3,0,"Under evaluation"),
        ("CAP-023","VEN-006","container_security",4,1,"CKS"),
    ]
    conn.executemany("INSERT OR IGNORE INTO vendor_capabilities VALUES (?,?,?,?,?,?)", caps)

    engagements = [
        # ── ENG-001 to ENG-011 : original seed ──────────────────────────────────
        ("ENG-001","VEN-001","APP-001","Pentest","Web App Pentest — SAP Fiori UI & API","2024-09-01","2024-09-15","Completed",0,2,5,8,3,"RPT-2024-001","2024-11-30","Closed",250000,9,"All findings closed.",today),
        ("ENG-002","VEN-005","APP-002","VA","External VA — Salesforce integration endpoints","2024-10-01","2024-10-07","Completed",0,1,3,6,4,"RPT-2024-002","2024-12-15","In Progress",80000,8,"1 High (OAuth config) still in remediation",today),
        ("ENG-003","VEN-001","APP-002","Pentest","API Security Testing — Salesforce REST & Apex","2025-02-01","2025-02-14","In Progress",0,0,0,0,0,None,None,"Open",200000,None,"Currently in testing phase",today),
        ("ENG-004","VEN-001","APP-003","Pentest","AS/400 Security Assessment — Network + App layer","2023-06-01","2023-06-21","Completed",1,4,9,12,5,"RPT-2023-001","2023-09-30","In Progress",350000,8,"Critical: unpatched RPC. Remediation open due to legacy constraints.",today),
        ("ENG-005","VEN-004","APP-004","Compliance Audit","PDPA Gap Analysis — HR data processing & retention","2024-11-01","2024-11-15","Completed",0,0,2,4,6,"RPT-2024-003","2025-03-31","In Progress",120000,8,"2 Gaps: consent mgmt & data retention policy",today),
        ("ENG-006","VEN-002","APP-005","SAST","Source Code Review — Python ML pipeline & REST API","2024-12-01","2024-12-10","Completed",0,1,4,7,10,"RPT-2024-004","2025-02-28","In Progress",150000,9,"High: SQL injection in analytics query builder",today),
        ("ENG-007","VEN-003","APP-007","Red Team","K8s Cluster — Container escape, privilege escalation","2024-08-01","2024-08-21","Completed",1,3,7,5,2,"RPT-2024-005","2024-10-31","Closed",400000,8,"Critical: container escape via privileged pod. All closed.",today),
        ("ENG-008","VEN-005","APP-009","VA","Internal VA — SAP SCM integration servers","2025-01-15","2025-01-20","Completed",0,2,4,5,3,"RPT-2025-001","2025-03-31","Open",70000,7,"2 High: unpatched middleware",today),
        ("ENG-009","VEN-001","APP-010","Pentest","Full-stack Web Pentest — Customer Portal React/Node","2024-11-15","2024-11-30","Completed",0,3,6,9,4,"RPT-2024-006","2025-01-31","In Progress",220000,9,"High: IDOR, XSS, Missing auth on API",today),
        ("ENG-010","VEN-002","APP-010","DAST","DAST — Production-like environment","2025-03-01","2025-03-07","Planned",0,0,0,0,0,None,None,"Open",130000,None,"Scheduled Q1 2025",today),
        ("ENG-011","VEN-004",None,"Compliance Audit","Org-wide ISO 27001:2022 Gap Assessment","2025-02-01","2025-02-28","In Progress",0,0,0,0,0,None,None,"Open",500000,None,"Annual ISO 27001 surveillance audit",today),
        # ── ENG-012 : APP-014 MES Factory v1 (Mission Critical) ─────────────────
        ("ENG-012","VEN-001","APP-014","Pentest","OT/SCADA Interface Pentest — MES APIs & PLC Connectivity","2023-05-01","2023-05-21","Completed",1,3,7,10,2,"RPT-2023-002","2023-09-30","In Progress",300000,8,"Critical: Unauthenticated PLC access via legacy Modbus. Partial remediation — upgrade in progress.",today),
        # ── ENG-013/014 : APP-015 Treasury System (Mission Critical, PI_SPI) ────
        ("ENG-013","VEN-004","APP-015","Compliance Audit","PDPA + Internal Control Audit — Treasury PI/SPI Data Handling","2024-06-01","2024-06-15","Completed",0,1,3,4,5,"RPT-2024-007","2024-09-30","In Progress",180000,8,"High: Missing data masking for counterparty PII in treasury reports. Remediation ongoing.",today),
        ("ENG-014","VEN-001","APP-015","Pentest","Treasury Web Pentest — Bloomberg/Reuters API & Dealing UI","2024-08-01","2024-08-15","Completed",0,2,4,6,3,"RPT-2024-008","2024-11-30","Closed",280000,9,"All findings remediated. Next pentest recommended Aug 2025.",today),
        # ── ENG-015/016 : APP-016 Identity Platform (Mission Critical, PI_SPI) ──
        ("ENG-015","VEN-002","APP-016","SAST","SAST — Identity Provider code (OAuth, SAML, MFA modules)","2024-07-01","2024-07-21","Completed",0,2,6,8,12,"RPT-2024-009","2024-10-31","In Progress",200000,8,"High: PKCE bypass, JWT signing weakness. 1 High open — patch pending vendor release.",today),
        ("ENG-016","VEN-001","APP-016","Pentest","Pentest — SSO/MFA flows, SAML assertion, LDAP injection","2025-01-15","2025-01-29","Completed",0,1,3,5,4,"RPT-2025-002","2025-03-31","In Progress",260000,9,"1 High open: SAML response signature bypass on legacy SP configuration.",today),
        # ── ENG-017/018 : APP-020 API Gateway (Mission Critical) ─────────────────
        ("ENG-017","VEN-005","APP-020","VA","External VA — API Gateway Kong instances & management plane","2024-09-01","2024-09-07","Completed",0,2,5,7,3,"RPT-2024-010","2024-11-30","Closed",90000,8,"All findings remediated. Clean posture after hardening.",today),
        ("ENG-018","VEN-001","APP-020","Pentest","API Gateway Security Pentest — Auth bypass, rate limit, plugin security","2025-02-10","2025-02-24","In Progress",0,0,0,0,0,None,None,"Open",230000,None,"In progress — preliminary findings expected end of February.",today),
        # ── ENG-019/020 : APP-022 e-Commerce (Mission Critical, PI_SPI) ──────────
        ("ENG-019","VEN-001","APP-022","Pentest","e-Commerce Full Pentest — Payment flow, cart, auth, PCI scope","2024-10-01","2024-10-21","Completed",0,4,8,11,5,"RPT-2024-011","2025-01-15","In Progress",320000,9,"High: IDOR in order API, unencrypted card preview in dev-mode endpoint.",today),
        ("ENG-020","VEN-004","APP-022","Compliance Audit","PCI DSS v4 Readiness Assessment — SAQ D scope","2024-11-15","2024-11-30","Completed",0,2,4,5,8,"RPT-2024-012","2025-03-31","In Progress",250000,8,"2 High gaps: P2PE not fully implemented, annual pentest frequency non-compliant.",today),
        # ── ENG-021/022 : APP-027 Network IPAM (Mission Critical) ────────────────
        ("ENG-021","VEN-005","APP-027","VA","VA — IPAM/DNS infrastructure & Infoblox appliances","2023-11-01","2023-11-07","Completed",0,1,3,5,2,"RPT-2023-003","2024-02-28","Closed",70000,7,"All findings closed. Last VA >12 months ago — reschedule overdue.",today),
        ("ENG-022","VEN-005","APP-027","VA","VA Round 2 — IPAM v2 post-upgrade config & DNS security hardening","2025-01-20","2025-01-25","Completed",0,1,2,4,3,"RPT-2025-003","2025-03-31","In Progress",75000,8,"1 High: Default SNMP community string on 3 core nodes. Awaiting config change window.",today),
        # ── ENG-023 : APP-029 ServiceMesh Istio (Mission Critical) ───────────────
        ("ENG-023","VEN-001","APP-029","Pentest","Service Mesh Security — Istio mTLS bypass, sidecar escape, RBAC","2024-07-01","2024-07-15","Completed",1,2,5,6,3,"RPT-2024-013","2024-10-31","In Progress",290000,8,"Critical: mTLS policy gap on legacy service path allows unencrypted traffic. In remediation.",today),
        # ── ENG-024 : APP-032 Cyber SIEM (Mission Critical) ──────────────────────
        ("ENG-024","VEN-003","APP-032","Red Team","Red Team — SIEM Platform attack simulation & log manipulation","2024-05-01","2024-05-28","Completed",0,1,4,3,5,"RPT-2024-014","2024-08-31","Closed",380000,8,"High: Log injection via crafted HTTP headers. All findings closed.",today),
        # ── ENG-025 : APP-045 Monitoring Observability (Mission Critical) ─────────
        ("ENG-025","VEN-005","APP-045","VA","Infrastructure VA — Prometheus/Grafana/Alertmanager stack","2024-12-01","2024-12-07","Completed",0,2,3,5,4,"RPT-2024-015","2025-02-28","In Progress",80000,7,"2 High: Unauthenticated Prometheus metrics endpoint in DMZ, no mTLS on federation endpoint.",today),
        # ── ENG-026/027 : APP-048 Fraud Detection AI (Mission Critical, PI_SPI) ──
        ("ENG-026","VEN-002","APP-048","SAST","SAST — Fraud ML model serving code & feature pipeline","2024-09-15","2024-09-30","Completed",0,1,5,7,9,"RPT-2024-016","2024-12-31","Closed",170000,9,"All findings closed. Excellent code quality overall.",today),
        ("ENG-027","VEN-001","APP-048","Pentest","Fraud API Pentest — Model inference endpoint, admin panel & PI data","2025-02-15","2025-02-28","Planned",0,0,0,0,0,None,None,"Open",250000,None,"Scheduled Feb 2025 — covers PI/SPI data in fraud signals and model API surface.",today),
        # ── ENG-028 : APP-057 Splunk SIEM (Mission Critical) ─────────────────────
        ("ENG-028","VEN-003","APP-057","Red Team","Splunk Security Assessment — Log tampering, admin bypass, SPL injection","2023-09-01","2023-09-21","Completed",0,2,4,3,2,"RPT-2023-004","2023-12-31","Closed",350000,7,"All findings closed. Assessment >24 months ago — urgent rescheduling required.",today),
        # ── ENG-029/030 : APP-058 Mulesoft ESB (Mission Critical) ─────────────────
        ("ENG-029","VEN-005","APP-058","VA","ESB Infrastructure VA — Mulesoft CloudHub runtime & API Manager","2024-11-01","2024-11-07","Completed",0,2,4,6,3,"RPT-2024-017","2025-02-28","In Progress",90000,7,"High: Exposed management API without IP allowlist. Remediation in progress.",today),
        ("ENG-030","VEN-002","APP-058","SAST","SAST — Mulesoft custom connector & transformation scripts","2025-01-05","2025-01-15","Completed",0,1,3,5,6,"RPT-2025-004","2025-03-31","In Progress",140000,8,"1 High: Hardcoded credential in legacy SFTP connector script. Ticket raised.",today),
        # ── ENG-031 : APP-065 PingFederate IAM (Mission Critical) ────────────────
        ("ENG-031","VEN-001","APP-065","Pentest","PingFederate IAM Pentest — OIDC, OAuth2, SAML & admin console","2024-06-01","2024-06-15","Completed",0,3,6,8,4,"RPT-2024-018","2024-09-30","Closed",270000,9,"All findings remediated. Strong overall IAM posture.",today),
        # ── ENG-032/033 : APP-072 OpenShift Platform (Mission Critical) ──────────
        ("ENG-032","VEN-001","APP-072","Pentest","OpenShift Platform Pentest — Cluster API, RBAC, namespace isolation","2024-11-01","2024-11-21","Completed",1,3,7,9,3,"RPT-2024-019","2025-02-28","In Progress",340000,8,"Critical: Overprivileged service account allowing cross-namespace secret access. Patch in review.",today),
        ("ENG-033","VEN-006","APP-072","Cloud Security","Cloud Security Review — OpenShift on Azure — network policies, RBAC posture","2025-02-01","2025-02-14","In Progress",0,0,0,0,0,None,None,"Open",200000,None,"In progress — cloud config review combined with ENG-032 pentest findings remediation tracking.",today),
        # ── ENG-034/035 : APP-073 Guidewire Claims (Mission Critical, PI_SPI) ────
        ("ENG-034","VEN-004","APP-073","Compliance Audit","PDPA Data Mapping — Guidewire Claims PI/SPI data flows","2024-08-01","2024-08-15","Completed",0,1,3,4,7,"RPT-2024-020","2024-11-30","Closed",160000,8,"All PDPA gaps closed. Next audit due Aug 2025.",today),
        ("ENG-035","VEN-001","APP-073","Pentest","Guidewire Claims Portal Pentest — Agent portal & PI data access control","2025-01-01","2025-01-15","Completed",0,2,5,7,4,"RPT-2025-005","2025-03-31","In Progress",300000,9,"High: Broken access control allows cross-customer claim data view. Fix in staging.",today),
        # ── ENG-036/037 : APP-075 SWIFT Gateway (Mission Critical, PI_SPI) ───────
        ("ENG-036","VEN-001","APP-075","Pentest","SWIFT CSP Pentest — HSM, SWIFT messaging & operator workstations","2024-09-01","2024-09-21","Completed",0,2,4,5,2,"RPT-2024-021","2024-12-31","In Progress",380000,9,"High: Missing MFA on SWIFT operator account. Awaiting token deployment.",today),
        ("ENG-037","VEN-004","APP-075","Compliance Audit","SWIFT CSP v2024 Controls Compliance Assessment","2024-10-01","2024-10-15","Completed",0,1,2,3,4,"RPT-2024-022","2025-01-31","In Progress",220000,8,"1 High gap: Secure zone boundary control partial compliance. Architecture change planned.",today),
        # ── ENG-038/039 : APP-080 IBM MQ Messaging (Mission Critical) ────────────
        ("ENG-038","VEN-005","APP-080","VA","IBM MQ VA — Queue manager config, channel auth & TLS settings","2023-08-01","2023-08-07","Completed",0,2,3,5,2,"RPT-2023-005","2023-11-30","Closed",75000,7,"All findings closed. Assessment >24 months ago — critical coverage gap, reschedule urgent.",today),
        ("ENG-039","VEN-005","APP-080","VA","IBM MQ VA Round 2 — Post-upgrade config hardening verification","2025-01-10","2025-01-15","Completed",0,1,2,3,2,"RPT-2025-006","2025-03-31","Open",78000,8,"1 High: Unencrypted channel on legacy mainframe connection still active.",today),
        # ── ENG-040/041 : APP-082 Kafka Event Bus (Mission Critical) ─────────────
        ("ENG-040","VEN-002","APP-082","SAST","Kafka Consumer/Producer Code Review — Auth, encryption, schema validation","2024-10-01","2024-10-15","Completed",0,1,4,6,5,"RPT-2024-023","2025-01-15","Closed",150000,8,"All findings closed. 1 High was hardcoded SASL password in consumer — removed.",today),
        ("ENG-041","VEN-001","APP-082","Pentest","Kafka Security Pentest — ZooKeeper exposure, ACL bypass, topic auth","2025-02-01","2025-02-15","In Progress",0,0,0,0,0,None,None,"Open",240000,None,"In progress — ZooKeeper access control and topic ACL testing underway.",today),
        # ── ENG-042/043 : APP-086 COBOL Payroll (Mission Critical, PI_SPI) ───────
        ("ENG-042","VEN-004","APP-086","Compliance Audit","Payroll PI/SPI Compliance Audit — PDPA, data retention & COBOL I/O","2024-04-01","2024-04-15","Completed",0,2,5,6,4,"RPT-2024-024","2024-07-31","In Progress",200000,7,"2 High gaps: excessive data retention (>7yr), no PI masking in batch output logs.",today),
        ("ENG-043","VEN-001","APP-086","Pentest","COBOL Payroll Infrastructure Pentest — Mainframe, RACF, JCL security","2023-03-01","2023-03-21","Completed",1,3,6,8,3,"RPT-2023-006","2023-07-31","In Progress",320000,7,"Critical: Weak RACF password policy. Legacy constraints — partial remediation only. Reschedule planned.",today),
        # ── ENG-044/045 : APP-087 Cybersource Payment (Mission Critical, PI_SPI) ─
        ("ENG-044","VEN-001","APP-087","Pentest","Payment Gateway Pentest — PCI CDE scope, card data environment","2024-11-01","2024-11-15","Completed",0,1,3,5,3,"RPT-2024-025","2025-02-28","In Progress",300000,9,"High: TLS 1.0 still enabled on legacy processor connection. Change window scheduled.",today),
        ("ENG-045","VEN-004","APP-087","Compliance Audit","PCI DSS v4 Full Audit — Cybersource CDE scope","2024-12-01","2024-12-15","Completed",0,2,3,4,6,"RPT-2024-026","2025-04-30","In Progress",350000,8,"2 High gaps in SAQ D: monitoring continuity gap, key rotation policy non-compliant.",today),
        # ── ENG-046/047 : APP-088 SAS Risk Engine (Mission Critical, PI_SPI) ─────
        ("ENG-046","VEN-002","APP-088","SAST","SAS Risk Model Code Review — SAS macros, data inputs & output masking","2024-07-01","2024-07-15","Completed",0,1,4,5,7,"RPT-2024-027","2024-10-31","Closed",160000,8,"All findings closed. Good overall code quality.",today),
        ("ENG-047","VEN-004","APP-088","Compliance Audit","Risk Data Governance Audit — PDPA & BCBS 239 data lineage alignment","2025-01-15","2025-02-14","In Progress",0,0,0,0,0,None,None,"Open",250000,None,"Ongoing — BCBS 239 data lineage documentation and PI classification under review.",today),
        # ── ENG-048 : APP-090 Hashicorp Vault (Mission Critical) ─────────────────
        ("ENG-048","VEN-001","APP-090","Pentest","Vault PKI & Secret Store Pentest — Token auth, policy bypass & HA failover","2024-10-15","2024-10-29","Completed",0,2,5,6,3,"RPT-2024-028","2025-01-31","In Progress",260000,9,"High: Vault audit log disabled on DR cluster. Auth method bypass PoC submitted.",today),
        # ── ENG-049 : APP-006 Legacy ERP Oracle (High, PI_SPI) ───────────────────
        ("ENG-049","VEN-002","APP-006","SAST","Oracle EBS Custom Code Review — PL/SQL, Forms & Reports","2023-04-01","2023-04-21","Completed",0,3,7,9,4,"RPT-2023-007","2023-08-31","In Progress",200000,7,"3 High open: SQL injection in custom Forms modules. Legacy system — patching requires upgrade.",today),
        # ── ENG-050 : APP-008 Data Warehouse v2 (High) ───────────────────────────
        ("ENG-050","VEN-005","APP-008","VA","VA — Snowflake/Teradata DW infrastructure & BI tool connectivity","2024-06-01","2024-06-07","Completed",0,1,3,5,4,"RPT-2024-029","2024-09-30","Closed",85000,8,"All findings closed. Clean posture after hardening.",today),
        # ── ENG-051 : APP-021 Legacy Payroll RPG (High, PI_SPI) ──────────────────
        ("ENG-051","VEN-004","APP-021","Compliance Audit","PDPA Assessment — AS/400 RPG Payroll PI data handling & batch logs","2024-03-01","2024-03-15","Completed",0,2,4,5,3,"RPT-2024-030","2024-07-31","In Progress",150000,7,"2 High: no DSAR process, PI in batch logs retained >5yr without masking.",today),
        # ── ENG-052 : APP-023 Risk Mgmt System (High, PI_SPI) ────────────────────
        ("ENG-052","VEN-001","APP-023","Pentest","Risk Management Portal Pentest — Internal web app & PI data access","2024-05-01","2024-05-15","Completed",0,2,4,6,3,"RPT-2024-031","2024-08-31","Closed",220000,8,"All findings closed.",today),
        # ── ENG-053 : APP-017 ITSM ServiceNow (High) ─────────────────────────────
        ("ENG-053","VEN-005","APP-017","VA","ServiceNow VA — Integration Hub, MID server & REST API endpoints","2024-08-01","2024-08-07","Completed",0,1,2,4,3,"RPT-2024-032","2024-11-30","Closed",80000,8,"All findings closed.",today),
        # ── ENG-054 : APP-036 Compliance GRC (High, PI_SPI) ──────────────────────
        ("ENG-054","VEN-004","APP-036","Compliance Audit","GRC Tool PDPA + ISO 27001 Data Classification Audit","2024-09-01","2024-09-15","Completed",0,0,3,4,5,"RPT-2024-033","2024-12-31","Closed",130000,9,"All findings closed. Excellent compliance posture.",today),
        # ── ENG-055 : APP-098 GitLab DevSecOps (High) ────────────────────────────
        ("ENG-055","VEN-002","APP-098","SAST","GitLab CI/CD Pipeline SAST — Secret scanning, SBOM & IaC analysis","2025-01-20","2025-01-31","Completed",0,1,3,4,6,"RPT-2025-007","2025-03-31","In Progress",160000,8,"High: Hardcoded AWS key in 3 old pipeline scripts. Purge and key rotation in progress.",today),
        # ── ENG-056 : APP-043 CDP Customer Data (High, PI_SPI) ───────────────────
        ("ENG-056","VEN-004","APP-043","Compliance Audit","CDP PDPA Consent & PI Flow Audit — Segment & CDP pipelines","2024-12-15","2025-01-15","In Progress",0,0,0,0,0,None,None,"Open",200000,None,"In progress — consent management workflow mapping and gap analysis underway.",today),
        # ── ENG-057 : APP-007 K8s Platform — Cloud follow-up (Mission Critical) ──
        ("ENG-057","VEN-006","APP-007","Cloud Security","K8s Cloud Security Posture — Azure AKS config, admission control, RBAC","2025-02-15","2025-02-28","Planned",0,0,0,0,0,None,None,"Open",180000,None,"Planned — follow-up cloud review to ENG-007 red team findings on AKS node config.",today),
        # ── ENG-058 : APP-029 ServiceMesh — Cloud follow-up (Mission Critical) ───
        ("ENG-058","VEN-006","APP-029","Cloud Security","Cloud Security Review — Istio Ambient mesh migration security assessment","2025-03-01","2025-03-21","Planned",0,0,0,0,0,None,None,"Open",220000,None,"Planned Q1 2025 — covers ambient mesh migration risks and eBPF dataplane security.",today),
        # ── ENG-059 : APP-033 Finance Close (High, PI_SPI) ───────────────────────
        ("ENG-059","VEN-004","APP-033","Compliance Audit","Finance Close PI Audit — Journal entry masking & period-end controls","2024-01-15","2024-01-31","Completed",0,1,2,3,4,"RPT-2024-034","2024-04-30","In Progress",140000,8,"1 High open: period-end journal entry access not properly segregated by role.",today),
        # ── ENG-060 : APP-022 e-Commerce Mobile (Mission Critical, PI_SPI) ────────
        ("ENG-060","VEN-001","APP-022","Pentest","e-Commerce Mobile App Pentest — iOS, Android & React Native BFF API","2025-02-20","2025-03-07","Planned",0,0,0,0,0,None,None,"Open",280000,None,"Planned — covers iOS, Android apps and Backend-for-Frontend API layer.",today),
        # ── ENG-061 : APP-085 Genesys Cloud CX (High, PI_SPI) ────────────────────
        ("ENG-061","VEN-004","APP-085","Compliance Audit","Genesys PDPA Audit — Call recording, voice PI retention & consent","2024-10-15","2024-10-31","Completed",0,1,2,4,5,"RPT-2024-035","2025-01-31","In Progress",160000,8,"High: Voice recordings retained beyond PDPA-allowed period. Retention policy update in progress.",today),
        # ── ENG-062 : APP-099 Archer Risk Platform (High, PI_SPI) ────────────────
        ("ENG-062","VEN-004","APP-099","Compliance Audit","Archer GRC Platform Audit — Risk register PI & GRC data governance","2024-11-01","2024-11-15","Completed",0,0,2,3,4,"RPT-2024-036","2025-02-28","Closed",130000,9,"All findings closed.",today),
    ]
    conn.executemany("INSERT OR IGNORE INTO vendor_engagements VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", engagements)
    print(f"  Seeded {len(vendors)} vendors, {len(caps)} capabilities, {len(engagements)} engagements")

# ─── VENDOR MODELS ─────────────────────────────────────────────────────────────
class VendorWrite(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    tier: Optional[str] = None
    status: Optional[str] = None
    specializations: Optional[List[str]] = None
    certifications: Optional[List[str]] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    website: Optional[str] = None
    country: Optional[str] = None
    nda_signed: Optional[bool] = None
    insurance_amt: Optional[int] = None
    framework_end: Optional[str] = None
    risk_rating: Optional[str] = None
    notes: Optional[str] = None

class EngagementWrite(BaseModel):
    vendor_id: Optional[str] = None
    app_id: Optional[str] = None
    type: Optional[str] = None
    scope: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: Optional[str] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    info_count: Optional[int] = None
    report_ref: Optional[str] = None
    remediation_by: Optional[str] = None
    remediation_status: Optional[str] = None
    cost: Optional[int] = None
    score: Optional[int] = None
    notes: Optional[str] = None

def write_log(category: str, event_type: str, severity: str = "INFO",
              actor_ip: str = None, resource_id: str = None,
              before_state: dict = None, after_state: dict = None,
              risk_flags: list = None, extra: dict = None,
              duration_ms: int = None, status_code: int = None,
              message: str = None):
    """Non-blocking write to audit_log table."""
    try:
        with get_audit_db() as conn:
            conn.execute("""INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                str(uuid.uuid4()),
                datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                category, event_type, severity,
                actor_ip, resource_id,
                json.dumps(before_state, ensure_ascii=False) if before_state else None,
                json.dumps(after_state,  ensure_ascii=False) if after_state  else None,
                json.dumps(risk_flags,   ensure_ascii=False) if risk_flags   else None,
                json.dumps(extra,        ensure_ascii=False) if extra        else None,
                duration_ms, status_code, message
            ))
    except Exception as e:
        print(f"  write_log error: {e}")

def _diff_fields(before: dict, after: dict) -> dict:
    """Return only changed fields as {field: [old, new]}."""
    diff = {}
    for k in set(list(before.keys()) + list(after.keys())):
        v_old = before.get(k); v_new = after.get(k)
        if v_old != v_new:
            diff[k] = [v_old, v_new]
    return diff

def _detect_risks(before: dict, after: dict, body_dict: dict = None) -> list:
    """Detect high-risk changes and return list of flag strings."""
    flags = []
    # PI/SPI export or enable
    if after.get("pi_spi") and not (before or {}).get("pi_spi"):
        flags.append("PI_SPI_ENABLED")
    # DR policy change
    if "dr" in (body_dict or {}) and before and str(before.get("dr")) != str(after.get("dr")):
        flags.append("DR_POLICY_CHANGED")
    # Compliance change
    if "compliance" in (body_dict or {}) and before and before.get("compliance") != after.get("compliance"):
        flags.append("COMPLIANCE_CHANGED")
    # Criticality upgrade
    crit_order = {"Low":0, "Medium":1, "High":2, "Mission Critical":3}
    if before and crit_order.get(after.get("criticality",""),0) > crit_order.get(before.get("criticality",""),0):
        flags.append("CRITICALITY_UPGRADED")
    return flags

# ─── OPERATION LOG MIDDLEWARE ──────────────────────────────────────────────────
class OperationLogMiddleware(BaseHTTPMiddleware):
    SKIP_PREFIXES = ("/assets/", "/docs", "/openapi", "/redoc")

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        dur_ms = int((time.monotonic() - start) * 1000)

        path = request.url.path
        if not any(path.startswith(p) for p in self.SKIP_PREFIXES) and path.startswith("/api/"):
            sev = "ERROR" if response.status_code >= 500 else ("WARNING" if response.status_code >= 400 else "INFO")
            write_log(
                category="OPERATION",
                event_type=f"{request.method} {path}",
                severity=sev,
                actor_ip=request.client.host if request.client else None,
                duration_ms=dur_ms,
                status_code=response.status_code,
                message=f"{request.method} {path} → {response.status_code} ({dur_ms}ms)"
            )
        return response

# ─── DATABASE ──────────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

DDL = """
CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT, vendor TEXT, type TEXT DEFAULT 'Package',
    status TEXT DEFAULT 'Active', bcg TEXT DEFAULT 'Tolerate',
    health INTEGER DEFAULT 75, tech_debt INTEGER DEFAULT 25,
    age INTEGER DEFAULT 0, tco INTEGER DEFAULT 0, users INTEGER DEFAULT 0,
    criticality TEXT DEFAULT 'Medium', dr INTEGER DEFAULT 0, eol TEXT,
    pi_spi INTEGER DEFAULT 0, contract_end TEXT, integration INTEGER DEFAULT 0,
    stack TEXT DEFAULT '[]', capability TEXT, strategic INTEGER DEFAULT 70,
    persons INTEGER DEFAULT 1, src_avail INTEGER DEFAULT 1,
    service_hour TEXT DEFAULT 'Business Hours', maint_window TEXT,
    lang TEXT, os TEXT, db_platform TEXT, support TEXT DEFAULT 'Inhouse',
    owner TEXT, biz_owner TEXT, compliance TEXT DEFAULT '[]', stream TEXT, approach TEXT,
    assess_status TEXT DEFAULT 'Not Started', assess_date TEXT, wave INTEGER DEFAULT 3,
    ea_group TEXT, ea_category TEXT, ea_sub_category TEXT DEFAULT '-',
    decommissioned INTEGER DEFAULT 0, decomm_date TEXT, decomm_reason TEXT,
    last_updated TEXT
);
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

def init_db():
    with get_db() as conn:
        conn.executescript(DDL)
        # Migration: เพิ่ม column biz_owner สำหรับ DB เก่าที่สร้างไว้ก่อนหน้า
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(applications)").fetchall()}
        if "biz_owner" not in existing_cols:
            conn.execute("ALTER TABLE applications ADD COLUMN biz_owner TEXT")
            print("  Migration: added column biz_owner")
        if "compliance" not in existing_cols:
            conn.execute("ALTER TABLE applications ADD COLUMN compliance TEXT DEFAULT '[]'")
            print("  Migration: added column compliance")
        conn.execute("INSERT OR REPLACE INTO config VALUES ('app_version', ?)", (APP_VERSION,))
        if conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0] == 0:
            rows = _seed_apps()
            rows = _assign_biz_owner(rows)    # assign Business App Owner name ตาม domain
            rows = _assign_compliance(rows)   # random compliance จาก attributes ของแต่ละ app
            # ensure every seed dict has required keys for named binding
            rows = [{**r, "biz_owner": r.get("biz_owner"), "compliance": r.get("compliance", "[]")} for r in rows]
            conn.executemany("""
                INSERT OR IGNORE INTO applications VALUES (
                    :id,:name,:domain,:vendor,:type,:status,:bcg,
                    :health,:tech_debt,:age,:tco,:users,:criticality,
                    :dr,:eol,:pi_spi,:contract_end,:integration,:stack,
                    :capability,:strategic,:persons,:src_avail,:service_hour,
                    :maint_window,:lang,:os,:db_platform,:support,:owner,
                    :biz_owner,:compliance,:stream,:approach,:assess_status,:assess_date,:wave,
                    :ea_group,:ea_category,:ea_sub_category,
                    0,NULL,NULL,:last_updated
                )
            """, rows)
            print(f"  Seeded {len(rows)} applications")
    print(f"DB ready: {DB_PATH}")

# ─── MODELS ────────────────────────────────────────────────────────────────────
class AppWrite(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    vendor: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    bcg: Optional[str] = None
    health: Optional[int] = None
    tech_debt: Optional[int] = None
    age: Optional[int] = None
    tco: Optional[int] = None
    users: Optional[int] = None
    criticality: Optional[str] = None
    dr: Optional[bool] = None
    eol: Optional[str] = None
    pi_spi: Optional[bool] = None
    contract_end: Optional[str] = None
    integration: Optional[int] = None
    stack: Optional[List[str]] = None
    capability: Optional[str] = None
    strategic: Optional[int] = None
    persons: Optional[int] = None
    src_avail: Optional[bool] = None
    service_hour: Optional[str] = None
    maint_window: Optional[str] = None
    lang: Optional[str] = None
    os: Optional[str] = None
    db_platform: Optional[str] = None
    support: Optional[str] = None
    owner: Optional[str] = None
    biz_owner: Optional[str] = None
    compliance: Optional[List[str]] = None
    stream: Optional[str] = None
    approach: Optional[str] = None
    assess_status: Optional[str] = None
    assess_date: Optional[str] = None
    wave: Optional[int] = None
    ea_group: Optional[str] = None
    ea_category: Optional[str] = None
    ea_sub_category: Optional[str] = None

class DecommBody(BaseModel):
    decomm_date: str
    decomm_reason: Optional[str] = "ไม่ระบุ"

# ─── HELPERS ───────────────────────────────────────────────────────────────────
def row_to_dict(row) -> dict:
    d = dict(row)
    try:
        d["stack"] = json.loads(d.get("stack") or "[]")
    except (json.JSONDecodeError, ValueError):
        d["stack"] = []
    try:
        d["compliance"] = json.loads(d.get("compliance") or "[]")
    except (json.JSONDecodeError, ValueError):
        d["compliance"] = []
    for f in ("dr","pi_spi","src_avail","decommissioned"):
        if f in d: d[f] = bool(d[f])
    return d

def next_id(conn) -> str:
    # BUG-04: ใช้ numeric sort แทน lexicographic เพื่อรองรับ > 999 apps
    row = conn.execute(
        "SELECT id FROM applications ORDER BY CAST(SUBSTR(id, 5) AS INTEGER) DESC LIMIT 1"
    ).fetchone()
    try:
        return f"APP-{int((row['id'] if row else 'APP-000').split('-')[1]) + 1:03d}"
    except (ValueError, IndexError, TypeError):
        return "APP-001"

# ─── ROUTES ────────────────────────────────────────────────────────────────────
@app.get("/api/version")
def r_version(current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM config WHERE key='app_version'").fetchone()
    ver = row["value"] if row else APP_VERSION
    return {
        "version":      ver,
        "app_name":     APP_NAME,
        "subtitle":     APP_SUBTITLE,
        "title":        f"{APP_NAME} {ver}",
        "page_title":   f"{APP_NAME} EA Portfolio {ver}",
        "logo_sub":     f"{APP_SUBTITLE} {ver}",
    }

@app.get("/api/config")
def get_config(current_user: dict = Depends(_require_auth)):
    """Return full mpx-studio.config.json (re-read each time so hot-editable)."""
    return _load_config()

@app.get("/api/config/mpx2/badges")
def get_mpx2_badges(current_user: dict = Depends(_require_auth)):
    """Return MPX2 badge positions from config."""
    cfg = _load_config()
    return {"badges": cfg.get("mpx2", {}).get("badges", [])}

@app.get("/api/stats")
def r_stats(current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        q = lambda s: conn.execute(s).fetchone()[0]
        return {
            "total_apps":      q("SELECT COUNT(*)  FROM applications WHERE decommissioned=0"),
            "active_apps":     q("SELECT COUNT(*)  FROM applications WHERE status='Active' AND decommissioned=0"),
            "mission_critical":q("SELECT COUNT(*)  FROM applications WHERE criticality='Mission Critical' AND decommissioned=0"),
            "total_tco":       q("SELECT SUM(tco)  FROM applications WHERE decommissioned=0") or 0,
            "domains":         q("SELECT COUNT(DISTINCT domain) FROM applications WHERE decommissioned=0"),
            "avg_health":      round(q("SELECT AVG(health) FROM applications WHERE decommissioned=0") or 0, 1),
            "decommissioned":  q("SELECT COUNT(*) FROM applications WHERE decommissioned=1"),
        }

@app.get("/api/apps")
def r_list(status: Optional[str]=None, domain: Optional[str]=None,
           bcg: Optional[str]=None, ea_group: Optional[str]=None,
           search: Optional[str]=None, show_decomm: bool=False, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        sql, p = "SELECT * FROM applications WHERE 1=1", []
        if not show_decomm:                     sql += " AND decommissioned=0"
        if status:  sql += " AND status=?";     p.append(status)
        if domain:  sql += " AND domain=?";     p.append(domain)
        if bcg:     sql += " AND bcg=?";        p.append(bcg)
        if ea_group:sql += " AND ea_group=?";   p.append(ea_group)
        if search:
            sql += " AND (name LIKE ? OR vendor LIKE ? OR domain LIKE ? OR capability LIKE ?)"
            p.extend([f"%{search}%"]*4)
        return [row_to_dict(r) for r in conn.execute(sql + " ORDER BY id", p).fetchall()]

@app.get("/api/apps/{app_id}")
def r_get(app_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    if not row: raise HTTPException(404, f"App {app_id} not found")
    return row_to_dict(row)

@app.post("/api/apps", status_code=201)
def r_create(body: AppWrite, request: Request, current_user: dict = Depends(_require_auth)):
    if not (body.name or "").strip(): raise HTTPException(400, "name is required")
    with get_db() as conn:
        aid = next_id(conn)
        h, td = int(body.health or 75), int(body.tech_debt or (100 - int(body.health or 75)))
        conn.execute("""INSERT INTO applications VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,NULL,?)""", (
            aid, body.name, body.domain, body.vendor, body.type or "Package",
            body.status or "Active", body.bcg or "Tolerate", h, td,
            int(body.age or 0), int(body.tco or 0), int(body.users or 0),
            body.criticality or "Medium", int(body.dr or False), body.eol,
            int(body.pi_spi or False), body.contract_end, int(body.integration or 0),
            json.dumps(body.stack or []), body.capability, int(body.strategic or 70),
            int(body.persons or 1), int(body.src_avail if body.src_avail is not None else True),
            body.service_hour or "Business Hours", body.maint_window, body.lang,
            body.os, body.db_platform, body.support or "Inhouse",
            body.owner, body.biz_owner, json.dumps(body.compliance or []),
            body.stream, body.approach or "Upgrade",
            body.assess_status or "Not Started", body.assess_date, int(body.wave or 3),
            body.ea_group, body.ea_category, body.ea_sub_category or "-",
            datetime.now().strftime("%Y-%m-%d"),
        ))
    _dump = getattr(body, "model_dump", None) or getattr(body, "dict")
    after = _dump()
    risks = []
    if body.pi_spi: risks.append("PI_SPI_ENABLED")
    write_log(
        category="AUDIT", event_type="APP_CREATE", severity="INFO",
        actor_ip=request.client.host if request.client else None,
        resource_id=aid, after_state=after,
        risk_flags=risks if risks else None,
        message=f"Created app {aid}: {body.name}"
    )
    return {"id": aid, "message": "Created"}

@app.put("/api/apps/{app_id}")
def r_update(app_id: str, body: AppWrite, request: Request, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        # BUG-02: ป้องกันการแก้ไข app ที่ถูก decommission แล้ว
        if row["decommissioned"]: raise HTTPException(400, "Cannot update a decommissioned application")
        before = row_to_dict(row)
        c = dict(row)
        # BUG-13: body.dict() deprecated ใน Pydantic v2 → ใช้ model_dump() พร้อม fallback
        _dump = getattr(body, "model_dump", None) or getattr(body, "dict")
        body_dict = _dump()
        for k, v in body_dict.items():
            if v is not None: c[k] = v
        if body.stack is not None: c["stack"] = json.dumps(body.stack)
        if body.compliance is not None: c["compliance"] = json.dumps(body.compliance)
        h = int(c.get("health") or 75)
        conn.execute("""UPDATE applications SET
            name=?,domain=?,vendor=?,type=?,status=?,bcg=?,health=?,tech_debt=?,
            age=?,tco=?,users=?,criticality=?,dr=?,eol=?,pi_spi=?,contract_end=?,
            integration=?,stack=?,capability=?,strategic=?,persons=?,src_avail=?,
            service_hour=?,maint_window=?,lang=?,os=?,db_platform=?,support=?,
            owner=?,biz_owner=?,compliance=?,stream=?,approach=?,assess_status=?,assess_date=?,wave=?,
            ea_group=?,ea_category=?,ea_sub_category=?,last_updated=? WHERE id=?""", (
            c["name"],c.get("domain"),c.get("vendor"),c.get("type"),c.get("status"),c.get("bcg"),
            h, int(c.get("tech_debt") or 100-h), int(c.get("age") or 0),
            int(c.get("tco") or 0), int(c.get("users") or 0), c.get("criticality"),
            int(c.get("dr") or False), c.get("eol"), int(c.get("pi_spi") or False),
            c.get("contract_end"), int(c.get("integration") or 0),
            c["stack"] if isinstance(c.get("stack"), str) else json.dumps(c.get("stack") or []),
            c.get("capability"), int(c.get("strategic") or 70), int(c.get("persons") or 1),
            int(c.get("src_avail") if c.get("src_avail") is not None else True),
            c.get("service_hour"), c.get("maint_window"), c.get("lang"), c.get("os"),
            c.get("db_platform"), c.get("support"), c.get("owner"), c.get("biz_owner"),
            c["compliance"] if isinstance(c.get("compliance"), str) else json.dumps(c.get("compliance") or []),
            c.get("stream"), c.get("approach"), c.get("assess_status"), c.get("assess_date"),
            int(c.get("wave") or 3), c.get("ea_group"), c.get("ea_category"),
            c.get("ea_sub_category") or "-",
            datetime.now().strftime("%Y-%m-%d"), app_id,
        ))
    # Build after state and detect risks
    after = {**before, **{k: v for k, v in body_dict.items() if v is not None}}
    diff  = _diff_fields(before, after)
    risks = _detect_risks(before, after, body_dict)
    sev   = "WARNING" if risks else "INFO"
    write_log(
        category="AUDIT", event_type="APP_UPDATE", severity=sev,
        actor_ip=request.client.host if request.client else None,
        resource_id=app_id, before_state=diff if diff else None, after_state=after,
        risk_flags=risks if risks else None,
        message=f"Updated app {app_id} ({app_id}): {', '.join(diff.keys()) if diff else 'no change'}"
    )
    if risks:
        write_log(
            category="COMPLIANCE", event_type="RISK_DETECTED", severity="WARNING",
            actor_ip=request.client.host if request.client else None,
            resource_id=app_id, risk_flags=risks,
            message=f"Risk flags on update {app_id}: {risks}"
        )
    return {"id": app_id, "message": "Updated"}

@app.post("/api/apps/{app_id}/decommission")
def r_decommission(app_id: str, body: DecommBody, request: Request, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT id, decommissioned, name, criticality FROM applications WHERE id=?", (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        if row["decommissioned"]: raise HTTPException(400, "Already decommissioned")
        conn.execute("""UPDATE applications SET decommissioned=1, status='Decommissioned',
            decomm_date=?, decomm_reason=?, last_updated=? WHERE id=?""",
            (body.decomm_date, body.decomm_reason, datetime.now().strftime("%Y-%m-%d"), app_id))
    risks = ["MISSION_CRITICAL_DECOMMISSION"] if row["criticality"] == "Mission Critical" else []
    write_log(
        category="AUDIT", event_type="APP_DECOMMISSION",
        severity="WARNING" if risks else "INFO",
        actor_ip=request.client.host if request.client else None,
        resource_id=app_id,
        after_state={"decomm_date": body.decomm_date, "decomm_reason": body.decomm_reason},
        risk_flags=risks if risks else None,
        message=f"Decommissioned app {app_id} ({row['name']}) on {body.decomm_date}"
    )
    return {"id": app_id, "message": "Decommissioned"}

class RestoreBody(BaseModel):
    restore_reason: Optional[str] = "ยกเลิกการปลดระวาง"
    restore_status: Optional[str] = "Active"   # Active | Phase-out | To-retire

@app.post("/api/apps/{app_id}/restore")
def r_restore(app_id: str, body: RestoreBody, request: Request, current_user: dict = Depends(_require_auth)):
    """Undo / cancel a decommission — restore app back to active portfolio."""
    allowed_statuses = {"Active", "Phase-out", "To-retire", "Planned"}
    if body.restore_status not in allowed_statuses:
        raise HTTPException(400, f"restore_status must be one of: {', '.join(sorted(allowed_statuses))}")
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, decommissioned, name, criticality, decomm_date, decomm_reason FROM applications WHERE id=?",
            (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        if not row["decommissioned"]: raise HTTPException(400, "App is not decommissioned")
        conn.execute("""UPDATE applications
            SET decommissioned=0, status=?, decomm_date=NULL, decomm_reason=NULL, last_updated=?
            WHERE id=?""",
            (body.restore_status, datetime.now().strftime("%Y-%m-%d"), app_id))
    write_log(
        category="AUDIT", event_type="APP_RESTORE",
        severity="INFO",
        actor_ip=request.client.host if request.client else None,
        resource_id=app_id,
        before_state={"decommissioned": True, "decomm_date": row["decomm_date"], "decomm_reason": row["decomm_reason"]},
        after_state={"decommissioned": False, "status": body.restore_status},
        message=f"Restored app {app_id} ({row['name']}) — reason: {body.restore_reason}"
    )
    return {"id": app_id, "status": body.restore_status, "message": "Restored"}

# ─── EXPORT ────────────────────────────────────────────────────────────────────
@app.get("/api/export")
def r_export(include_decomm: bool = False, request: Request = None, current_user: dict = Depends(_require_auth)):
    """Export all apps as JSON — frontend converts to XLSX."""
    with get_db() as conn:
        sql = "SELECT * FROM applications"
        if not include_decomm:
            sql += " WHERE decommissioned=0"
        sql += " ORDER BY id"
        rows = conn.execute(sql).fetchall()
    result = [row_to_dict(r) for r in rows]
    # Count PI/SPI apps in export
    pi_spi_count = sum(1 for r in result if r.get("pi_spi"))
    risks = ["PI_SPI_DATA_EXPORT"] if pi_spi_count > 0 else []
    write_log(
        category="AUDIT", event_type="DATA_EXPORT",
        severity="WARNING" if risks else "INFO",
        actor_ip=(request.client.host if request and request.client else None),
        risk_flags=risks if risks else None,
        extra={"app_count": len(result), "include_decomm": include_decomm, "pi_spi_count": pi_spi_count},
        message=f"Exported {len(result)} apps (pi_spi={pi_spi_count})"
    )
    return result

# ─── IMPORT ────────────────────────────────────────────────────────────────────
class ImportApp(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    domain: Optional[str] = None
    vendor: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    bcg: Optional[str] = None
    health: Optional[int] = None
    tech_debt: Optional[int] = None
    age: Optional[int] = None
    tco: Optional[int] = None
    users: Optional[int] = None
    criticality: Optional[str] = None
    dr: Optional[bool] = None
    eol: Optional[str] = None
    pi_spi: Optional[bool] = None
    contract_end: Optional[str] = None
    integration: Optional[int] = None
    stack: Optional[List[str]] = None
    capability: Optional[str] = None
    strategic: Optional[int] = None
    persons: Optional[int] = None
    src_avail: Optional[bool] = None
    service_hour: Optional[str] = None
    maint_window: Optional[str] = None
    lang: Optional[str] = None
    os: Optional[str] = None
    db_platform: Optional[str] = None
    support: Optional[str] = None
    owner: Optional[str] = None
    biz_owner: Optional[str] = None
    compliance: Optional[List[str]] = None
    stream: Optional[str] = None
    approach: Optional[str] = None
    assess_status: Optional[str] = None
    assess_date: Optional[str] = None
    wave: Optional[int] = None
    ea_group: Optional[str] = None
    ea_category: Optional[str] = None
    ea_sub_category: Optional[str] = None

class ImportBody(BaseModel):
    apps: List[ImportApp]
    mode: str = "upsert"   # "upsert" | "replace"

@app.post("/api/import")
def r_import(body: ImportBody, request: Request = None, current_user: dict = Depends(_require_auth)):
    """
    Import apps from frontend (parsed from XLSX).
    mode=upsert : insert new + update existing (default)
    mode=replace: clear all data first, then insert all
    """
    # BUG-10: validate mode ก่อน
    if body.mode not in ("upsert", "replace"):
        raise HTTPException(400, f"Invalid mode '{body.mode}'. Use 'upsert' or 'replace'")

    if not body.apps:
        raise HTTPException(400, "No apps provided")

    # BUG-05: ตรวจ valid records ก่อน ถ้า mode=replace จะไม่ลบข้อมูลเมื่อไม่มี record ที่ valid
    valid_apps = [a for a in body.apps if a.id and (a.name or "").strip()]
    if body.mode == "replace" and not valid_apps:
        raise HTTPException(400, "No valid apps to import (all records missing id or name) — replace aborted to protect existing data")

    added = updated = errors = int(len(body.apps) - len(valid_apps))
    errors = len(body.apps) - len(valid_apps)
    added = updated = 0
    today = datetime.now().strftime("%Y-%m-%d")

    with get_db() as conn:
        # BUG-05: ลบหลังจากตรวจว่ามี valid records แน่แล้ว
        if body.mode == "replace":
            conn.execute("DELETE FROM applications")

        for a in valid_apps:
            try:
                existing = conn.execute(
                    "SELECT id FROM applications WHERE id=?", (a.id,)
                ).fetchone()

                h  = int(a.health or 75)
                td = int(a.tech_debt if a.tech_debt is not None else 100 - h)

                if existing:
                    # UPDATE
                    conn.execute("""UPDATE applications SET
                        name=?,domain=?,vendor=?,type=?,status=?,bcg=?,health=?,tech_debt=?,
                        age=?,tco=?,users=?,criticality=?,dr=?,eol=?,pi_spi=?,contract_end=?,
                        integration=?,stack=?,capability=?,strategic=?,persons=?,src_avail=?,
                        service_hour=?,maint_window=?,lang=?,os=?,db_platform=?,support=?,
                        owner=?,biz_owner=?,compliance=?,stream=?,approach=?,assess_status=?,assess_date=?,wave=?,
                        ea_group=?,ea_category=?,ea_sub_category=?,last_updated=? WHERE id=?""",
                        (a.name,a.domain,a.vendor,a.type or "Package",a.status or "Active",
                         a.bcg or "Tolerate",h,td,int(a.age or 0),int(a.tco or 0),int(a.users or 0),
                         a.criticality or "Medium",int(a.dr or False),a.eol,
                         int(a.pi_spi or False),a.contract_end,int(a.integration or 0),
                         json.dumps(a.stack or []),a.capability,int(a.strategic or 70),
                         int(a.persons or 1),int(a.src_avail if a.src_avail is not None else True),
                         a.service_hour,a.maint_window,a.lang,a.os,a.db_platform,
                         a.support,a.owner,a.biz_owner,json.dumps(a.compliance or []),
                         a.stream,a.approach,a.assess_status,a.assess_date,
                         int(a.wave or 3),a.ea_group,a.ea_category,a.ea_sub_category or "-",
                         today, a.id))
                    updated += 1
                else:
                    # INSERT
                    conn.execute("""INSERT INTO applications VALUES (
                        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,NULL,?)""",
                        (a.id,a.name,a.domain,a.vendor,a.type or "Package",a.status or "Active",
                         a.bcg or "Tolerate",h,td,int(a.age or 0),int(a.tco or 0),int(a.users or 0),
                         a.criticality or "Medium",int(a.dr or False),a.eol,
                         int(a.pi_spi or False),a.contract_end,int(a.integration or 0),
                         json.dumps(a.stack or []),a.capability,int(a.strategic or 70),
                         int(a.persons or 1),int(a.src_avail if a.src_avail is not None else True),
                         a.service_hour,a.maint_window,a.lang,a.os,a.db_platform,
                         a.support,a.owner,a.biz_owner,json.dumps(a.compliance or []),
                         a.stream,a.approach,a.assess_status,a.assess_date,
                         int(a.wave or 3),a.ea_group,a.ea_category,a.ea_sub_category or "-",today))
                    added += 1
            except Exception as ex:
                errors += 1
                print(f"  Import error {a.id}: {ex}")

    write_log(
        category="AUDIT", event_type="DATA_IMPORT", severity="INFO",
        actor_ip=(request.client.host if request and request.client else None),
        extra={"mode": body.mode, "added": added, "updated": updated, "errors": errors},
        message=f"Import {body.mode}: added={added} updated={updated} errors={errors}"
    )
    return {"added": added, "updated": updated, "errors": errors,
            "total": added + updated, "message": f"Import complete"}


@app.get("/api/ea/structure")
def r_ea_structure(current_user: dict = Depends(_require_auth)):
    groups = [
        {"group":"1. Direction","color":"#7b61ff","categories":["1.1 BOD","1.2 Vision, Mission, Strategies","1.3 Goals, Objectives","1.4 Governance Body","1.5 Standard & Policies","1.6 Business Process & Services"]},
        {"group":"2. Services","color":"#00e5ff","categories":["2.1 Customer","2.2 Partner","2.3 Service","2.4 Employee","2.6 Channel","2.7 Portal & Gateway"]},
        {"group":"3. Core Products","color":"#00d68f","categories":["3.1 Organization","3.2 Corporate & Core System","3.3 Back Office & Support System"]},
        {"group":"4. Support","color":"#ff9f43","categories":["4.1 Training & Communication","4.2 Corporate Information","4.3 Corporate Application & Information Technology"]},
        {"group":"5. Governance","color":"#ff4757","categories":["5.1 Corporate Security & Policy","5.2 Risk & Internal Control","5.3 Law & Compliance"]},
    ]
    with get_db() as conn:
        for g in groups:
            g["counts"] = {c: conn.execute(
                "SELECT COUNT(*) FROM applications WHERE ea_group=? AND ea_category=? AND decommissioned=0",
                (g["group"], c)).fetchone()[0] for c in g["categories"]}
    return groups

# ─── VENDOR ENDPOINTS ──────────────────────────────────────────────────────────
def _next_vendor_id(conn) -> str:
    row = conn.execute("SELECT vendor_id FROM vendors ORDER BY vendor_id DESC LIMIT 1").fetchone()
    try: return f"VEN-{int((row['vendor_id'] if row else 'VEN-000').split('-')[1])+1:03d}"
    except: return "VEN-001"

def _next_eng_id(conn) -> str:
    row = conn.execute("SELECT engagement_id FROM vendor_engagements ORDER BY engagement_id DESC LIMIT 1").fetchone()
    try: return f"ENG-{int((row['engagement_id'] if row else 'ENG-000').split('-')[1])+1:03d}"
    except: return "ENG-001"

@app.get("/api/vendors")
def r_vendors(tier: Optional[str]=None, type: Optional[str]=None,
              status: Optional[str]=None, search: Optional[str]=None, current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        sql, p = "SELECT * FROM vendors WHERE 1=1", []
        if tier:   sql += " AND tier=?";   p.append(tier)
        if type:   sql += " AND type=?";   p.append(type)
        if status: sql += " AND status=?"; p.append(status)
        if search:
            sql += " AND (name LIKE ? OR type LIKE ? OR contact_name LIKE ?)"
            p.extend([f"%{search}%"]*3)
        rows = conn.execute(sql+" ORDER BY tier,name", p).fetchall()
        # attach capabilities count and last engagement date per vendor
        result = []
        for r in rows:
            d = _vrow(r)
            d["cap_count"] = conn.execute("SELECT COUNT(*) FROM vendor_capabilities WHERE vendor_id=?",(d["vendor_id"],)).fetchone()[0]
            d["eng_count"]  = conn.execute("SELECT COUNT(*) FROM vendor_engagements WHERE vendor_id=?",(d["vendor_id"],)).fetchone()[0]
            last = conn.execute("SELECT MAX(end_date) FROM vendor_engagements WHERE vendor_id=? AND status='Completed'",(d["vendor_id"],)).fetchone()[0]
            d["last_engagement"] = last
            result.append(d)
    return result

@app.get("/api/vendors/stats")
def r_vendors_stats(current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        q = lambda s,*a: conn.execute(s,a).fetchone()[0]
        open_crit = conn.execute(
            "SELECT SUM(critical) FROM vendor_engagements WHERE remediation_status!='Closed'"
        ).fetchone()[0] or 0
        open_high = conn.execute(
            "SELECT SUM(high) FROM vendor_engagements WHERE remediation_status!='Closed'"
        ).fetchone()[0] or 0
        cost_ytd  = conn.execute(
            "SELECT SUM(cost) FROM vendor_engagements WHERE start_date>=?",
            (f"{datetime.now().year}-01-01",)
        ).fetchone()[0] or 0
        return {
            "total_vendors":   q("SELECT COUNT(*) FROM vendors"),
            "preferred":       q("SELECT COUNT(*) FROM vendors WHERE tier='Preferred'"),
            "approved":        q("SELECT COUNT(*) FROM vendors WHERE tier='Approved'"),
            "total_eng":       q("SELECT COUNT(*) FROM vendor_engagements"),
            "in_progress":     q("SELECT COUNT(*) FROM vendor_engagements WHERE status='In Progress'"),
            "planned":         q("SELECT COUNT(*) FROM vendor_engagements WHERE status='Planned'"),
            "open_critical":   int(open_crit),
            "open_high":       int(open_high),
            "cost_ytd":        int(cost_ytd),
            "avg_score":       round(conn.execute("SELECT AVG(score) FROM vendor_engagements WHERE score IS NOT NULL").fetchone()[0] or 0, 1),
        }

@app.get("/api/vendors/{vendor_id}")
def r_vendor_get(vendor_id: str, current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        row = conn.execute("SELECT * FROM vendors WHERE vendor_id=?", (vendor_id,)).fetchone()
        if not row: raise HTTPException(404, f"Vendor {vendor_id} not found")
        d = _vrow(row)
        d["capabilities"] = [dict(r) for r in conn.execute(
            "SELECT * FROM vendor_capabilities WHERE vendor_id=? ORDER BY proficiency DESC", (vendor_id,)).fetchall()]
        d["engagements"]  = [_erow(r) for r in conn.execute(
            "SELECT * FROM vendor_engagements WHERE vendor_id=? ORDER BY start_date DESC", (vendor_id,)).fetchall()]
    return d

@app.post("/api/vendors", status_code=201)
def r_vendor_create(body: VendorWrite, current_user: dict = Depends(_require_auth)):
    if not (body.name or "").strip(): raise HTTPException(400, "name is required")
    today = datetime.now().strftime("%Y-%m-%d")
    with get_vendor_db() as conn:
        vid = _next_vendor_id(conn)
        conn.execute("""INSERT INTO vendors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            vid, body.name, body.type, body.tier or "Registered", body.status or "Active",
            json.dumps(body.specializations or []), json.dumps(body.certifications or []),
            body.contact_name, body.contact_email, body.website,
            body.country or "Thailand", int(body.nda_signed or False),
            body.insurance_amt or 0, body.framework_end, body.risk_rating or "Medium",
            0, body.notes, today, today))
    return {"vendor_id": vid, "message": "Created"}

@app.put("/api/vendors/{vendor_id}")
def r_vendor_update(vendor_id: str, body: VendorWrite, current_user: dict = Depends(_require_auth)):
    today = datetime.now().strftime("%Y-%m-%d")
    with get_vendor_db() as conn:
        row = conn.execute("SELECT * FROM vendors WHERE vendor_id=?", (vendor_id,)).fetchone()
        if not row: raise HTTPException(404, f"Vendor {vendor_id} not found")
        c = _vrow(row)
        _dump = getattr(body, "model_dump", None) or getattr(body, "dict")
        for k, v in _dump().items():
            if v is not None: c[k] = v
        conn.execute("""UPDATE vendors SET name=?,type=?,tier=?,status=?,specializations=?,certifications=?,
            contact_name=?,contact_email=?,website=?,country=?,nda_signed=?,insurance_amt=?,
            framework_end=?,risk_rating=?,notes=?,updated_at=? WHERE vendor_id=?""", (
            c["name"], c.get("type"), c.get("tier","Registered"), c.get("status","Active"),
            json.dumps(c.get("specializations") or []), json.dumps(c.get("certifications") or []),
            c.get("contact_name"), c.get("contact_email"), c.get("website"),
            c.get("country","Thailand"), int(c.get("nda_signed") or False),
            c.get("insurance_amt",0), c.get("framework_end"), c.get("risk_rating","Medium"),
            c.get("notes"), today, vendor_id))
    return {"vendor_id": vendor_id, "message": "Updated"}

@app.get("/api/engagements")
def r_engagements(vendor_id: Optional[str]=None, app_id: Optional[str]=None,
                  type: Optional[str]=None, status: Optional[str]=None,
                  remediation_status: Optional[str]=None, current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        sql, p = "SELECT e.*, v.name as vendor_name FROM vendor_engagements e JOIN vendors v ON e.vendor_id=v.vendor_id WHERE 1=1", []
        if vendor_id: sql += " AND e.vendor_id=?"; p.append(vendor_id)
        if app_id:    sql += " AND e.app_id=?";    p.append(app_id)
        if type:      sql += " AND e.type=?";       p.append(type)
        if status:    sql += " AND e.status=?";     p.append(status)
        if remediation_status: sql += " AND e.remediation_status=?"; p.append(remediation_status)
        rows = conn.execute(sql+" ORDER BY e.start_date DESC", p).fetchall()
    return [_erow(r) for r in rows]

@app.get("/api/apps/{app_id}/engagements")
def r_app_engagements(app_id: str, current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        rows = conn.execute("""SELECT e.*, v.name as vendor_name, v.tier as vendor_tier
            FROM vendor_engagements e JOIN vendors v ON e.vendor_id=v.vendor_id
            WHERE e.app_id=? ORDER BY e.start_date DESC""", (app_id,)).fetchall()
    return [_erow(r) for r in rows]

@app.post("/api/engagements", status_code=201)
def r_engagement_create(body: EngagementWrite, current_user: dict = Depends(_require_auth)):
    if not body.vendor_id: raise HTTPException(400, "vendor_id is required")
    if not body.type:       raise HTTPException(400, "type is required")
    today = datetime.now().strftime("%Y-%m-%d")
    with get_vendor_db() as conn:
        eid = _next_eng_id(conn)
        conn.execute("""INSERT INTO vendor_engagements VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            eid, body.vendor_id, body.app_id, body.type, body.scope,
            body.start_date, body.end_date, body.status or "Planned",
            body.critical or 0, body.high or 0, body.medium or 0, body.low or 0, body.info_count or 0,
            body.report_ref, body.remediation_by, body.remediation_status or "Open",
            body.cost or 0, body.score, body.notes, today))
        # update vendor avg_score
        conn.execute("""UPDATE vendors SET avg_score=(
            SELECT ROUND(AVG(score),1) FROM vendor_engagements
            WHERE vendor_id=? AND score IS NOT NULL), updated_at=? WHERE vendor_id=?""",
            (body.vendor_id, today, body.vendor_id))
    return {"engagement_id": eid, "message": "Created"}

@app.put("/api/engagements/{engagement_id}")
def r_engagement_update(engagement_id: str, body: EngagementWrite, current_user: dict = Depends(_require_auth)):
    today = datetime.now().strftime("%Y-%m-%d")
    with get_vendor_db() as conn:
        row = conn.execute("SELECT * FROM vendor_engagements WHERE engagement_id=?", (engagement_id,)).fetchone()
        if not row: raise HTTPException(404, f"Engagement {engagement_id} not found")
        c = _erow(row)
        _dump = getattr(body, "model_dump", None) or getattr(body, "dict")
        for k, v in _dump().items():
            if v is not None: c[k] = v
        conn.execute("""UPDATE vendor_engagements SET
            vendor_id=?,app_id=?,type=?,scope=?,start_date=?,end_date=?,status=?,
            critical=?,high=?,medium=?,low=?,info_count=?,report_ref=?,
            remediation_by=?,remediation_status=?,cost=?,score=?,notes=?
            WHERE engagement_id=?""", (
            c["vendor_id"],c.get("app_id"),c.get("type"),c.get("scope"),
            c.get("start_date"),c.get("end_date"),c.get("status","Planned"),
            c.get("critical",0),c.get("high",0),c.get("medium",0),c.get("low",0),c.get("info_count",0),
            c.get("report_ref"),c.get("remediation_by"),c.get("remediation_status","Open"),
            c.get("cost",0),c.get("score"),c.get("notes"),engagement_id))
        # refresh avg_score
        conn.execute("""UPDATE vendors SET avg_score=(
            SELECT ROUND(AVG(score),1) FROM vendor_engagements
            WHERE vendor_id=? AND score IS NOT NULL), updated_at=? WHERE vendor_id=?""",
            (c["vendor_id"], today, c["vendor_id"]))
    return {"engagement_id": engagement_id, "message": "Updated"}

# ─── LOG ENDPOINTS ─────────────────────────────────────────────────────────────
@app.get("/api/logs")
def r_logs(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    current_user: dict = Depends(_require_auth)):
    """Read audit logs — read-only endpoint for the Logs viewer."""
    with get_audit_db() as conn:
        sql  = "SELECT * FROM audit_log WHERE 1=1"
        args: list = []
        if category:    sql += " AND category=?";    args.append(category)
        if severity:    sql += " AND severity=?";    args.append(severity)
        if event_type:  sql += " AND event_type LIKE ?"; args.append(f"%{event_type}%")
        if resource_id: sql += " AND resource_id=?"; args.append(resource_id)
        if from_ts:     sql += " AND ts>=?";         args.append(from_ts)
        if to_ts:       sql += " AND ts<=?";         args.append(to_ts)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        args.extend([min(limit, 1000), offset])
        rows = conn.execute(sql, args).fetchall()
        cnt_sql  = "SELECT COUNT(*) FROM audit_log WHERE 1=1"
        cnt_args: list = []
        if category: cnt_sql += " AND category=?"; cnt_args.append(category)
        if severity: cnt_sql += " AND severity=?"; cnt_args.append(severity)
        total_row = conn.execute(cnt_sql, cnt_args).fetchone()
    result = []
    for r in rows:
        d = dict(r)
        for f in ("before_state", "after_state", "risk_flags", "extra"):
            try:    d[f] = json.loads(d[f]) if d.get(f) else None
            except: d[f] = d.get(f)
        result.append(d)
    return {"logs": result, "total": total_row[0], "limit": limit, "offset": offset}

@app.get("/api/logs/stats")
def r_logs_stats(current_user: dict = Depends(_require_auth)):
    """Aggregate stats for log dashboard."""
    with get_audit_db() as conn:
        def q(sql, *args): return conn.execute(sql, args).fetchone()[0]
        today = datetime.now().strftime("%Y-%m-%d")
        return {
            "total":          q("SELECT COUNT(*) FROM audit_log"),
            "audit":          q("SELECT COUNT(*) FROM audit_log WHERE category='AUDIT'"),
            "compliance":     q("SELECT COUNT(*) FROM audit_log WHERE category='COMPLIANCE'"),
            "operation":      q("SELECT COUNT(*) FROM audit_log WHERE category='OPERATION'"),
            "errors_today":   q("SELECT COUNT(*) FROM audit_log WHERE severity='ERROR' AND ts>=?", today),
            "warnings_today": q("SELECT COUNT(*) FROM audit_log WHERE severity='WARNING' AND ts>=?", today),
            "pi_spi_exports": q("SELECT COUNT(*) FROM audit_log WHERE risk_flags LIKE '%PI_SPI_DATA_EXPORT%'"),
            "risk_events":    q("SELECT COUNT(*) FROM audit_log WHERE risk_flags IS NOT NULL AND risk_flags != 'null'"),
        }

class LogQueryBody(BaseModel):
    sql: str = ""

@app.post("/api/logs/query")
def r_logs_query(body: LogQueryBody, current_user: dict = Depends(_require_auth)):
    """Execute a predefined audit SQL query (read-only SELECT only)."""
    sql = (body.sql or "").strip()
    if not sql:
        raise HTTPException(400, "sql is required")
    # Safety: only allow SELECT
    if not sql.upper().lstrip().startswith("SELECT"):
        raise HTTPException(400, "Only SELECT queries are allowed")
    # Block dangerous keywords
    blocked = ["DROP","DELETE","UPDATE","INSERT","ALTER","CREATE","ATTACH","DETACH","PRAGMA"]
    for kw in blocked:
        if kw in sql.upper():
            raise HTTPException(400, f"Keyword '{kw}' is not allowed in queries")
    try:
        with get_audit_db() as conn:
            conn.execute("PRAGMA query_only = ON")
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchmany(500)]
        return {"columns": cols, "rows": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(400, f"Query error: {e}")


# ─── AUTH ENDPOINTS ────────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def r_login(body: LoginBody, request: Request):
    if not _AUTH_ENABLED:
        return {"token": _create_jwt({"sub": "anonymous", "roles": ["admin"], "menus": ["*"]}),
                "user": {"username": "anonymous", "display_name": "Anonymous", "roles": ["admin"], "menus": ["*"]}}
    user = _get_user_dict(body.username)
    if not user or not _verify_password(body.password, user.get("hashed_password", "")):
        write_log(category="AUDIT", event_type="LOGIN_FAIL", severity="WARN",
                  actor_ip=request.client.host if request.client else "-",
                  message=f"Login failed for username: {body.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token_payload = {
        "sub":          user["username"],
        "display_name": user.get("display_name", user["username"]),
        "email":        user.get("email", ""),
        "roles":        user.get("roles", ["viewer"]),
        "menus":        user.get("menus", []),
    }
    token = _create_jwt(token_payload)
    write_log(category="AUDIT", event_type="LOGIN_SUCCESS", severity="INFO",
              actor_ip=request.client.host if request.client else "-",
              resource_id=user["username"],
              message=f"Login success: {user.get('display_name', user['username'])}")
    return {
        "token": token,
        "expire_minutes": _UCFG.get("token_expire_minutes", 480),
        "user": {"username": user["username"], **{k: v for k, v in token_payload.items() if k != "sub"}}
    }

@app.get("/api/auth/me")
def r_me(current_user: dict = Depends(_require_auth)):
    return current_user

@app.post("/api/auth/logout")
def r_logout(current_user: dict = Depends(_require_auth)):
    # JWT is stateless — client drops the token; log the event
    write_log(category="AUDIT", event_type="LOGOUT", severity="INFO",
              resource_id=current_user.get("sub"),
              message=f"Logout: {current_user.get('display_name', current_user.get('sub'))}")
    return {"message": "Logged out"}


@app.get("/api/auth/users")
def r_list_users(current_user: dict = Depends(_require_auth)):
    """List all users (admin only) — passwords are never returned."""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")
    safe_users = []
    for u in _UCFG.get("users", []):
        safe_users.append({
            "username":     u.get("username"),
            "display_name": u.get("display_name", ""),
            "email":        u.get("email", ""),
            "active":       u.get("active", True),
            "roles":        u.get("roles", []),
            "menus":        u.get("menus", []),
        })
    return {
        "users": safe_users,
        "token_expire_minutes": _UCFG.get("token_expire_minutes", 480),
        "auth_enabled": _AUTH_ENABLED,
    }


# ─── USER MANAGEMENT ENDPOINTS ────────────────────────────────────────────────

class UpdateUserBody(BaseModel):
    menus:        Optional[List[str]] = None
    roles:        Optional[List[str]] = None
    active:       Optional[bool]      = None
    display_name: Optional[str]       = None
    email:        Optional[str]       = None

VALID_MENUS = {"*","dashboard","inventory","architecture","planning",
               "analytics","vendor","asset","ops","audit","config"}
VALID_ROLES = {"admin","editor","viewer","vendor"}

@app.put("/api/auth/users/{username}")
def r_update_user(username: str, body: UpdateUserBody,
                  current_user: dict = Depends(_require_auth)):
    """Update user menus/roles/status (admin only)."""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")
    if username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Cannot edit your own account")

    # Reload config fresh from disk each time so concurrent edits are safe
    if not os.path.exists(_USERS_CONFIG_PATH):
        raise HTTPException(status_code=503, detail="users.config.json not found")
    with open(_USERS_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    user_rec = next((u for u in cfg.get("users", []) if u["username"] == username), None)
    if not user_rec:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

    changed = {}
    if body.menus is not None:
        bad = [m for m in body.menus if m not in VALID_MENUS]
        if bad:
            raise HTTPException(status_code=400, detail=f"Invalid menu keys: {bad}")
        user_rec["menus"] = body.menus
        changed["menus"] = body.menus
    if body.roles is not None:
        bad = [r for r in body.roles if r not in VALID_ROLES]
        if bad:
            raise HTTPException(status_code=400, detail=f"Invalid roles: {bad}")
        user_rec["roles"] = body.roles
        changed["roles"] = body.roles
    if body.active is not None:
        user_rec["active"] = body.active
        changed["active"] = body.active
    if body.display_name is not None:
        user_rec["display_name"] = body.display_name
        changed["display_name"] = body.display_name
    if body.email is not None:
        user_rec["email"] = body.email
        changed["email"] = body.email

    # Write back
    with open(_USERS_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    # Also update in-memory cache
    _UCFG["users"] = cfg["users"]

    write_log(category="AUDIT", event_type="USER_UPDATE", severity="INFO",
              resource_id=username,
              after_state=json.dumps(changed, ensure_ascii=False),
              message=f"User '{username}' updated by {current_user.get('sub','?')}: {list(changed.keys())}")

    return {"username": username, "updated": changed, "message": "User updated"}

# ─── STATIC + CATCH-ALL ────────────────────────────────────────────────────────
if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

@app.get("/{full_path:path}", include_in_schema=False)
def catch_all(full_path: str = ""):
    if full_path.startswith("api/"): raise HTTPException(404)
    idx = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(idx) if os.path.exists(idx) else JSONResponse(
        {"service": f"MPX Studio EA Portfolio {APP_VERSION}", "docs": "/docs"})

# ─── SEED DATA ─────────────────────────────────────────────────────────────────
def _assign_biz_owner(apps: list) -> list:
    """Assign deterministic Business App Owner names to seed apps based on domain.
    ใช้ fixed seed เพื่อให้ผลลัพธ์เหมือนเดิมทุกครั้ง"""
    import random
    rng = random.Random(7)  # fixed seed → reproducible

    # Domain → Business Owner pool (1-2 คนต่อ domain เพื่อให้ดูสมจริง)
    DOMAIN_OWNERS = {
        "Finance":       ["Wichai T.", "Nattaya P.", "Kraingkrai S."],
        "CRM":           ["Warangkana B.", "Phonsawan N."],
        "Customer":      ["Warangkana B.", "Ratchanee O.", "Phonsawan N."],
        "HR":            ["Sirirat K.", "Pimchanok W."],
        "Analytics":     ["Ekachai M.", "Duangdao S.", "Patcharee R."],
        "Digital":       ["Ekachai M.", "Natthaphat C."],
        "Supply Chain":  ["Thitipong A.", "Kornwipa S."],
        "Operations":    ["Suchart P.", "Malai T.", "Thitipong A."],
        "Infrastructure":["Kittisak N.", "Chainarong B."],
        "Security":      ["Worawit L.", "Kittisak N."],
    }
    FALLBACK = ["Narong V.", "Sunisa C.", "Prayoon T.", "Apirada J.", "Chalermpol K."]

    for app in apps:
        domain = app.get("domain", "")
        pool = DOMAIN_OWNERS.get(domain, FALLBACK)
        app["biz_owner"] = rng.choice(pool)
    return apps


def _assign_compliance(apps: list) -> list:
    """Assign deterministic compliance values to seed apps based on their attributes.
    เพิ่ม standard ใหม่ใน COMPLIANCE_STANDARDS (index.html) แล้วเพิ่ม logic ตรงนี้เพื่อ auto-assign seed data"""
    import random
    rng = random.Random(42)  # fixed seed → reproducible ทุกครั้ง
    CLOUD_KEYWORDS = {"Kubernetes","Azure","AWS","GCP","Snowflake","Heroku","Terraform","Kafka","Cloud","Istio","Helm"}
    for app in apps:
        stack_str = app.get("stack", "")
        eligible = []
        if app.get("pi_spi"):                                          eligible += ["ISO 27001", "PDPA"]
        if app.get("dr"):                                              eligible.append("DR Policy")
        if int(app.get("integration", 0)) > 10:                       eligible.append("API Standards")
        if any(k in stack_str for k in CLOUD_KEYWORDS):               eligible.append("Cloud-First")
        if app.get("criticality") in ("Mission Critical", "High"):    eligible.append("Zero-Trust")
        eligible = list(dict.fromkeys(eligible))   # dedupe, preserve order
        # เลือก subset: อย่างน้อย 1 รายการถ้ามี eligible, บางครั้งได้ทั้งหมด
        if eligible:
            n = rng.randint(max(1, len(eligible) - 1), len(eligible))
            app["compliance"] = json.dumps(rng.sample(eligible, min(n, len(eligible))))
        else:
            app["compliance"] = "[]"
    return apps

def _seed_apps() -> list:
    return [
        {"id":'APP-001',"name":'SAP S/4HANA',"domain":'Finance',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":12,"age":3,"tco":4200,"users":850,"criticality":'Mission Critical',"dr":1,"eol":'2032-12',"pi_spi":1,"contract_end":'2027-06',"integration":12,"stack":'["ABAP", "SAP UI5", "HANA"]',"capability":'ERP Core',"strategic":92,"persons":8,"src_avail":1,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'ABAP',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Somchai K.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Completed',"assess_date":'2024-06',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-002',"name":'Salesforce CRM',"domain":'CRM',"vendor":'Salesforce',"type":'Package',"status":'Active',"bcg":'Invest',"health":85,"tech_debt":15,"age":4,"tco":2800,"users":420,"criticality":'Mission Critical',"dr":1,"eol":'2030-12',"pi_spi":1,"contract_end":'2026-03',"integration":18,"stack":'["Apex", "Lightning", "Heroku"]',"capability":'CRM',"strategic":88,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Sat 23:00-03:00',"lang":'Apex/JS',"os":'Cloud (SaaS)',"db_platform":'Salesforce DB',"support":'Vendor',"owner":'Narong P.',"stream":'Customer Experience',"approach":'Migrate',"assess_status":'Completed',"assess_date":'2024-09',"wave":2,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-003',"name":'Core Banking AS/400',"domain":'Finance',"vendor":'IBM',"type":'Inhouse',"status":'Phase-out',"bcg":'Retire',"health":35,"tech_debt":82,"age":22,"tco":6500,"users":120,"criticality":'Mission Critical',"dr":0,"eol":'2025-12',"pi_spi":1,"contract_end":'2025-12',"integration":35,"stack":'["RPG", "COBOL", "DB2"]',"capability":'Core Banking',"strategic":15,"persons":2,"src_avail":1,"service_hour":'24x7',"maint_window":'Sun 01:00-05:00',"lang":'RPG/COBOL',"os":'IBM i (AS/400)',"db_platform":'DB2/400',"support":'Inhouse',"owner":'Wanchai S.',"stream":'Core Banking Transform',"approach":'Replace',"assess_status":'Completed',"assess_date":'2023-12',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-004',"name":'HR WorkDay',"domain":'HR',"vendor":'Workday',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":2,"tco":1800,"users":1200,"criticality":'High',"dr":1,"eol":'2033-06',"pi_spi":1,"contract_end":'2028-01',"integration":8,"stack":'["Workday Studio", "REST API"]',"capability":'HR Management',"strategic":85,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Workday Studio',"os":'Cloud (SaaS)',"db_platform":'Workday DB',"support":'Vendor',"owner":'Pitchaya N.',"stream":'HR Modernization',"approach":'Extend',"assess_status":'Planned',"assess_date":'2025-03',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-005',"name":'AI Analytics Hub',"domain":'Analytics',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Grow',"health":78,"tech_debt":22,"age":1,"tco":950,"users":280,"criticality":'High',"dr":1,"eol":'2029-06',"pi_spi":0,"contract_end":'N/A',"integration":14,"stack":'["Python", "TensorFlow", "Kubernetes"]',"capability":'Analytics & AI',"strategic":95,"persons":6,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sat 20:00-24:00',"lang":'Python',"os":'Linux (K8s)',"db_platform":'PostgreSQL',"support":'Inhouse',"owner":'Thanakrit W.',"stream":'Data & AI',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":2,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-006',"name":'Legacy ERP Oracle',"domain":'Finance',"vendor":'Oracle',"type":'Package',"status":'Phase-out',"bcg":'Retire',"health":42,"tech_debt":75,"age":18,"tco":5200,"users":95,"criticality":'High',"dr":0,"eol":'2026-06',"pi_spi":1,"contract_end":'2026-06',"integration":28,"stack":'["Oracle Forms", "PL/SQL"]',"capability":'ERP Core',"strategic":20,"persons":3,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-08:00',"lang":'PL/SQL',"os":'Oracle Linux',"db_platform":'Oracle 11g',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Retire',"assess_status":'Completed',"assess_date":'2023-06',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-007',"name":'K8s Platform',"domain":'Infrastructure',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Invest',"health":92,"tech_debt":6,"age":2,"tco":1200,"users":45,"criticality":'Mission Critical',"dr":1,"eol":'2030-06',"pi_spi":0,"contract_end":'N/A',"integration":30,"stack":'["Kubernetes", "Helm", "Terraform"]',"capability":'Cloud Platform',"strategic":90,"persons":5,"src_avail":1,"service_hour":'24x7',"maint_window":'Tue 02:00-04:00',"lang":'YAML/HCL',"os":'Linux (Ubuntu)',"db_platform":'etcd',"support":'Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-11',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-008',"name":'Data Warehouse v2',"domain":'Analytics',"vendor":'Snowflake',"type":'Package',"status":'Active',"bcg":'Grow',"health":82,"tech_debt":18,"age":3,"tco":1600,"users":180,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-09',"integration":22,"stack":'["Snowflake", "dbt", "Airflow"]',"capability":'Data Platform',"strategic":87,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 01:00-05:00',"lang":'SQL/Python',"os":'Cloud (SaaS)',"db_platform":'Snowflake',"support":'Vendor+Inhouse',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Grow',"assess_status":'Completed',"assess_date":'2024-08',"wave":2,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-009',"name":'Supply Chain SAP',"domain":'Supply Chain',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":80,"tech_debt":20,"age":5,"tco":3100,"users":340,"criticality":'Mission Critical',"dr":1,"eol":'2031-06',"pi_spi":1,"contract_end":'2027-06',"integration":16,"stack":'["ABAP", "SAP SCM", "HANA"]',"capability":'Supply Chain',"strategic":86,"persons":7,"src_avail":1,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'ABAP',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Upgrade',"assess_status":'In Progress',"assess_date":'2024-12',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-010',"name":'Customer Portal',"domain":'Customer',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Grow',"health":75,"tech_debt":28,"age":4,"tco":800,"users":50000,"criticality":'High',"dr":1,"eol":'2029-06',"pi_spi":1,"contract_end":'N/A',"integration":12,"stack":'["React", "Node.js", "PostgreSQL"]',"capability":'Customer Self-Service',"strategic":82,"persons":6,"src_avail":1,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'JavaScript',"os":'Linux (K8s)',"db_platform":'PostgreSQL',"support":'Inhouse',"owner":'Worapon S.',"stream":'Customer Experience',"approach":'Modernize',"assess_status":'Planned',"assess_date":'2025-02',"wave":2,"ea_group":'2. Services',"ea_category":'2.7 Portal & Gateway',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-011',"name":'Legacy CRM Siebel',"domain":'CRM',"vendor":'Oracle',"type":'Package',"status":'To-retire',"bcg":'Retire',"health":28,"tech_debt":90,"age":20,"tco":3800,"users":65,"criticality":'High',"dr":0,"eol":'2025-06',"pi_spi":1,"contract_end":'2025-06',"integration":24,"stack":'["Siebel", "PL/SQL"]',"capability":'CRM',"strategic":8,"persons":1,"src_avail":0,"service_hour":'Business Hours',"maint_window":'N/A',"lang":'Siebel VB',"os":'Windows Server',"db_platform":'Oracle 10g',"support":'Vendor',"owner":'Teerayut K.',"stream":'Customer Experience',"approach":'Retire',"assess_status":'Completed',"assess_date":'2024-01',"wave":1,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-012',"name":'Azure DevOps',"domain":'Infrastructure',"vendor":'Microsoft',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":3,"tco":420,"users":220,"criticality":'Medium',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2026-12',"integration":15,"stack":'["Azure", "Git", "YAML"]',"capability":'DevOps',"strategic":78,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'YAML',"os":'Cloud (SaaS)',"db_platform":'Azure SQL',"support":'Vendor',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Not Started',"assess_date":'',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-013',"name":'Power BI Platform',"domain":'Analytics',"vendor":'Microsoft',"type":'Package',"status":'Active',"bcg":'Grow',"health":83,"tech_debt":14,"age":3,"tco":680,"users":520,"criticality":'Medium',"dr":0,"eol":'2032-12',"pi_spi":0,"contract_end":'2026-12',"integration":10,"stack":'["Power BI", "DAX", "Azure"]',"capability":'BI & Reporting',"strategic":80,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'DAX/M',"os":'Cloud (SaaS)',"db_platform":'Power BI Premium',"support":'Vendor',"owner":'Orawan L.',"stream":'Data & AI',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":3,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-014',"name":'MES Factory v1',"domain":'Operations',"vendor":'Rockwell',"type":'Package',"status":'Phase-out',"bcg":'Tolerate',"health":55,"tech_debt":60,"age":12,"tco":2200,"users":80,"criticality":'Mission Critical',"dr":0,"eol":'2027-06',"pi_spi":0,"contract_end":'2027-06',"integration":6,"stack":'["FactoryTalk", "Historian"]',"capability":'Manufacturing',"strategic":42,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 04:00-06:00',"lang":'Proprietary',"os":'Windows Server 2012',"db_platform":'SQL Server 2012',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Replace',"assess_status":'Planned',"assess_date":'2025-06',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-015',"name":'Treasury System',"domain":'Finance',"vendor":'FIS',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":68,"tech_debt":38,"age":9,"tco":1500,"users":35,"criticality":'Mission Critical',"dr":1,"eol":'2028-06',"pi_spi":1,"contract_end":'2028-06',"integration":14,"stack":'["FIS Integrity", "SQL Server"]',"capability":'Treasury',"strategic":65,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 23:00-03:00',"lang":'C#/.NET',"os":'Windows Server',"db_platform":'SQL Server',"support":'Vendor',"owner":'Nipon A.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Completed',"assess_date":'2024-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-016',"name":'Identity Platform',"domain":'Security',"vendor":'Okta',"type":'Package',"status":'Active',"bcg":'Invest',"health":94,"tech_debt":5,"age":2,"tco":560,"users":5000,"criticality":'Mission Critical',"dr":1,"eol":'2033-12',"pi_spi":1,"contract_end":'2027-03',"integration":45,"stack":'["Okta", "SAML", "OAuth2"]',"capability":'Identity & Access',"strategic":92,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 02:00-04:00',"lang":'N/A (SaaS)',"os":'Cloud (SaaS)',"db_platform":'Okta DB',"support":'Vendor',"owner":'Kanchana R.',"stream":'Security',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":1,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-017',"name":'ITSM ServiceNow',"domain":'Operations',"vendor":'ServiceNow',"type":'Package',"status":'Active',"bcg":'Invest',"health":86,"tech_debt":12,"age":4,"tco":1100,"users":350,"criticality":'High',"dr":1,"eol":'2032-06',"pi_spi":0,"contract_end":'2027-09',"integration":20,"stack":'["ServiceNow", "JavaScript", "Glide"]',"capability":'IT Service Mgmt',"strategic":84,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'ServiceNow DB',"support":'Vendor+Inhouse',"owner":'Prasertsak D.',"stream":'IT Operations',"approach":'Extend',"assess_status":'Completed',"assess_date":'2024-07',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-018',"name":'Batch Processing v2',"domain":'Operations',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Tolerate',"health":62,"tech_debt":45,"age":8,"tco":380,"users":5,"criticality":'High',"dr":0,"eol":'2027-12',"pi_spi":0,"contract_end":'N/A',"integration":8,"stack":'["Java", "Spring", "Oracle"]',"capability":'Batch Ops',"strategic":50,"persons":2,"src_avail":1,"service_hour":'Off-Hours',"maint_window":'Daily 00:00-04:00',"lang":'Java',"os":'RHEL 7',"db_platform":'Oracle 12c',"support":'Inhouse',"owner":'Phanuwat S.',"stream":'Operations',"approach":'Modernize',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-019',"name":'Document Mgmt',"domain":'Operations',"vendor":'OpenText',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":65,"tech_debt":42,"age":10,"tco":920,"users":450,"criticality":'Medium',"dr":0,"eol":'2026-12',"pi_spi":1,"contract_end":'2026-12',"integration":12,"stack":'["OpenText", "Documentum"]',"capability":'Document Mgmt',"strategic":55,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java',"os":'Windows Server',"db_platform":'SQL Server',"support":'Vendor',"owner":'Apinya T.',"stream":'Operations',"approach":'Replace',"assess_status":'In Progress',"assess_date":'2024-11',"wave":3,"ea_group":'2. Services',"ea_category":'2.6 Channel',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-020',"name":'API Gateway',"domain":'Infrastructure',"vendor":'Kong',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":2,"tco":320,"users":20,"criticality":'Mission Critical',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'2027-06',"integration":60,"stack":'["Kong", "Kubernetes", "Lua"]',"capability":'Integration',"strategic":88,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Tue 02:00-04:00',"lang":'Lua/Go',"os":'Linux (K8s)',"db_platform":'PostgreSQL',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-021',"name":'Legacy Payroll RPG',"domain":'HR',"vendor":'Internal',"type":'Inhouse',"status":'To-retire',"bcg":'Retire',"health":30,"tech_debt":88,"age":25,"tco":1800,"users":12,"criticality":'High',"dr":0,"eol":'2025-12',"pi_spi":1,"contract_end":'N/A',"integration":5,"stack":'["RPG", "ILE", "DB2/400"]',"capability":'Payroll',"strategic":5,"persons":1,"src_avail":1,"service_hour":'Off-Hours',"maint_window":'N/A',"lang":'RPG/ILE',"os":'IBM i (AS/400)',"db_platform":'DB2/400',"support":'Inhouse',"owner":'Wanchai S.',"stream":'HR Modernization',"approach":'Retire',"assess_status":'Completed',"assess_date":'2023-09',"wave":1,"ea_group":'2. Services',"ea_category":'2.3 Service',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-022',"name":'e-Commerce Platform',"domain":'Customer',"vendor":'Commercetools',"type":'Package',"status":'Active',"bcg":'Invest',"health":87,"tech_debt":14,"age":2,"tco":2200,"users":200000,"criticality":'Mission Critical',"dr":1,"eol":'2031-12',"pi_spi":1,"contract_end":'2027-12',"integration":25,"stack":'["Commercetools", "React", "GraphQL"]',"capability":'e-Commerce',"strategic":94,"persons":8,"src_avail":0,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'MongoDB/SaaS',"support":'Vendor+Inhouse',"owner":'Varunya C.',"stream":'Customer Experience',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":2,"ea_group":'1. Direction',"ea_category":'1.5 Standard & Policies',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-023',"name":'Risk Mgmt System',"domain":'Finance',"vendor":"Moody's","type":'Package',"status":'Active',"bcg":'Tolerate',"health":70,"tech_debt":32,"age":7,"tco":1400,"users":45,"criticality":'High',"dr":1,"eol":'2029-06',"pi_spi":1,"contract_end":'2029-06',"integration":10,"stack":'["Moody\'s RMS", "Oracle"]',"capability":'Risk Management',"strategic":70,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Oracle Linux',"db_platform":'Oracle 19c',"support":'Vendor',"owner":'Nipon A.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Planned',"assess_date":'2025-04',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-024',"name":'ML Feature Store',"domain":'Analytics',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Grow',"health":76,"tech_debt":24,"age":1,"tco":480,"users":30,"criticality":'Medium',"dr":0,"eol":'2030-06',"pi_spi":0,"contract_end":'N/A',"integration":8,"stack":'["Python", "Redis", "PostgreSQL"]',"capability":'ML Platform',"strategic":90,"persons":4,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Python',"os":'Linux (K8s)',"db_platform":'Redis/PostgreSQL',"support":'Inhouse',"owner":'Thanakrit W.',"stream":'Data & AI',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-02',"wave":2,"ea_group":'2. Services',"ea_category":'2.4 Employee',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-025',"name":'EAM - Maximo',"domain":'Operations',"vendor":'IBM',"type":'Package',"status":'Phase-out',"bcg":'Tolerate',"health":58,"tech_debt":55,"age":14,"tco":2600,"users":95,"criticality":'High',"dr":0,"eol":'2027-06',"pi_spi":0,"contract_end":'2027-06',"integration":9,"stack":'["IBM Maximo", "Java EE", "Db2"]',"capability":'Asset Management',"strategic":48,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java EE',"os":'AIX',"db_platform":'IBM Db2',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Replace',"assess_status":'Completed',"assess_date":'2023-10',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-026',"name":'Cloud MDM',"domain":'Analytics',"vendor":'Reltio',"type":'Package',"status":'Active',"bcg":'Grow',"health":80,"tech_debt":18,"age":2,"tco":760,"users":60,"criticality":'Medium',"dr":1,"eol":'2030-06',"pi_spi":1,"contract_end":'2027-06',"integration":18,"stack":'["Reltio", "REST", "Kafka"]',"capability":'Master Data',"strategic":82,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Cloud (SaaS)',"db_platform":'Reltio Graph DB',"support":'Vendor',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-027',"name":'Network IPAM',"domain":'Infrastructure',"vendor":'Infoblox',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":72,"tech_debt":28,"age":6,"tco":280,"users":8,"criticality":'Mission Critical',"dr":1,"eol":'2029-12',"pi_spi":0,"contract_end":'2027-12',"integration":4,"stack":'["Infoblox", "REST", "DNS"]',"capability":'Network Mgmt',"strategic":60,"persons":2,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'N/A (Appliance)',"os":'Infoblox OS',"db_platform":'Infoblox DB',"support":'Vendor',"owner":'Nuntachai P.',"stream":'IT Operations',"approach":'Upgrade',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.2 Partner',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-028',"name":'Old BI Crystal',"domain":'Analytics',"vendor":'SAP',"type":'Package',"status":'To-retire',"bcg":'Retire',"health":22,"tech_debt":92,"age":19,"tco":980,"users":30,"criticality":'Low',"dr":0,"eol":'2025-06',"pi_spi":0,"contract_end":'2025-06',"integration":5,"stack":'["Crystal Reports", "SAP BO"]',"capability":'BI & Reporting',"strategic":5,"persons":1,"src_avail":0,"service_hour":'Business Hours',"maint_window":'N/A',"lang":'Crystal Syntax',"os":'Windows Server',"db_platform":'SQL Server 2008',"support":'Vendor',"owner":'Orawan L.',"stream":'Data & AI',"approach":'Retire',"assess_status":'Completed',"assess_date":'2023-08',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-029',"name":'ServiceMesh Istio',"domain":'Infrastructure',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Invest',"health":85,"tech_debt":12,"age":2,"tco":180,"users":12,"criticality":'Mission Critical',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'N/A',"integration":40,"stack":'["Istio", "Kubernetes", "Envoy"]',"capability":'Cloud Platform',"strategic":86,"persons":4,"src_avail":1,"service_hour":'24x7',"maint_window":'Tue 02:00-04:00',"lang":'YAML/Go',"os":'Linux (K8s)',"db_platform":'N/A',"support":'Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-11',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-030',"name":'Procurement Ariba',"domain":'Supply Chain',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":84,"tech_debt":14,"age":3,"tco":1200,"users":160,"criticality":'High',"dr":1,"eol":'2030-12',"pi_spi":1,"contract_end":'2027-06',"integration":12,"stack":'["SAP Ariba", "REST", "XML"]',"capability":'Procurement',"strategic":80,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'SAP HANA',"support":'Vendor',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Extend',"assess_status":'Completed',"assess_date":'2024-06',"wave":2,"ea_group":'2. Services',"ea_category":'2.7 Portal & Gateway',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-031',"name":'Contact Center CX',"domain":'Customer',"vendor":'Genesys',"type":'Package',"status":'Active',"bcg":'Invest',"health":82,"tech_debt":16,"age":3,"tco":1850,"users":280,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":1,"contract_end":'2027-12',"integration":14,"stack":'["Genesys Cloud", "WebRTC", "REST"]',"capability":'Contact Center',"strategic":85,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Genesys DB',"support":'Vendor',"owner":'Varunya C.',"stream":'Customer Experience',"approach":'Extend',"assess_status":'In Progress',"assess_date":'2024-12',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-032',"name":'Cyber SIEM',"domain":'Security',"vendor":'Splunk',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":3,"tco":890,"users":15,"criticality":'Mission Critical',"dr":1,"eol":'2030-12',"pi_spi":0,"contract_end":'2026-12',"integration":50,"stack":'["Splunk", "Python", "REST"]',"capability":'Security Ops',"strategic":92,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 02:00-04:00',"lang":'SPL/Python',"os":'Linux',"db_platform":'Splunk Index',"support":'Vendor+Inhouse',"owner":'Kanchana R.',"stream":'Security',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-033',"name":'Finance Close',"domain":'Finance',"vendor":'BlackLine',"type":'Package',"status":'Active',"bcg":'Grow',"health":81,"tech_debt":17,"age":2,"tco":680,"users":85,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":1,"contract_end":'2027-06',"integration":8,"stack":'["BlackLine", "REST", "SAP"]',"capability":'Financial Close',"strategic":78,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'BlackLine DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Grow',"assess_status":'Planned',"assess_date":'2025-05',"wave":3,"ea_group":'1. Direction',"ea_category":'1.6 Business Process & Services',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-034',"name":'WMS Warehouse',"domain":'Supply Chain',"vendor":'Manhattan',"type":'Package',"status":'Phase-out',"bcg":'Tolerate',"health":60,"tech_debt":50,"age":11,"tco":1700,"users":120,"criticality":'High',"dr":0,"eol":'2027-12',"pi_spi":0,"contract_end":'2027-12',"integration":10,"stack":'["Manhattan WMS", "SQL Server"]',"capability":'Warehouse Ops',"strategic":52,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'Java',"os":'Windows Server',"db_platform":'SQL Server 2016',"support":'Vendor',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Replace',"assess_status":'In Progress',"assess_date":'2024-10',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-035',"name":'IoT Data Platform',"domain":'Operations',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Grow',"health":74,"tech_debt":26,"age":2,"tco":520,"users":18,"criticality":'Medium',"dr":0,"eol":'2030-06',"pi_spi":0,"contract_end":'N/A',"integration":22,"stack":'["MQTT", "Kafka", "TimescaleDB"]',"capability":'IoT',"strategic":88,"persons":4,"src_avail":1,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'Python/Go',"os":'Linux (K8s)',"db_platform":'TimescaleDB',"support":'Inhouse',"owner":'Phanuwat S.',"stream":'Operations',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.3 Service',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-036',"name":'Compliance GRC',"domain":'Security',"vendor":'ServiceNow',"type":'Package',"status":'Active',"bcg":'Invest',"health":86,"tech_debt":12,"age":2,"tco":580,"users":60,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":1,"contract_end":'2027-09',"integration":15,"stack":'["ServiceNow GRC", "REST"]',"capability":'Compliance',"strategic":85,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'ServiceNow DB',"support":'Vendor',"owner":'Prasertsak D.',"stream":'Security',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-08',"wave":1,"ea_group":'4. Support',"ea_category":'4.1 Training & Communication',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-037',"name":'Legacy GL Batch',"domain":'Finance',"vendor":'Internal',"type":'Inhouse',"status":'To-retire',"bcg":'Retire',"health":25,"tech_debt":95,"age":28,"tco":1200,"users":8,"criticality":'High',"dr":0,"eol":'2025-09',"pi_spi":1,"contract_end":'N/A',"integration":7,"stack":'["COBOL", "JCL", "z/OS"]',"capability":'General Ledger',"strategic":4,"persons":1,"src_avail":1,"service_hour":'Off-Hours',"maint_window":'N/A',"lang":'COBOL',"os":'IBM z/OS',"db_platform":'VSAM/EBCDIC',"support":'Inhouse',"owner":'Wanchai S.',"stream":'Core Finance',"approach":'Retire',"assess_status":'Completed',"assess_date":'2023-06',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-038',"name":'Chat & Collab',"domain":'HR',"vendor":'Microsoft',"type":'Package',"status":'Active',"bcg":'Invest',"health":92,"tech_debt":6,"age":3,"tco":340,"users":4500,"criticality":'Medium',"dr":1,"eol":'2033-12',"pi_spi":0,"contract_end":'2026-12',"integration":20,"stack":'["Teams", "Azure AD", "Graph API"]',"capability":'Collaboration',"strategic":80,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'N/A (SaaS)',"os":'Cloud (SaaS)',"db_platform":'Microsoft 365',"support":'Vendor',"owner":'Pitchaya N.',"stream":'HR Modernization',"approach":'Extend',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'5. Governance',"ea_category":'5.2 Risk & Internal Control',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-039',"name":'Legacy EDI Hub',"domain":'Supply Chain',"vendor":'Internal',"type":'Inhouse',"status":'Phase-out',"bcg":'Tolerate',"health":50,"tech_debt":68,"age":16,"tco":780,"users":6,"criticality":'High',"dr":0,"eol":'2026-12',"pi_spi":0,"contract_end":'N/A',"integration":42,"stack":'["EDI X12", "VAN", "COBOL"]',"capability":'B2B Integration',"strategic":38,"persons":2,"src_avail":1,"service_hour":'24x7',"maint_window":'Daily 02:00-03:00',"lang":'COBOL',"os":'IBM i',"db_platform":'DB2/400',"support":'Inhouse',"owner":'Wanchai S.',"stream":'Supply Chain',"approach":'Replace',"assess_status":'In Progress',"assess_date":'2024-11',"wave":2,"ea_group":'2. Services',"ea_category":'2.4 Employee',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-040',"name":'RPA Platform',"domain":'Operations',"vendor":'UiPath',"type":'Package',"status":'Active',"bcg":'Grow',"health":79,"tech_debt":20,"age":2,"tco":420,"users":25,"criticality":'Medium',"dr":0,"eol":'2030-06',"pi_spi":0,"contract_end":'2027-06',"integration":28,"stack":'["UiPath", "RPA", "Python"]',"capability":'Process Automation',"strategic":84,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 20:00-24:00',"lang":'UiPath Studio',"os":'Windows',"db_platform":'SQL Server',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Grow',"assess_status":'Planned',"assess_date":'2025-03',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-041',"name":'PLM Windchill',"domain":'Operations',"vendor":'PTC',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":66,"tech_debt":40,"age":9,"tco":1400,"users":95,"criticality":'High',"dr":0,"eol":'2028-06',"pi_spi":0,"contract_end":'2028-06',"integration":8,"stack":'["PTC Windchill", "Java EE", "Oracle"]',"capability":'PLM',"strategic":60,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java EE',"os":'Windows Server',"db_platform":'Oracle 19c',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Upgrade',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-042',"name":'Catalog PIM',"domain":'Customer',"vendor":'Akeneo',"type":'Package',"status":'Active',"bcg":'Grow',"health":82,"tech_debt":16,"age":2,"tco":360,"users":45,"criticality":'Medium',"dr":0,"eol":'2030-12',"pi_spi":0,"contract_end":'2027-12',"integration":16,"stack":'["Akeneo", "REST", "GraphQL"]',"capability":'Product Catalog',"strategic":82,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'PHP',"os":'Cloud (SaaS)',"db_platform":'Akeneo DB',"support":'Vendor',"owner":'Varunya C.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-043',"name":'CDP Customer Data',"domain":'Customer',"vendor":'Segment',"type":'Package',"status":'Active',"bcg":'Invest',"health":84,"tech_debt":14,"age":2,"tco":680,"users":35,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":1,"contract_end":'2027-06',"integration":30,"stack":'["Segment", "Kafka", "React"]',"capability":'Customer Data',"strategic":90,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Segment DB',"support":'Vendor',"owner":'Worapon S.',"stream":'Customer Experience',"approach":'Invest',"assess_status":'In Progress',"assess_date":'2024-12',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-044',"name":'Tax Engine',"domain":'Finance',"vendor":'Vertex',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":72,"tech_debt":30,"age":6,"tco":420,"users":20,"criticality":'High',"dr":0,"eol":'2028-12',"pi_spi":1,"contract_end":'2028-12',"integration":8,"stack":'["Vertex", "REST", "SAP"]',"capability":'Tax',"strategic":65,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Cloud (SaaS)',"db_platform":'Vertex DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Planned',"assess_date":'2025-06',"wave":3,"ea_group":'5. Governance',"ea_category":'5.1 Corporate Security & Policy',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-045',"name":'Monitoring Observ.',"domain":'Infrastructure',"vendor":'Datadog',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":2,"tco":580,"users":35,"criticality":'Mission Critical',"dr":1,"eol":'2031-12',"pi_spi":0,"contract_end":'2026-12',"integration":35,"stack":'["Datadog", "APM", "Terraform"]',"capability":'Observability',"strategic":88,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'N/A (SaaS)',"os":'Cloud (SaaS)',"db_platform":'Datadog TSDB',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'IT Operations',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'2. Services',"ea_category":'2.6 Channel',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-046',"name":'Old Asset AS/400',"domain":'Operations',"vendor":'IBM',"type":'Inhouse',"status":'To-retire',"bcg":'Retire',"health":20,"tech_debt":96,"age":30,"tco":950,"users":5,"criticality":'Medium',"dr":0,"eol":'2025-06',"pi_spi":0,"contract_end":'N/A',"integration":3,"stack":'["RPG", "AS/400", "DB2/400"]',"capability":'Asset Management',"strategic":2,"persons":1,"src_avail":1,"service_hour":'Business Hours',"maint_window":'N/A',"lang":'RPG',"os":'IBM i',"db_platform":'DB2/400',"support":'Inhouse',"owner":'Wanchai S.',"stream":'Operations',"approach":'Retire',"assess_status":'Completed',"assess_date":'2023-06',"wave":1,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-047',"name":'Demand Planning',"domain":'Supply Chain',"vendor":'Kinaxis',"type":'Package',"status":'Active',"bcg":'Invest',"health":85,"tech_debt":13,"age":3,"tco":1100,"users":65,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'2027-06',"integration":14,"stack":'["Kinaxis RapidResponse", "REST"]',"capability":'Demand Planning',"strategic":84,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Kinaxis DB',"support":'Vendor',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Invest',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-048',"name":'Fraud Detection AI',"domain":'Security',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Grow',"health":80,"tech_debt":20,"age":1,"tco":680,"users":8,"criticality":'Mission Critical',"dr":1,"eol":'2030-12',"pi_spi":1,"contract_end":'N/A',"integration":12,"stack":'["Python", "TensorFlow", "Kafka"]',"capability":'Fraud Detection',"strategic":94,"persons":5,"src_avail":1,"service_hour":'24x7',"maint_window":'Mon 02:00-04:00',"lang":'Python',"os":'Linux (K8s)',"db_platform":'Kafka/PostgreSQL',"support":'Inhouse',"owner":'Kanchana R.',"stream":'Security',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":2,"ea_group":'1. Direction',"ea_category":'1.4 Governance Body',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-049',"name":'Content Mgmt CMS',"domain":'Customer',"vendor":'Contentful',"type":'Package',"status":'Active',"bcg":'Grow',"health":82,"tech_debt":16,"age":2,"tco":280,"users":30,"criticality":'Low',"dr":0,"eol":'2030-12',"pi_spi":0,"contract_end":'2027-12',"integration":10,"stack":'["Contentful", "GraphQL", "CDN"]',"capability":'Content Mgmt',"strategic":75,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Contentful DB',"support":'Vendor',"owner":'Worapon S.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.7 Portal & Gateway',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-050',"name":'Gen-AI Copilot',"domain":'Digital',"vendor":'Internal',"type":'Inhouse',"status":'Planned',"bcg":'Grow',"health":70,"tech_debt":25,"age":0,"tco":520,"users":0,"criticality":'Medium',"dr":0,"eol":'2032-06',"pi_spi":0,"contract_end":'N/A',"integration":5,"stack":'["GPT-4", "LangChain", "Azure"]',"capability":'AI Assistant',"strategic":96,"persons":6,"src_avail":1,"service_hour":'Business Hours',"maint_window":'N/A',"lang":'Python',"os":'Azure Cloud',"db_platform":'Azure CosmosDB',"support":'Inhouse',"owner":'Thanakrit W.',"stream":'Data & AI',"approach":'Build',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-051',"name":'Oracle HCM Cloud',"domain":'HR',"vendor":'Oracle',"type":'Package',"status":'Active',"bcg":'Invest',"health":86,"tech_debt":11,"age":3,"tco":2200,"users":950,"criticality":'High',"dr":1,"eol":'2033-12',"pi_spi":1,"contract_end":'2028-06',"integration":9,"stack":'["Oracle HCM", "REST API", "OIC"]',"capability":'HR Management',"strategic":84,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Groovy/JS',"os":'Cloud (SaaS)',"db_platform":'Oracle DB',"support":'Vendor',"owner":'Pitchaya N.',"stream":'HR Modernization',"approach":'Extend',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-052',"name":'ServiceNow ITSM',"domain":'Infrastructure',"vendor":'ServiceNow',"type":'Package',"status":'Active',"bcg":'Invest',"health":91,"tech_debt":7,"age":4,"tco":1800,"users":680,"criticality":'High',"dr":1,"eol":'2032-06',"pi_spi":0,"contract_end":'2027-06',"integration":20,"stack":'["ServiceNow", "JavaScript", "REST"]',"capability":'IT Service Mgmt',"strategic":88,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'ServiceNow DB',"support":'Vendor',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-053',"name":'Maximo EAM',"domain":'Operations',"vendor":'IBM',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":62,"tech_debt":42,"age":11,"tco":2600,"users":210,"criticality":'High',"dr":1,"eol":'2028-06',"pi_spi":0,"contract_end":'2028-06',"integration":8,"stack":'["Maximo", "Java", "DB2"]',"capability":'Asset Management',"strategic":60,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 03:00-07:00',"lang":'Java',"os":'AIX',"db_platform":'DB2',"support":'Vendor+Inhouse',"owner":'Patipan W.',"stream":'Operations',"approach":'Modernize',"assess_status":'In Progress',"assess_date":'2024-07',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-054',"name":'Tableau Analytics',"domain":'Analytics',"vendor":'Salesforce',"type":'Package',"status":'Active',"bcg":'Grow',"health":84,"tech_debt":12,"age":3,"tco":720,"users":390,"criticality":'Medium',"dr":0,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-01',"integration":12,"stack":'["Tableau", "REST API", "Python"]',"capability":'Visual Analytics',"strategic":81,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-24:00',"lang":'VizQL',"os":'Cloud (SaaS)',"db_platform":'Tableau DB',"support":'Vendor',"owner":'Orawan L.',"stream":'Data & AI',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-055',"name":'Pega BPM',"domain":'Operations',"vendor":'Pegasystems',"type":'Package',"status":'Active',"bcg":'Grow',"health":79,"tech_debt":21,"age":5,"tco":1900,"users":320,"criticality":'High',"dr":1,"eol":'2030-06',"pi_spi":1,"contract_end":'2027-12',"integration":16,"stack":'["Pega", "Java", "React"]',"capability":'Business Process Mgmt',"strategic":79,"persons":5,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java/Pega',"os":'Linux',"db_platform":'PostgreSQL',"support":'Vendor+Inhouse',"owner":'Sirichai B.',"stream":'Operations',"approach":'Extend',"assess_status":'Planned',"assess_date":'2025-05',"wave":2,"ea_group":'1. Direction',"ea_category":'1.6 Business Process & Services',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-056',"name":'SAP Ariba',"domain":'Supply Chain',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":83,"tech_debt":14,"age":4,"tco":1600,"users":180,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":1,"contract_end":'2027-06',"integration":11,"stack":'["SAP Ariba", "REST", "ABAP"]',"capability":'Procurement',"strategic":85,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 23:00-03:00',"lang":'ABAP/JS',"os":'Cloud (SaaS)',"db_platform":'SAP HANA',"support":'Vendor',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Upgrade',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-057',"name":'Splunk SIEM',"domain":'Security',"vendor":'Splunk',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":3,"tco":1400,"users":40,"criticality":'Mission Critical',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'2026-12',"integration":25,"stack":'["Splunk", "Python", "REST"]',"capability":'Security Monitoring',"strategic":92,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Tue 03:00-05:00',"lang":'SPL/Python',"os":'Linux',"db_platform":'Splunk Index',"support":'Vendor+Inhouse',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-11',"wave":1,"ea_group":'5. Governance',"ea_category":'5.1 Corporate Security & Policy',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-058',"name":'Mulesoft ESB',"domain":'Infrastructure',"vendor":'Salesforce',"type":'Package',"status":'Active',"bcg":'Invest',"health":85,"tech_debt":13,"age":4,"tco":2100,"users":25,"criticality":'Mission Critical',"dr":1,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-06',"integration":48,"stack":'["Mulesoft", "REST", "SOAP", "Kafka"]',"capability":'Integration Platform',"strategic":90,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 03:00-05:00',"lang":'DataWeave',"os":'Cloud (SaaS)',"db_platform":'MySQL',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-06',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-059',"name":'WMS Manhattan',"domain":'Supply Chain',"vendor":'Manhattan',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":68,"tech_debt":38,"age":9,"tco":2400,"users":160,"criticality":'High',"dr":1,"eol":'2028-12',"pi_spi":0,"contract_end":'2028-12',"integration":7,"stack":'["Manhattan WMS", "Java", "Oracle"]',"capability":'Warehouse Mgmt',"strategic":62,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 04:00-08:00',"lang":'Java',"os":'Windows Server',"db_platform":'Oracle 12c',"support":'Vendor',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Replace',"assess_status":'Planned',"assess_date":'2025-06',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-060',"name":'Adobe Experience Mgr',"domain":'Digital',"vendor":'Adobe',"type":'Package',"status":'Active',"bcg":'Grow',"health":80,"tech_debt":20,"age":4,"tco":1300,"users":55,"criticality":'Medium',"dr":0,"eol":'2031-06',"pi_spi":0,"contract_end":'2027-03',"integration":9,"stack":'["AEM", "Java", "HTL"]',"capability":'Digital Experience',"strategic":78,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java/HTL',"os":'Cloud (SaaS)',"db_platform":'JCR/MongoDB',"support":'Vendor+Inhouse',"owner":'Worapon S.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":3,"ea_group":'2. Services',"ea_category":'2.7 Portal & Gateway',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-061',"name":'KRONOS WFM',"domain":'HR',"vendor":'UKG',"type":'Package',"status":'Phase-out',"bcg":'Tolerate',"health":52,"tech_debt":55,"age":12,"tco":1100,"users":800,"criticality":'High',"dr":0,"eol":'2026-06',"pi_spi":0,"contract_end":'2026-06',"integration":5,"stack":'["KRONOS", "Java", "SQL Server"]',"capability":'Workforce Mgmt',"strategic":38,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 03:00-07:00',"lang":'Java',"os":'Windows Server 2016',"db_platform":'SQL Server 2014',"support":'Vendor',"owner":'Pitchaya N.',"stream":'HR Modernization',"approach":'Replace',"assess_status":'Completed',"assess_date":'2024-02',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-062',"name":'Coupa Spend Mgmt',"domain":'Finance',"vendor":'Coupa',"type":'Package',"status":'Active',"bcg":'Grow',"health":87,"tech_debt":11,"age":2,"tco":860,"users":240,"criticality":'Medium',"dr":0,"eol":'2032-12',"pi_spi":0,"contract_end":'2027-06',"integration":7,"stack":'["Coupa", "REST API", "OAuth"]',"capability":'Spend Management',"strategic":76,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Coupa DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-063',"name":'SAP TM Transport',"domain":'Supply Chain',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":81,"tech_debt":17,"age":5,"tco":1700,"users":90,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'2027-06',"integration":8,"stack":'["SAP TM", "ABAP", "HANA"]',"capability":'Transport Mgmt',"strategic":82,"persons":4,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'ABAP',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Upgrade',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-064',"name":'Veeva Vault QMS',"domain":'Operations',"vendor":'Veeva',"type":'Package',"status":'Active',"bcg":'Invest',"health":89,"tech_debt":9,"age":2,"tco":1100,"users":120,"criticality":'High',"dr":1,"eol":'2033-06',"pi_spi":1,"contract_end":'2027-12',"integration":6,"stack":'["Veeva Vault", "REST", "Java"]',"capability":'Quality Mgmt',"strategic":86,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java/JS',"os":'Cloud (SaaS)',"db_platform":'Veeva DB',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Extend',"assess_status":'Completed',"assess_date":'2024-08',"wave":2,"ea_group":'5. Governance',"ea_category":'5.2 Risk & Internal Control',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-065',"name":'PingFederate IAM',"domain":'Security',"vendor":'Ping Identity',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":3,"tco":950,"users":2500,"criticality":'Mission Critical',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2026-09',"integration":32,"stack":'["PingFederate", "OAuth", "SAML"]',"capability":'Identity & Access',"strategic":94,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 02:00-04:00',"lang":'Java',"os":'Linux',"db_platform":'PostgreSQL',"support":'Vendor+Inhouse',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":1,"ea_group":'5. Governance',"ea_category":'5.1 Corporate Security & Policy',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-066',"name":'Informatica MDM',"domain":'Analytics',"vendor":'Informatica',"type":'Package',"status":'Active',"bcg":'Grow',"health":76,"tech_debt":26,"age":6,"tco":1400,"users":35,"criticality":'High',"dr":1,"eol":'2030-12',"pi_spi":0,"contract_end":'2028-06',"integration":18,"stack":'["Informatica", "Java", "Oracle"]',"capability":'Master Data Mgmt',"strategic":83,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java',"os":'Linux',"db_platform":'Oracle 19c',"support":'Vendor+Inhouse',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Modernize',"assess_status":'In Progress',"assess_date":'2024-12',"wave":2,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-067',"name":'DocuSign eSign',"domain":'Finance',"vendor":'DocuSign',"type":'Package',"status":'Active',"bcg":'Grow',"health":92,"tech_debt":6,"age":2,"tco":340,"users":600,"criticality":'Medium',"dr":0,"eol":'2033-12',"pi_spi":1,"contract_end":'2027-03',"integration":8,"stack":'["DocuSign", "REST", "OAuth"]',"capability":'Digital Signature',"strategic":74,"persons":1,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-24:00',"lang":'REST API',"os":'Cloud (SaaS)',"db_platform":'DocuSign DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Extend',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-068',"name":'Zabbix Monitoring',"domain":'Infrastructure',"vendor":'Internal',"type":'Inhouse',"status":'Active',"bcg":'Tolerate',"health":70,"tech_debt":32,"age":7,"tco":180,"users":30,"criticality":'High',"dr":1,"eol":'2027-12',"pi_spi":0,"contract_end":'N/A',"integration":40,"stack":'["Zabbix", "PHP", "MySQL"]',"capability":'Infrastructure Monitoring',"strategic":65,"persons":2,"src_avail":1,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'PHP',"os":'Linux (Ubuntu)',"db_platform":'MySQL',"support":'Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Replace',"assess_status":'Planned',"assess_date":'2025-03',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-069',"name":'Confluence Wiki',"domain":'Infrastructure',"vendor":'Atlassian',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":73,"tech_debt":28,"age":6,"tco":210,"users":780,"criticality":'Low',"dr":0,"eol":'2028-12',"pi_spi":0,"contract_end":'2026-12',"integration":6,"stack":'["Confluence", "Java", "REST"]',"capability":'Knowledge Mgmt',"strategic":55,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Cloud (SaaS)',"db_platform":'PostgreSQL',"support":'Vendor',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Modernize',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.1 Training & Communication',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-070',"name":'Jira Service Desk',"domain":'Infrastructure',"vendor":'Atlassian',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":75,"tech_debt":25,"age":5,"tco":280,"users":920,"criticality":'Medium',"dr":0,"eol":'2029-12',"pi_spi":0,"contract_end":'2026-12',"integration":10,"stack":'["Jira", "REST", "Python"]',"capability":'Service Desk',"strategic":58,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Cloud (SaaS)',"db_platform":'PostgreSQL',"support":'Vendor',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Modernize',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-071',"name":'SAP GRC Access',"domain":'Security',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":84,"tech_debt":14,"age":5,"tco":980,"users":150,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":1,"contract_end":'2027-06',"integration":7,"stack":'["SAP GRC", "ABAP", "HANA"]',"capability":'GRC & Compliance',"strategic":88,"persons":3,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'ABAP',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Nuntachai P.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Completed',"assess_date":'2024-07',"wave":1,"ea_group":'5. Governance',"ea_category":'5.3 Law & Compliance',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-072',"name":'OpenShift Platform',"domain":'Infrastructure',"vendor":'Red Hat',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":2,"tco":1600,"users":60,"criticality":'Mission Critical',"dr":1,"eol":'2032-06',"pi_spi":0,"contract_end":'2027-06',"integration":35,"stack":'["OpenShift", "Kubernetes", "Helm"]',"capability":'Container Platform',"strategic":92,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Tue 02:00-04:00',"lang":'YAML/Ansible',"os":'RHEL',"db_platform":'etcd',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-11',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-073',"name":'Guidewire Claims',"domain":'Operations',"vendor":'Guidewire',"type":'Package',"status":'Active',"bcg":'Invest',"health":87,"tech_debt":11,"age":3,"tco":3200,"users":440,"criticality":'Mission Critical',"dr":1,"eol":'2032-12',"pi_spi":1,"contract_end":'2028-06',"integration":14,"stack":'["Guidewire", "Java", "Gosu"]',"capability":'Claims Processing',"strategic":90,"persons":6,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'Gosu/Java',"os":'Linux',"db_platform":'Oracle 19c',"support":'Vendor+Inhouse',"owner":'Somchai K.',"stream":'Core Banking Transform',"approach":'Extend',"assess_status":'Completed',"assess_date":'2024-09',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-074',"name":'Dynatrace APM',"domain":'Infrastructure',"vendor":'Dynatrace',"type":'Package',"status":'Active',"bcg":'Grow',"health":91,"tech_debt":7,"age":2,"tco":860,"users":50,"criticality":'High',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2027-06',"integration":28,"stack":'["Dynatrace", "OneAgent", "REST"]',"capability":'Application Performance',"strategic":85,"persons":2,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 03:00-05:00',"lang":'OneAgent',"os":'Cloud (SaaS)',"db_platform":'Dynatrace DB',"support":'Vendor',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-075',"name":'SWIFT Gateway',"domain":'Finance',"vendor":'SWIFT',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":6,"tco":2800,"users":15,"criticality":'Mission Critical',"dr":1,"eol":'2030-06',"pi_spi":1,"contract_end":'2028-06',"integration":22,"stack":'["SWIFT", "FIN", "ISO 20022"]',"capability":'Payment Gateway',"strategic":95,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 01:00-05:00',"lang":'C++/Java',"os":'RHEL',"db_platform":'Oracle 19c',"support":'Vendor+Inhouse',"owner":'Somchai K.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Completed',"assess_date":'2024-06',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-076',"name":'Anaplan FP&A',"domain":'Finance',"vendor":'Anaplan',"type":'Package',"status":'Active',"bcg":'Grow',"health":85,"tech_debt":13,"age":3,"tco":1100,"users":180,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-06',"integration":8,"stack":'["Anaplan", "REST", "Excel"]',"capability":'Financial Planning',"strategic":82,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Anaplan Model',"os":'Cloud (SaaS)',"db_platform":'Anaplan DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Grow',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-077',"name":'Verint Speech Analytics',"domain":'Customer',"vendor":'Verint',"type":'Package',"status":'Active',"bcg":'Grow',"health":78,"tech_debt":22,"age":3,"tco":760,"users":65,"criticality":'Medium',"dr":0,"eol":'2030-12',"pi_spi":0,"contract_end":'2027-03',"integration":7,"stack":'["Verint", "Python", "REST"]',"capability":'Voice Analytics',"strategic":76,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Python',"os":'Windows Server 2019',"db_platform":'SQL Server 2019',"support":'Vendor',"owner":'Narong P.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-078',"name":'Redis Cache Cluster',"domain":'Infrastructure',"vendor":'Redis Labs',"type":'Package',"status":'Active',"bcg":'Invest',"health":93,"tech_debt":5,"age":2,"tco":420,"users":0,"criticality":'High',"dr":1,"eol":'2033-12',"pi_spi":0,"contract_end":'2027-06',"integration":18,"stack":'["Redis", "Cluster", "Sentinel"]',"capability":'In-Memory Cache',"strategic":80,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'Redis',"os":'Linux (K8s)',"db_platform":'Redis',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-079',"name":'Mendix Low-Code',"domain":'Digital',"vendor":'Siemens',"type":'Package',"status":'Active',"bcg":'Grow',"health":82,"tech_debt":16,"age":2,"tco":680,"users":45,"criticality":'Low',"dr":0,"eol":'2032-06',"pi_spi":0,"contract_end":'2026-12',"integration":6,"stack":'["Mendix", "REST", "Java"]',"capability":'Low-Code Dev',"strategic":72,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Mendix',"os":'Cloud (SaaS)',"db_platform":'Mendix DB',"support":'Vendor+Inhouse',"owner":'Worapon S.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-080',"name":'IBM MQ Messaging',"domain":'Infrastructure',"vendor":'IBM',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":72,"tech_debt":30,"age":10,"tco":890,"users":0,"criticality":'Mission Critical',"dr":1,"eol":'2028-06',"pi_spi":0,"contract_end":'2028-06',"integration":42,"stack":'["IBM MQ", "Java", "AMQP"]',"capability":'Message Queuing',"strategic":65,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 02:00-04:00',"lang":'Java/C',"os":'AIX',"db_platform":'IBM MQ Store',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Replace',"assess_status":'In Progress',"assess_date":'2024-11',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-081',"name":'Workiva GRC Report',"domain":'Finance',"vendor":'Workiva',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":2,"tco":720,"users":85,"criticality":'High',"dr":1,"eol":'2033-06',"pi_spi":1,"contract_end":'2027-03',"integration":5,"stack":'["Workiva", "REST", "Excel"]',"capability":'Regulatory Reporting',"strategic":87,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Wdesk',"os":'Cloud (SaaS)',"db_platform":'Workiva DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Extend',"assess_status":'Planned',"assess_date":'2025-05',"wave":2,"ea_group":'5. Governance',"ea_category":'5.3 Law & Compliance',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-082',"name":'Kafka Event Bus',"domain":'Infrastructure',"vendor":'Confluent',"type":'Package',"status":'Active',"bcg":'Invest',"health":89,"tech_debt":9,"age":3,"tco":960,"users":0,"criticality":'Mission Critical',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2027-06',"integration":38,"stack":'["Apache Kafka", "Confluent", "Java"]',"capability":'Event Streaming',"strategic":91,"persons":4,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'Java/Scala',"os":'Linux (K8s)',"db_platform":'Kafka Topics',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-083',"name":'NetSuite ERP SME',"domain":'Finance',"vendor":'Oracle',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":74,"tech_debt":27,"age":7,"tco":1400,"users":130,"criticality":'High',"dr":1,"eol":'2029-12',"pi_spi":0,"contract_end":'2026-12',"integration":10,"stack":'["NetSuite", "SuiteScript", "REST"]',"capability":'SME Finance',"strategic":58,"persons":2,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'SuiteScript',"os":'Cloud (SaaS)',"db_platform":'NetSuite DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Migrate',"assess_status":'Planned',"assess_date":'2025-06',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-084',"name":'Grafana Observability',"domain":'Infrastructure',"vendor":'Grafana Labs',"type":'Package',"status":'Active',"bcg":'Grow',"health":88,"tech_debt":10,"age":2,"tco":320,"users":45,"criticality":'High',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2026-12',"integration":22,"stack":'["Grafana", "Prometheus", "Loki"]',"capability":'Observability',"strategic":82,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'PromQL',"os":'Linux (K8s)',"db_platform":'Prometheus',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-085',"name":'Genesys Cloud CX',"domain":'Customer',"vendor":'Genesys',"type":'Package',"status":'Active',"bcg":'Invest',"health":86,"tech_debt":12,"age":3,"tco":2200,"users":380,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":1,"contract_end":'2027-06',"integration":14,"stack":'["Genesys Cloud", "REST", "WebRTC"]',"capability":'Contact Centre',"strategic":88,"persons":5,"src_avail":0,"service_hour":'24x7',"maint_window":'Sun 02:00-06:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Genesys DB',"support":'Vendor+Inhouse',"owner":'Narong P.',"stream":'Customer Experience',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-10',"wave":2,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-086',"name":'Legacy COBOL Payroll',"domain":'HR',"vendor":'Internal',"type":'Inhouse',"status":'Phase-out',"bcg":'Retire',"health":32,"tech_debt":88,"age":25,"tco":3100,"users":8,"criticality":'Mission Critical',"dr":0,"eol":'2025-12',"pi_spi":1,"contract_end":'N/A',"integration":6,"stack":'["COBOL", "JCL", "VSAM"]',"capability":'Payroll Processing',"strategic":10,"persons":1,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'COBOL/JCL',"os":'IBM z/OS',"db_platform":'VSAM',"support":'Inhouse',"owner":'Wanchai S.',"stream":'HR Modernization',"approach":'Replace',"assess_status":'Completed',"assess_date":'2023-06',"wave":1,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-087',"name":'Cybersource Payment',"domain":'Customer',"vendor":'Visa',"type":'Package',"status":'Active',"bcg":'Invest',"health":92,"tech_debt":6,"age":4,"tco":880,"users":50000,"criticality":'Mission Critical',"dr":1,"eol":'2032-12',"pi_spi":1,"contract_end":'2028-03',"integration":12,"stack":'["Cybersource", "REST", "3DS"]',"capability":'Payment Processing',"strategic":95,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Mon 03:00-05:00',"lang":'REST API',"os":'Cloud (SaaS)',"db_platform":'Cybersource DB',"support":'Vendor',"owner":'Narong P.',"stream":'Customer Experience',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-09',"wave":1,"ea_group":'2. Services',"ea_category":'2.1 Customer',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-088',"name":'SAS Risk Engine',"domain":'Analytics',"vendor":'SAS',"type":'Package',"status":'Active',"bcg":'Invest',"health":84,"tech_debt":14,"age":7,"tco":3600,"users":35,"criticality":'Mission Critical',"dr":1,"eol":'2030-06',"pi_spi":1,"contract_end":'2026-12',"integration":15,"stack":'["SAS", "Python", "R"]',"capability":'Risk Analytics',"strategic":91,"persons":5,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'SAS/Python',"os":'Linux',"db_platform":'SAS DB',"support":'Vendor+Inhouse',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Modernize',"assess_status":'In Progress',"assess_date":'2024-12',"wave":2,"ea_group":'5. Governance',"ea_category":'5.2 Risk & Internal Control',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-089',"name":'SAP EWM',"domain":'Supply Chain',"vendor":'SAP',"type":'Package',"status":'Planned',"bcg":'Invest',"health":72,"tech_debt":20,"age":1,"tco":1800,"users":0,"criticality":'High',"dr":1,"eol":'2034-06',"pi_spi":0,"contract_end":'2030-06',"integration":9,"stack":'["SAP EWM", "ABAP", "HANA"]',"capability":'Warehouse Mgmt',"strategic":84,"persons":4,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'ABAP',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Sirichai B.',"stream":'Supply Chain',"approach":'Build',"assess_status":'Not Started',"assess_date":'',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-090',"name":'Hashicorp Vault',"domain":'Security',"vendor":'HashiCorp',"type":'Package',"status":'Active',"bcg":'Invest',"health":91,"tech_debt":7,"age":2,"tco":480,"users":0,"criticality":'Mission Critical',"dr":1,"eol":'2033-12',"pi_spi":0,"contract_end":'2026-06',"integration":30,"stack":'["Vault", "Terraform", "REST"]',"capability":'Secrets Management',"strategic":93,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Wed 02:00-04:00',"lang":'HCL/Go',"os":'Linux (K8s)',"db_platform":'Consul',"support":'Vendor+Inhouse',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-08',"wave":1,"ea_group":'5. Governance',"ea_category":'5.1 Corporate Security & Policy',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-091',"name":'Camunda BPM Engine',"domain":'Operations',"vendor":'Camunda',"type":'Package',"status":'Active',"bcg":'Grow',"health":83,"tech_debt":15,"age":2,"tco":560,"users":120,"criticality":'Medium',"dr":0,"eol":'2032-06',"pi_spi":0,"contract_end":'2027-06',"integration":14,"stack":'["Camunda", "Java", "BPMN"]',"capability":'Workflow Engine',"strategic":77,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java',"os":'Linux (K8s)',"db_platform":'PostgreSQL',"support":'Vendor+Inhouse',"owner":'Patipan W.',"stream":'Operations',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'1. Direction',"ea_category":'1.6 Business Process & Services',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-092',"name":'Elastic Search',"domain":'Analytics',"vendor":'Elastic',"type":'Package',"status":'Active',"bcg":'Grow',"health":87,"tech_debt":11,"age":4,"tco":640,"users":25,"criticality":'High',"dr":1,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-06',"integration":16,"stack":'["Elasticsearch", "Kibana", "Logstash"]',"capability":'Search & Analytics',"strategic":80,"persons":3,"src_avail":0,"service_hour":'24x7',"maint_window":'Thu 02:00-04:00',"lang":'REST/JSON',"os":'Linux (K8s)',"db_platform":'Elasticsearch',"support":'Vendor+Inhouse',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Grow',"assess_status":'In Progress',"assess_date":'2025-01',"wave":2,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-093',"name":'Veeva CTMS',"domain":'Operations',"vendor":'Veeva',"type":'Package',"status":'Active',"bcg":'Invest',"health":85,"tech_debt":12,"age":3,"tco":1300,"users":90,"criticality":'High',"dr":1,"eol":'2032-06',"pi_spi":1,"contract_end":'2028-06',"integration":8,"stack":'["Veeva CTMS", "REST", "Java"]',"capability":'Clinical Trial Mgmt',"strategic":83,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'Java/JS',"os":'Cloud (SaaS)',"db_platform":'Veeva DB',"support":'Vendor',"owner":'Patipan W.',"stream":'Operations',"approach":'Extend',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'3. Core Products',"ea_category":'3.2 Corporate & Core System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-094',"name":'MuleSoft API Portal',"domain":'Digital',"vendor":'Salesforce',"type":'Package',"status":'Active',"bcg":'Grow',"health":84,"tech_debt":14,"age":3,"tco":780,"users":80,"criticality":'Medium',"dr":0,"eol":'2031-12',"pi_spi":0,"contract_end":'2027-06',"integration":22,"stack":'["MuleSoft", "REST", "OpenAPI"]',"capability":'API Management',"strategic":79,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'DataWeave',"os":'Cloud (SaaS)',"db_platform":'MySQL',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Customer Experience',"approach":'Grow',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'2. Services',"ea_category":'2.2 Partner',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-095',"name":'SAP Concur Travel',"domain":'Finance',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Tolerate',"health":77,"tech_debt":24,"age":6,"tco":680,"users":920,"criticality":'Low',"dr":0,"eol":'2029-12',"pi_spi":0,"contract_end":'2026-12',"integration":4,"stack":'["SAP Concur", "REST", "OAuth"]',"capability":'T&E Management',"strategic":52,"persons":1,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'JavaScript',"os":'Cloud (SaaS)',"db_platform":'Concur DB',"support":'Vendor',"owner":'Amorn C.',"stream":'Core Finance',"approach":'Extend',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'3. Core Products',"ea_category":'3.3 Back Office & Support System',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-096',"name":'Databricks Lakehouse',"domain":'Analytics',"vendor":'Databricks',"type":'Package',"status":'Active',"bcg":'Invest',"health":88,"tech_debt":10,"age":2,"tco":1800,"users":55,"criticality":'High',"dr":1,"eol":'2033-06',"pi_spi":0,"contract_end":'2027-06',"integration":14,"stack":'["Databricks", "Spark", "Delta Lake", "Python"]',"capability":'Data Lakehouse',"strategic":92,"persons":5,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Python/SQL',"os":'Cloud (SaaS)',"db_platform":'Delta Lake',"support":'Vendor+Inhouse',"owner":'Charoenporn V.',"stream":'Data & AI',"approach":'Invest',"assess_status":'Completed',"assess_date":'2024-11',"wave":2,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-097',"name":'SAP Fiori Launchpad',"domain":'Digital',"vendor":'SAP',"type":'Package',"status":'Active',"bcg":'Invest',"health":86,"tech_debt":12,"age":4,"tco":480,"users":1200,"criticality":'High',"dr":1,"eol":'2031-06',"pi_spi":0,"contract_end":'2027-06',"integration":8,"stack":'["SAP Fiori", "UI5", "ABAP"]',"capability":'UX Platform',"strategic":82,"persons":3,"src_avail":1,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'ABAP/UI5',"os":'SUSE Linux',"db_platform":'SAP HANA',"support":'Vendor+Inhouse',"owner":'Somchai K.',"stream":'Core Finance',"approach":'Upgrade',"assess_status":'Planned',"assess_date":'2025-03',"wave":2,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-098',"name":'GitLab DevSecOps',"domain":'Infrastructure',"vendor":'GitLab',"type":'Package',"status":'Active',"bcg":'Invest',"health":90,"tech_debt":8,"age":3,"tco":560,"users":280,"criticality":'High',"dr":1,"eol":'2032-12',"pi_spi":0,"contract_end":'2027-06',"integration":18,"stack":'["GitLab", "Docker", "Kubernetes"]',"capability":'DevSecOps Platform',"strategic":86,"persons":4,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sat 22:00-02:00',"lang":'YAML/Ruby',"os":'Linux (K8s)',"db_platform":'PostgreSQL',"support":'Vendor+Inhouse',"owner":'Nuttapon T.',"stream":'Platform Modernization',"approach":'Invest',"assess_status":'In Progress',"assess_date":'2025-01',"wave":1,"ea_group":'4. Support',"ea_category":'4.3 Corporate Application & Information Technology',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-099',"name":'Archer Risk Platform',"domain":'Security',"vendor":'RSA',"type":'Package',"status":'Active',"bcg":'Invest',"health":82,"tech_debt":16,"age":5,"tco":1200,"users":95,"criticality":'High',"dr":1,"eol":'2030-12',"pi_spi":1,"contract_end":'2027-12',"integration":12,"stack":'["Archer", "Java", "REST"]',"capability":'Risk Management',"strategic":88,"persons":3,"src_avail":0,"service_hour":'Business Hours',"maint_window":'Sun 02:00-06:00',"lang":'Java',"os":'Windows Server 2019',"db_platform":'SQL Server 2019',"support":'Vendor+Inhouse',"owner":'Nuntachai P.',"stream":'Platform Modernization',"approach":'Modernize',"assess_status":'Planned',"assess_date":'2025-04',"wave":2,"ea_group":'5. Governance',"ea_category":'5.2 Risk & Internal Control',"ea_sub_category":'-',"last_updated":'2025-01-01'},
        {"id":'APP-100',"name":'Digital Twin Platform',"domain":'Digital',"vendor":'Internal',"type":'Inhouse',"status":'Planned',"bcg":'Grow',"health":65,"tech_debt":30,"age":0,"tco":880,"users":0,"criticality":'Medium',"dr":0,"eol":'2033-12',"pi_spi":0,"contract_end":'N/A',"integration":8,"stack":'["Python", "IoT", "Azure Digital Twins", "React"]',"capability":'Digital Twin',"strategic":90,"persons":5,"src_avail":1,"service_hour":'Business Hours',"maint_window":'N/A',"lang":'Python',"os":'Azure Cloud',"db_platform":'Azure CosmosDB',"support":'Inhouse',"owner":'Thanakrit W.',"stream":'Data & AI',"approach":'Build',"assess_status":'Not Started',"assess_date":'',"wave":3,"ea_group":'4. Support',"ea_category":'4.2 Corporate Information',"ea_sub_category":'-',"last_updated":'2025-01-01'}
    ]

# ─── STARTUP (FastAPI lifecycle) ───────────────────────────────────────────────
app.add_middleware(OperationLogMiddleware)

@app.on_event("startup")
def _on_startup():
    init_audit_db()
    init_vendor_db()
    init_db()

# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print(f"\n{'='*55}")
    print(f"  {APP_NAME} EA Portfolio {APP_VERSION}")
    print(f"{'='*55}")
    print(f"  Config   : {_CONFIG_PATH}")
    print(f"  Users    : {_USERS_CONFIG_PATH} ({'AUTH ON' if _AUTH_ENABLED else 'AUTH OFF'})")
    print(f"  Frontend : http://localhost:{PORT}/")
    print(f"  API Docs : http://localhost:{PORT}/docs")
    print(f"  Database : {os.path.abspath(DB_PATH)}")
    print(f"  Audit DB : {os.path.abspath(AUDIT_DB_PATH)}")
    print(f"{'='*55}\n")
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=True, reload_excludes=["*.db"])
