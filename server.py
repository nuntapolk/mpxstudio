"""
MPX AppPort EA Portfolio — FastAPI + SQLite Backend
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
import json, os, sqlite3, uuid, time
import hmac, hashlib, base64, secrets
try:
    import requests as _requests_lib
    _NVD_AVAILABLE = True
except ImportError:
    _requests_lib = None
    _NVD_AVAILABLE = False
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import List, Optional, Any

try:
    from fastapi import FastAPI, HTTPException, Request, Depends
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

# ─── CONFIG — อ่านจาก mpx-studio.config.json ─────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mpx-studio.config.json")

def _load_config() -> dict:
    defaults = {
        "version":      "V001",
        "app_name":     "MPX AppPort",
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
APP_NAME     = CFG.get("app_name", "MPX AppPort")
APP_SUBTITLE = CFG.get("subtitle", "EA PORTFOLIO")

_BASE          = os.path.dirname(os.path.abspath(__file__))
DB_PATH        = os.path.join(_BASE, "appport.db")
AUDIT_DB_PATH  = os.path.join(_BASE, "appport_audit.db")
VENDOR_DB_PATH = os.path.join(_BASE, "vendor.db")
ESA_DB_PATH        = os.path.join(_BASE, "esa.db")
EA_DOMAINS_DB_PATH = os.path.join(_BASE, "ea_domains.db")
PORT               = int(os.environ.get("PORT", 8000))   # Railway injects $PORT automatically
STATIC_DIR     = os.path.join(_BASE, "static")

# ── Auth config ────────────────────────────────────────────────────────────────
import json as _json_mod
import threading

def _load_users_config():
    p = os.path.join(_BASE, "users.config.json")
    if not os.path.isfile(p):
        return None
    with open(p) as f:
        return _json_mod.load(f)

_UCFG = _load_users_config()
_AUTH_ENABLED = _UCFG is not None

# ── FIX #5: Warn on startup if JWT secret is default / not configured ─────────
_ALLOWED_ROLES = {"admin", "editor", "viewer", "vendor"}
_DEFAULT_JWT_SECRET = "dev-secret-change-me"
_jwt_secret_in_use = (_UCFG or {}).get("jwt_secret", _DEFAULT_JWT_SECRET)
if not _jwt_secret_in_use or _jwt_secret_in_use == _DEFAULT_JWT_SECRET:
    print("=" * 70)
    print("⚠️  SECURITY WARNING: JWT secret is not set or uses the default value.")
    print("   Set a strong 'jwt_secret' in users.config.json before production use.")
    print("=" * 70)

# ── FIX #3: Token blacklist — tokens added here are rejected even if not expired
_TOKEN_BLACKLIST: set = set()
_BLACKLIST_LOCK = threading.Lock()

def _blacklist_token(token: str) -> None:
    """Add token to blacklist and prune expired entries."""
    with _BLACKLIST_LOCK:
        _TOKEN_BLACKLIST.add(token)
        # Prune tokens whose exp has already passed
        now = datetime.now().timestamp()
        stale = set()
        for t in _TOKEN_BLACKLIST:
            try:
                _, b, _ = t.split(".")
                pad = 4 - len(b) % 4
                if pad != 4: b += "=" * pad
                payload = json.loads(base64.urlsafe_b64decode(b))
                if payload.get("exp", 0) < now:
                    stale.add(t)
            except Exception:
                stale.add(t)
        _TOKEN_BLACKLIST -= stale

# ── FIX #2: Login rate limiting (per username, in-memory) ─────────────────────
_FAILED_ATTEMPTS: dict = {}   # username -> [timestamps]
_ATTEMPTS_LOCK   = threading.Lock()
_MAX_ATTEMPTS    = 5
_LOCKOUT_WINDOW  = 15 * 60   # 15 minutes in seconds

def _check_login_rate(username: str) -> None:
    """Raise HTTP 429 if the username has too many recent failed attempts."""
    now = datetime.now().timestamp()
    with _ATTEMPTS_LOCK:
        recent = [t for t in _FAILED_ATTEMPTS.get(username, []) if now - t < _LOCKOUT_WINDOW]
        _FAILED_ATTEMPTS[username] = recent
        if len(recent) >= _MAX_ATTEMPTS:
            raise HTTPException(429, f"Account locked. Too many failed attempts. Try again in 15 minutes.")

def _record_failed_attempt(username: str) -> None:
    with _ATTEMPTS_LOCK:
        _FAILED_ATTEMPTS.setdefault(username, []).append(datetime.now().timestamp())

def _clear_failed_attempts(username: str) -> None:
    with _ATTEMPTS_LOCK:
        _FAILED_ATTEMPTS.pop(username, None)

def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64url_dec(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4: s += "=" * pad
    return base64.urlsafe_b64decode(s)

def _verify_password(plain: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        # format: pbkdf2_sha256$iters$<base64(salt)>$<base64(hash)>
        iters = int(parts[1])
        salt  = base64.b64decode(parts[2])   # decode from base64 → original salt bytes
        h     = parts[3]
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, iters)
        return hmac.compare_digest(base64.b64encode(dk).decode(), h)
    except Exception:
        return False

def _hash_password(plain: str, iters: int = 310000) -> str:
    """Hash a plaintext password using PBKDF2-SHA256. Returns pbkdf2_sha256$iters$b64(salt)$b64(hash)."""
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

# ── FIX #7: Password strength validation ──────────────────────────────────────
def _validate_password_strength(password: str) -> None:
    """Raise HTTP 400 if password is too weak."""
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        raise HTTPException(400, "Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise HTTPException(400, "Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise HTTPException(400, "Password must contain at least one digit")

def _create_jwt(payload: dict) -> str:
    secret = (_UCFG or {}).get("jwt_secret", _DEFAULT_JWT_SECRET)
    header  = _b64url_enc(b'{"alg":"HS256","typ":"JWT"}')
    body_b  = _b64url_enc(json.dumps(payload).encode())
    sig     = _b64url_enc(hmac.new(secret.encode(), f"{header}.{body_b}".encode(), hashlib.sha256).digest())
    return f"{header}.{body_b}.{sig}"

def _verify_jwt(token: str) -> Optional[dict]:
    try:
        # FIX #3: Reject blacklisted tokens immediately
        if token in _TOKEN_BLACKLIST:
            return None
        secret = (_UCFG or {}).get("jwt_secret", _DEFAULT_JWT_SECRET)
        h, b, s = token.split(".")
        expected = _b64url_enc(hmac.new(secret.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, expected): return None
        payload = json.loads(_b64url_dec(b))
        if payload.get("exp", 0) < datetime.now().timestamp(): return None
        return payload
    except Exception:
        return None

# ─── FASTAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = f"MPX AppPort EA Portfolio {APP_VERSION}",
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
AUDIT_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    log_id        TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    category      TEXT NOT NULL,   -- AUDIT | COMPLIANCE | OPERATION
    event_type    TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'INFO',
    actor_ip      TEXT,
    resource_type TEXT DEFAULT 'APP',  -- APP | VENDOR | ENGAGEMENT | PROJECT | SYSTEM
    resource_id   TEXT,
    before_state  TEXT,
    after_state   TEXT,
    risk_flags    TEXT,
    extra         TEXT,
    duration_ms   INTEGER,
    status_code   INTEGER,
    message       TEXT
);
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
        # Step 1: create table only (no indices yet — avoids "no such column" if DB is old)
        conn.executescript(AUDIT_DDL_TABLE)

        # Step 2: migrate missing columns BEFORE creating any index that references them
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "resource_type" not in existing_cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN resource_type TEXT DEFAULT 'APP'")
            conn.commit()
            print("  Migration: audit_log ← added column resource_type")

        # Step 3: create / ensure indices — all columns are guaranteed to exist now
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_restype  ON audit_log(resource_type)")
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

# ─── ESA DATABASE ──────────────────────────────────────────────────────────────
ESA_DDL = """
CREATE TABLE IF NOT EXISTS abb (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    criticality TEXT DEFAULT 'High',
    status      TEXT DEFAULT 'Required',
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS sbb (
    id              TEXT PRIMARY KEY,
    abb_id          TEXT NOT NULL REFERENCES abb(id),
    vendor_id       TEXT,
    product_name    TEXT NOT NULL,
    version         TEXT,
    deployment_type TEXT DEFAULT 'On-Premise',
    status          TEXT DEFAULT 'Active',
    note            TEXT,
    created_at      TEXT,
    updated_at      TEXT
);
CREATE TABLE IF NOT EXISTS abb_app_coverage (
    id             TEXT PRIMARY KEY,
    abb_id         TEXT NOT NULL REFERENCES abb(id),
    app_id         TEXT NOT NULL,
    sbb_id         TEXT,
    coverage_level TEXT DEFAULT 'None',
    note           TEXT,
    created_at     TEXT,
    updated_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sbb_abb       ON sbb(abb_id);
CREATE INDEX IF NOT EXISTS idx_cov_abb       ON abb_app_coverage(abb_id);
CREATE INDEX IF NOT EXISTS idx_cov_app       ON abb_app_coverage(app_id);
"""

# ─── EA DOMAINS DATABASE (ea_domains.db) ──────────────────────────────────────
EA_DOMAINS_DDL = """
-- ── EBA: Business Architecture ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bcap (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    priority    TEXT DEFAULT 'High',
    status      TEXT DEFAULT 'Active',
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS bprocess (
    id          TEXT PRIMARY KEY,
    bcap_id     TEXT NOT NULL REFERENCES bcap(id),
    name        TEXT NOT NULL,
    type        TEXT DEFAULT 'Core',
    framework   TEXT,
    description TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS bcap_app_map (
    id            TEXT PRIMARY KEY,
    bcap_id       TEXT NOT NULL REFERENCES bcap(id),
    app_id        TEXT NOT NULL,
    bprocess_id   TEXT,
    support_level TEXT DEFAULT 'None',
    note          TEXT,
    created_at    TEXT,
    updated_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_bprc_bcap ON bprocess(bcap_id);
CREATE INDEX IF NOT EXISTS idx_bcap_map_app ON bcap_app_map(app_id);

-- ── EDA: Data Architecture ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ddomain (
    id             TEXT PRIMARY KEY,
    domain         TEXT NOT NULL,
    name           TEXT NOT NULL,
    owner          TEXT,
    description    TEXT,
    classification TEXT DEFAULT 'Internal',
    status         TEXT DEFAULT 'Active',
    created_at     TEXT,
    updated_at     TEXT
);
CREATE TABLE IF NOT EXISTS dasset (
    id          TEXT PRIMARY KEY,
    ddomain_id  TEXT NOT NULL REFERENCES ddomain(id),
    name        TEXT NOT NULL,
    type        TEXT DEFAULT 'Database',
    platform    TEXT,
    status      TEXT DEFAULT 'Active',
    description TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS ddomain_app_map (
    id          TEXT PRIMARY KEY,
    ddomain_id  TEXT NOT NULL REFERENCES ddomain(id),
    app_id      TEXT NOT NULL,
    dasset_id   TEXT,
    role        TEXT DEFAULT 'None',
    note        TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_dasset_dom ON dasset(ddomain_id);
CREATE INDEX IF NOT EXISTS idx_dmap_app   ON ddomain_app_map(app_id);

-- ── EAA: Application Architecture ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS acap (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT DEFAULT 'Core',
    description TEXT,
    priority    TEXT DEFAULT 'High',
    status      TEXT DEFAULT 'Active',
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS appsys (
    id          TEXT PRIMARY KEY,
    acap_id     TEXT NOT NULL REFERENCES acap(id),
    name        TEXT NOT NULL,
    vendor      TEXT,
    status      TEXT DEFAULT 'Active',
    lifecycle   TEXT DEFAULT 'Current',
    description TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS acap_app_map (
    id          TEXT PRIMARY KEY,
    acap_id     TEXT NOT NULL REFERENCES acap(id),
    app_id      TEXT NOT NULL,
    appsys_id   TEXT,
    fit_level   TEXT DEFAULT 'None',
    note        TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_asys_acap ON appsys(acap_id);
CREATE INDEX IF NOT EXISTS idx_amap_app  ON acap_app_map(app_id);

-- ── ETA: Technology Architecture ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tstd (
    id           TEXT PRIMARY KEY,
    domain       TEXT NOT NULL,
    name         TEXT NOT NULL,
    radar_status TEXT DEFAULT 'Adopt',
    description  TEXT,
    lifecycle    TEXT DEFAULT 'Current',
    created_at   TEXT,
    updated_at   TEXT
);
CREATE TABLE IF NOT EXISTS tprod (
    id          TEXT PRIMARY KEY,
    tstd_id     TEXT NOT NULL REFERENCES tstd(id),
    name        TEXT NOT NULL,
    vendor      TEXT,
    version     TEXT,
    lifecycle   TEXT DEFAULT 'Current',
    status      TEXT DEFAULT 'Active',
    description TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS tstd_app_map (
    id          TEXT PRIMARY KEY,
    tstd_id     TEXT NOT NULL REFERENCES tstd(id),
    app_id      TEXT NOT NULL,
    tprod_id    TEXT,
    compliance  TEXT DEFAULT 'None',
    note        TEXT,
    created_at  TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_tprod_tstd ON tprod(tstd_id);
CREATE INDEX IF NOT EXISTS idx_tmap_app   ON tstd_app_map(app_id);

-- ── Tech Catalog (B32.43) ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_catalog (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    vendor          TEXT,
    category        TEXT,
    sub_category    TEXT,
    tier            TEXT DEFAULT 'Tier 2',
    standard_status TEXT DEFAULT 'Approved',
    website_url     TEXT,
    tags            TEXT,
    description     TEXT,
    created_by      TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tech_versions (
    id                TEXT PRIMARY KEY,
    tech_id           TEXT NOT NULL REFERENCES tech_catalog(id),
    version_label     TEXT NOT NULL,
    major             INTEGER,
    minor             INTEGER,
    patch             INTEGER,
    build             TEXT,
    release_type      TEXT DEFAULT 'GA',
    release_date      TEXT,
    eol_date          TEXT,
    ext_support_end   TEXT,
    lifecycle_phase   TEXT DEFAULT 'Active',
    release_notes_url TEXT,
    is_latest         INTEGER DEFAULT 0,
    is_lts            INTEGER DEFAULT 0,
    created_at        TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tv_tech ON tech_versions(tech_id);
CREATE TABLE IF NOT EXISTS tech_servers (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    ip_address  TEXT,
    environment TEXT DEFAULT 'Production',
    server_type TEXT,
    location    TEXT,
    os_name     TEXT,
    os_version  TEXT,
    cpu_core    INTEGER,
    ram_gb      INTEGER,
    managed_by  TEXT,
    status      TEXT DEFAULT 'Active',
    note        TEXT,
    created_by  TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tech_usage (
    id                TEXT PRIMARY KEY,
    tech_id           TEXT NOT NULL REFERENCES tech_catalog(id),
    version_id        TEXT REFERENCES tech_versions(id),
    usage_target_type TEXT DEFAULT 'App',
    app_id            TEXT,
    server_id         TEXT REFERENCES tech_servers(id),
    environment       TEXT DEFAULT 'Production',
    usage_type        TEXT,
    installed_version TEXT,
    install_date      TEXT,
    upgrade_plan      TEXT,
    note              TEXT,
    created_by        TEXT,
    created_at        TEXT DEFAULT (datetime('now')),
    updated_at        TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tu_tech ON tech_usage(tech_id);
CREATE INDEX IF NOT EXISTS idx_tu_app  ON tech_usage(app_id);
CREATE INDEX IF NOT EXISTS idx_tu_srv  ON tech_usage(server_id);
CREATE TABLE IF NOT EXISTS tech_vulnerabilities (
    id               TEXT PRIMARY KEY,
    tech_id          TEXT NOT NULL REFERENCES tech_catalog(id),
    version_id       TEXT REFERENCES tech_versions(id),
    cve_id           TEXT UNIQUE,
    severity         TEXT,
    cvss_score       REAL,
    title            TEXT,
    description      TEXT,
    affected_versions TEXT,
    fixed_in_version TEXT,
    published_date   TEXT,
    nvd_url          TEXT,
    status           TEXT DEFAULT 'Open',
    remediation      TEXT,
    remediation_date TEXT,
    assigned_to      TEXT,
    source           TEXT DEFAULT 'NVD',
    fetched_at       TEXT,
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tvl_tech ON tech_vulnerabilities(tech_id);
CREATE INDEX IF NOT EXISTS idx_tvl_cve  ON tech_vulnerabilities(cve_id);
CREATE TABLE IF NOT EXISTS tech_radar (
    id         TEXT PRIMARY KEY,
    tech_id    TEXT NOT NULL REFERENCES tech_catalog(id),
    radar_date TEXT NOT NULL,
    ring       TEXT NOT NULL,
    quadrant   TEXT,
    rationale  TEXT,
    decided_by TEXT,
    prev_ring  TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tr_tech ON tech_radar(tech_id);
"""

# ── EBA Seed ──────────────────────────────────────────────────────────────────
_EBA_SEED_BCAP = [
    # Customer (6)
    ("BCAP-001","Customer","Customer Acquisition","กระบวนการหาลูกค้าใหม่ตั้งแต่ Lead จนถึง Prospect","High","Active"),
    ("BCAP-002","Customer","Customer Onboarding","กระบวนการรับลูกค้าใหม่และ KYC","High","Active"),
    ("BCAP-003","Customer","Customer Service Management","การจัดการบริการและ SLA ลูกค้า","High","Active"),
    ("BCAP-004","Customer","Customer Retention","การรักษาลูกค้าและป้องกัน Churn","Medium","Active"),
    ("BCAP-005","Customer","Customer Analytics","การวิเคราะห์ข้อมูลและ Segmentation ลูกค้า","Medium","Active"),
    ("BCAP-006","Customer","CRM & Relationship","การจัดการ Account, Contact และ Opportunity","High","Active"),
    # Finance (6)
    ("BCAP-007","Finance","Financial Planning & Budgeting","การวางแผนงบประมาณและ Rolling Forecast","Critical","Active"),
    ("BCAP-008","Finance","Revenue Management","การจัดการ Revenue Recognition และ Billing","Critical","Active"),
    ("BCAP-009","Finance","Cost Management","การจัดสรรต้นทุนและควบคุมค่าใช้จ่าย","High","Active"),
    ("BCAP-010","Finance","Financial Reporting","การจัดทำรายงานการเงินและ Regulatory Reporting","Critical","Active"),
    ("BCAP-011","Finance","Treasury & Cash Management","การจัดการกระแสเงินสดและการชำระเงิน","High","Active"),
    ("BCAP-012","Finance","Tax Management","การปฏิบัติตามกฎหมายภาษีและ Transfer Pricing","High","Active"),
    # HR (5)
    ("BCAP-013","HR","Talent Acquisition","การสรรหาและคัดเลือกบุคลากร","High","Active"),
    ("BCAP-014","HR","Employee Lifecycle Management","การจัดการตลอด Employee Journey","High","Active"),
    ("BCAP-015","HR","Performance Management","การตั้งเป้าหมายและประเมินผลงาน","Medium","Active"),
    ("BCAP-016","HR","Learning & Development","การฝึกอบรมและพัฒนาศักยภาพบุคลากร","Medium","Active"),
    ("BCAP-017","HR","Compensation & Benefits","การจัดการเงินเดือน สวัสดิการ และ Incentive","High","Active"),
    # Operations (6)
    ("BCAP-018","Operations","Service Delivery Management","การส่งมอบบริการและติดตาม SLA","High","Active"),
    ("BCAP-019","Operations","Process Automation","การทำ RPA และ Workflow Automation","Medium","Active"),
    ("BCAP-020","Operations","Quality Management","การประกันและควบคุมคุณภาพ","High","Active"),
    ("BCAP-021","Operations","Vendor Management","การคัดเลือกและบริหาร Vendor","Medium","Active"),
    ("BCAP-022","Operations","Facilities & Asset Management","การจัดการสินทรัพย์และสถานที่","Low","Active"),
    ("BCAP-023","Operations","Business Continuity","การวางแผน BCP และ Disaster Recovery","Critical","Active"),
    # Strategy (4)
    ("BCAP-024","Strategy","Strategic Planning","การกำหนดกลยุทธ์และ OKR ระดับองค์กร","High","Active"),
    ("BCAP-025","Strategy","Innovation Management","การจัดการ Idea และ Innovation Portfolio","Medium","Active"),
    ("BCAP-026","Strategy","Portfolio Management","การจัดลำดับความสำคัญการลงทุน IT","High","Active"),
    ("BCAP-027","Strategy","EA Governance","การกำกับ Architecture Review Board","High","Active"),
    # Digital (5)
    ("BCAP-028","Digital","Digital Channel Management","การจัดการช่องทาง Web, Mobile, Social","High","Active"),
    ("BCAP-029","Digital","Digital Product Development","Agile delivery และ Product Launch","High","Active"),
    ("BCAP-030","Digital","Data & Analytics Capability","Data Strategy และ Analytics Delivery","High","Active"),
    ("BCAP-031","Digital","Cloud & Platform Management","Cloud Governance และ Platform Engineering","High","Active"),
    ("BCAP-032","Digital","Cybersecurity Management","Security Operations และ Risk Management","Critical","Active"),
    # Supply Chain (4)
    ("BCAP-033","Supply Chain","Procurement Management","การจัดซื้อจัดหาตั้งแต่ Sourcing ถึง Payment","High","Active"),
    ("BCAP-034","Supply Chain","Inventory Management","การวางแผนและควบคุม Inventory","Medium","Active"),
    ("BCAP-035","Supply Chain","Logistics & Distribution","การขนส่งและ Last Mile Delivery","Medium","Active"),
    ("BCAP-036","Supply Chain","Demand Planning","การพยากรณ์ความต้องการและ S&OP","High","Active"),
    # Governance (4)
    ("BCAP-037","Governance","Risk Management","การระบุ ประเมิน และบรรเทาความเสี่ยง","Critical","Active"),
    ("BCAP-038","Governance","Compliance & Regulatory","การปฏิบัติตาม Policy และ Regulation","Critical","Active"),
    ("BCAP-039","Governance","Legal & Contract Management","การจัดการสัญญาและกฎหมาย","High","Active"),
    ("BCAP-040","Governance","Corporate Governance","การกำกับดูแลกิจการและ Board Management","High","Active"),
]

_EBA_SEED_BPROCESS = [
    # BCAP-001 Customer Acquisition
    ("BPRC-001","BCAP-001","Lead Generation & Nurturing","Core","APQC","การสร้างและบ่ม Lead จากช่องทางต่างๆ"),
    ("BPRC-002","BCAP-001","Digital Marketing Campaign","Core","APQC","การทำ Campaign ผ่านช่องทาง Digital"),
    ("BPRC-003","BCAP-001","Partner & Referral Management","Support","APQC","การจัดการ Partner Channel และ Referral Program"),
    # BCAP-002 Customer Onboarding
    ("BPRC-004","BCAP-002","KYC & Identity Verification","Core","APQC","การตรวจสอบตัวตนลูกค้า"),
    ("BPRC-005","BCAP-002","Digital Onboarding","Core","APQC","การ Onboard ลูกค้าผ่านช่องทาง Digital"),
    ("BPRC-006","BCAP-002","Account & Contract Activation","Support","APQC","การเปิดใช้งาน Account และสัญญา"),
    # BCAP-003 Customer Service
    ("BPRC-007","BCAP-003","Service Request Handling","Core","APQC","การรับและจัดการคำร้องบริการ"),
    ("BPRC-008","BCAP-003","Complaint Resolution","Core","APQC","การแก้ไขข้อร้องเรียนของลูกค้า"),
    ("BPRC-009","BCAP-003","SLA Monitoring & Reporting","Support","APQC","การติดตามและรายงาน SLA"),
    # BCAP-004 Customer Retention
    ("BPRC-010","BCAP-004","Loyalty Program Management","Core","APQC","การบริหารโปรแกรมสะสมคะแนนและสิทธิพิเศษ"),
    ("BPRC-011","BCAP-004","Churn Prediction & Prevention","Core","APQC","การพยากรณ์และป้องกันการสูญเสียลูกค้า"),
    ("BPRC-012","BCAP-004","Win-back Campaign","Support","APQC","การดึงลูกค้าที่หายไปกลับมา"),
    # BCAP-005 Customer Analytics
    ("BPRC-013","BCAP-005","Customer Segmentation","Core","APQC","การแบ่งกลุ่มลูกค้าตาม Behavior และ Profile"),
    ("BPRC-014","BCAP-005","Behavioral Analysis","Core","APQC","การวิเคราะห์พฤติกรรมลูกค้า"),
    ("BPRC-015","BCAP-005","NPS & Satisfaction Tracking","Support","APQC","การวัด NPS และความพึงพอใจ"),
    # BCAP-006 CRM
    ("BPRC-016","BCAP-006","Account & Contact Management","Core","APQC","การจัดการข้อมูล Account และ Contact"),
    ("BPRC-017","BCAP-006","Opportunity & Pipeline Management","Core","APQC","การจัดการ Sales Pipeline"),
    ("BPRC-018","BCAP-006","Sales Forecasting","Support","APQC","การพยากรณ์ยอดขาย"),
    # BCAP-007 Financial Planning
    ("BPRC-019","BCAP-007","Annual Budget Planning","Core","COSO","การวางแผนงบประมาณประจำปี"),
    ("BPRC-020","BCAP-007","Rolling Forecast","Core","COSO","การจัดทำ Rolling Forecast รายไตรมาส"),
    ("BPRC-021","BCAP-007","Variance Analysis","Support","COSO","การวิเคราะห์ความแตกต่างจากแผน"),
    # BCAP-008 Revenue Management
    ("BPRC-022","BCAP-008","Revenue Recognition","Core","IFRS15","การรับรู้รายได้ตามมาตรฐาน IFRS 15"),
    ("BPRC-023","BCAP-008","Billing & Invoicing","Core","APQC","การออกใบแจ้งหนี้และเรียกเก็บเงิน"),
    ("BPRC-024","BCAP-008","Price & Discount Management","Support","APQC","การจัดการราคาและส่วนลด"),
    # BCAP-009 Cost Management
    ("BPRC-025","BCAP-009","Cost Allocation & Transfer","Core","COSO","การจัดสรรต้นทุนระหว่าง Cost Center"),
    ("BPRC-026","BCAP-009","Expense Control & Reporting","Core","APQC","การควบคุมและรายงานค่าใช้จ่าย"),
    ("BPRC-027","BCAP-009","Cost Optimization Analysis","Support","APQC","การวิเคราะห์โอกาสลดต้นทุน"),
    # BCAP-010 Financial Reporting
    ("BPRC-028","BCAP-010","Financial Statement Preparation","Core","IFRS","การจัดทำงบการเงิน"),
    ("BPRC-029","BCAP-010","Regulatory Reporting","Core","BOT","การรายงานต่อ Regulator"),
    ("BPRC-030","BCAP-010","Management Reporting","Support","APQC","การจัดทำรายงานผู้บริหาร"),
    # BCAP-011 Treasury
    ("BPRC-031","BCAP-011","Cash Flow Forecasting","Core","APQC","การพยากรณ์กระแสเงินสด"),
    ("BPRC-032","BCAP-011","Payment Processing","Core","APQC","การประมวลผลการชำระเงิน"),
    ("BPRC-033","BCAP-011","Bank Reconciliation","Support","APQC","การกระทบยอดบัญชีธนาคาร"),
    # BCAP-012 Tax
    ("BPRC-034","BCAP-012","Tax Compliance Filing","Core","RD","การยื่นแบบภาษีตามกฎหมาย"),
    ("BPRC-035","BCAP-012","Tax Planning","Core","APQC","การวางแผนภาษี"),
    ("BPRC-036","BCAP-012","Transfer Pricing Documentation","Support","OECD","การจัดทำเอกสาร Transfer Pricing"),
    # BCAP-013 Talent Acquisition
    ("BPRC-037","BCAP-013","Job Requisition & Approval","Core","APQC","การขออัตรากำลังและอนุมัติ"),
    ("BPRC-038","BCAP-013","Candidate Sourcing & Screening","Core","APQC","การสรรหาและกลั่นกรองผู้สมัคร"),
    ("BPRC-039","BCAP-013","Offer & Onboarding","Support","APQC","การเสนอและรับพนักงานใหม่"),
    # BCAP-014 Employee Lifecycle
    ("BPRC-040","BCAP-014","New Employee Onboarding","Core","APQC","การ Onboard พนักงานใหม่"),
    ("BPRC-041","BCAP-014","Internal Transfer & Promotion","Core","APQC","การโยกย้ายและเลื่อนตำแหน่ง"),
    ("BPRC-042","BCAP-014","Offboarding & Exit Management","Support","APQC","การออกจากงานและ Exit Interview"),
    # BCAP-015 Performance Management
    ("BPRC-043","BCAP-015","Goal Setting & OKR","Core","OKR","การตั้งเป้าหมายและ KPI รายบุคคล"),
    ("BPRC-044","BCAP-015","Performance Review Cycle","Core","APQC","รอบการประเมินผลงาน"),
    ("BPRC-045","BCAP-015","Calibration & Ranking","Support","APQC","การ Calibrate และ Rank พนักงาน"),
    # BCAP-016 L&D
    ("BPRC-046","BCAP-016","Training Needs Analysis","Core","APQC","การวิเคราะห์ความต้องการฝึกอบรม"),
    ("BPRC-047","BCAP-016","Learning Program Delivery","Core","APQC","การจัดการฝึกอบรมและ E-Learning"),
    ("BPRC-048","BCAP-016","Certification & Competency Tracking","Support","APQC","การติดตาม Certificate และ Competency"),
    # BCAP-017 Compensation
    ("BPRC-049","BCAP-017","Payroll Processing","Core","APQC","การประมวลผลเงินเดือนและภาษีหัก ณ ที่จ่าย"),
    ("BPRC-050","BCAP-017","Benefits Administration","Core","APQC","การจัดการสวัสดิการพนักงาน"),
    ("BPRC-051","BCAP-017","Incentive & Bonus Management","Support","APQC","การจัดการ Incentive และโบนัส"),
    # BCAP-018 Service Delivery
    ("BPRC-052","BCAP-018","Service Request Fulfillment","Core","ITIL","การดำเนินการตาม Service Request"),
    ("BPRC-053","BCAP-018","SLA Monitoring","Core","ITIL","การติดตาม SLA และ KPI บริการ"),
    ("BPRC-054","BCAP-018","Escalation Management","Support","ITIL","การจัดการ Escalation"),
    # BCAP-019 Process Automation
    ("BPRC-055","BCAP-019","RPA Implementation","Core","Custom","การนำ RPA มาใช้ใน Process ซ้ำซาก"),
    ("BPRC-056","BCAP-019","Workflow Automation","Core","BPMN","การทำ Workflow Automation"),
    ("BPRC-057","BCAP-019","Process Monitoring & Analytics","Support","Custom","การติดตามประสิทธิภาพ Process"),
    # BCAP-020 Quality
    ("BPRC-058","BCAP-020","Quality Assurance","Core","ISO9001","การประกันคุณภาพ"),
    ("BPRC-059","BCAP-020","Quality Control & Testing","Core","ISO9001","การตรวจสอบและทดสอบคุณภาพ"),
    ("BPRC-060","BCAP-020","Continual Improvement","Support","ISO9001","การปรับปรุงกระบวนการอย่างต่อเนื่อง"),
    # BCAP-021 Vendor
    ("BPRC-061","BCAP-021","Vendor Selection & Due Diligence","Core","APQC","การคัดเลือกและตรวจสอบ Vendor"),
    ("BPRC-062","BCAP-021","Contract Negotiation & Signing","Core","APQC","การเจรจาและทำสัญญากับ Vendor"),
    ("BPRC-063","BCAP-021","Vendor Performance Review","Support","APQC","การประเมิน Vendor ประจำปี"),
    # BCAP-022 Facilities
    ("BPRC-064","BCAP-022","Asset Registration & Tracking","Core","ISO55000","การลงทะเบียนและติดตามสินทรัพย์"),
    ("BPRC-065","BCAP-022","Maintenance Scheduling","Core","ISO55000","การวางแผน Maintenance"),
    ("BPRC-066","BCAP-022","Space & Facilities Management","Support","Custom","การจัดการพื้นที่และสิ่งอำนวยความสะดวก"),
    # BCAP-023 BCP
    ("BPRC-067","BCAP-023","BCP Planning & Testing","Core","ISO22301","การวางแผนและทดสอบ BCP"),
    ("BPRC-068","BCAP-023","Disaster Recovery","Core","ISO22301","การกู้คืนระบบจาก Disaster"),
    ("BPRC-069","BCAP-023","Crisis Communication","Support","ISO22301","การสื่อสารในภาวะวิกฤต"),
    # BCAP-024 Strategic Planning
    ("BPRC-070","BCAP-024","Strategy Formulation","Core","BSC","การกำหนดกลยุทธ์องค์กร"),
    ("BPRC-071","BCAP-024","OKR Cascade & Alignment","Core","OKR","การ Cascade OKR จาก Corporate สู่ Team"),
    ("BPRC-072","BCAP-024","Strategic Review & Adjustment","Support","BSC","การทบทวนและปรับกลยุทธ์"),
    # BCAP-025 Innovation
    ("BPRC-073","BCAP-025","Idea Management","Core","Custom","การรวบรวมและ Screen Idea"),
    ("BPRC-074","BCAP-025","Innovation Portfolio Management","Core","Custom","การบริหาร Innovation Pipeline"),
    ("BPRC-075","BCAP-025","POC & Experiment Management","Support","Design Thinking","การทำ POC และ Experiment"),
    # BCAP-026 Portfolio
    ("BPRC-076","BCAP-026","Investment Prioritization","Core","MoSCoW","การจัดลำดับความสำคัญการลงทุน"),
    ("BPRC-077","BCAP-026","Portfolio Review","Core","APQC","การทบทวน IT Portfolio"),
    ("BPRC-078","BCAP-026","Benefits Realization","Support","MSP","การวัดผลประโยชน์ที่ได้รับ"),
    # BCAP-027 EA Governance
    ("BPRC-079","BCAP-027","Architecture Review Board","Core","TOGAF","การบริหาร ARB"),
    ("BPRC-080","BCAP-027","EA Standards Management","Core","TOGAF","การจัดการมาตรฐาน Architecture"),
    ("BPRC-081","BCAP-027","Waiver & Exception Management","Support","TOGAF","การจัดการ Waiver"),
    # BCAP-028 Digital Channel
    ("BPRC-082","BCAP-028","Web Presence Management","Core","Custom","การจัดการ Website และ SEO"),
    ("BPRC-083","BCAP-028","Mobile App Management","Core","Custom","การจัดการ Mobile Application"),
    ("BPRC-084","BCAP-028","Social Media Management","Support","Custom","การจัดการ Social Media"),
    # BCAP-029 Digital Product
    ("BPRC-085","BCAP-029","Product Discovery","Core","Design Thinking","การค้นหาโอกาสและ Problem-Solution Fit"),
    ("BPRC-086","BCAP-029","Agile Delivery","Core","Scrum","การพัฒนาผลิตภัณฑ์แบบ Agile"),
    ("BPRC-087","BCAP-029","Product Launch & Go-to-Market","Support","Custom","การ Launch Product"),
    # BCAP-030 Data Capability
    ("BPRC-088","BCAP-030","Data Strategy & Governance","Core","DAMA","การกำหนด Data Strategy"),
    ("BPRC-089","BCAP-030","Analytics Product Delivery","Core","Custom","การส่งมอบ Analytics Product"),
    ("BPRC-090","BCAP-030","Data Monetization","Support","Custom","การสร้างรายได้จากข้อมูล"),
    # BCAP-031 Cloud
    ("BPRC-091","BCAP-031","Cloud Governance & FinOps","Core","FinOps","การกำกับ Cloud และควบคุมต้นทุน"),
    ("BPRC-092","BCAP-031","Platform Engineering","Core","Custom","การสร้าง Internal Developer Platform"),
    ("BPRC-093","BCAP-031","Cloud Cost Optimization","Support","FinOps","การ Optimize ค่าใช้จ่าย Cloud"),
    # BCAP-032 Cybersecurity
    ("BPRC-094","BCAP-032","Security Operations","Core","NIST CSF","การดำเนินการ SOC"),
    ("BPRC-095","BCAP-032","Cyber Risk Management","Core","ISO27005","การจัดการความเสี่ยง Cyber"),
    ("BPRC-096","BCAP-032","Security Compliance","Support","ISO27001","การปฏิบัติตามมาตรฐาน Security"),
    # BCAP-033 Procurement
    ("BPRC-097","BCAP-033","Strategic Sourcing","Core","APQC","การจัดซื้อเชิงกลยุทธ์"),
    ("BPRC-098","BCAP-033","Purchase Order Management","Core","APQC","การบริหาร PO"),
    ("BPRC-099","BCAP-033","Invoice & Payment Processing","Support","APQC","การประมวลผล Invoice"),
    # BCAP-034 Inventory
    ("BPRC-100","BCAP-034","Inventory Planning","Core","APQC","การวางแผน Inventory"),
    ("BPRC-101","BCAP-034","Stock Control & Replenishment","Core","APQC","การควบคุมและเติม Stock"),
    ("BPRC-102","BCAP-034","Warehouse Management","Support","APQC","การบริหารคลังสินค้า"),
    # BCAP-035 Logistics
    ("BPRC-103","BCAP-035","Shipment Planning","Core","APQC","การวางแผนการขนส่ง"),
    ("BPRC-104","BCAP-035","Carrier & 3PL Management","Core","APQC","การบริหาร Carrier"),
    ("BPRC-105","BCAP-035","Last Mile Delivery","Support","Custom","การส่งสินค้าถึงลูกค้า"),
    # BCAP-036 Demand Planning
    ("BPRC-106","BCAP-036","Demand Forecasting","Core","APQC","การพยากรณ์ความต้องการ"),
    ("BPRC-107","BCAP-036","S&OP Process","Core","APQC","กระบวนการ Sales & Operations Planning"),
    ("BPRC-108","BCAP-036","Capacity Planning","Support","APQC","การวางแผนกำลังการผลิต"),
    # BCAP-037 Risk
    ("BPRC-109","BCAP-037","Risk Identification & Assessment","Core","ISO31000","การระบุและประเมินความเสี่ยง"),
    ("BPRC-110","BCAP-037","Risk Treatment & Mitigation","Core","ISO31000","การบรรเทาความเสี่ยง"),
    ("BPRC-111","BCAP-037","Risk Monitoring & Reporting","Support","ISO31000","การติดตามและรายงานความเสี่ยง"),
    # BCAP-038 Compliance
    ("BPRC-112","BCAP-038","Policy Management","Core","Custom","การจัดการ Policy องค์กร"),
    ("BPRC-113","BCAP-038","Regulatory Monitoring","Core","Custom","การติดตามการเปลี่ยนแปลง Regulation"),
    ("BPRC-114","BCAP-038","Internal Audit","Support","IIA","การตรวจสอบภายใน"),
    # BCAP-039 Legal
    ("BPRC-115","BCAP-039","Contract Drafting & Review","Core","Custom","การร่างและตรวจสอบสัญญา"),
    ("BPRC-116","BCAP-039","Legal Due Diligence","Core","Custom","การตรวจสอบสถานะทางกฎหมาย"),
    ("BPRC-117","BCAP-039","Contract Repository & Tracking","Support","Custom","การจัดเก็บและติดตามสัญญา"),
    # BCAP-040 Corporate Governance
    ("BPRC-118","BCAP-040","Board Meeting Management","Core","CG Code","การจัดการประชุมคณะกรรมการ"),
    ("BPRC-119","BCAP-040","Disclosure & Investor Relations","Core","SEC","การเปิดเผยข้อมูลต่อผู้ถือหุ้น"),
    ("BPRC-120","BCAP-040","Annual General Meeting","Support","CG Code","การจัดประชุมผู้ถือหุ้น"),
]

# ── EDA Seed ──────────────────────────────────────────────────────────────────
_EDA_SEED_DDOMAIN = [
    # Master Data (6)
    ("DDOM-001","Master Data","Customer Master","CRM Team","ข้อมูลหลักของลูกค้า","Internal","Active"),
    ("DDOM-002","Master Data","Product & Service Master","Product Team","ข้อมูลหลักของผลิตภัณฑ์และบริการ","Internal","Active"),
    ("DDOM-003","Master Data","Employee Master","HR Team","ข้อมูลหลักของพนักงาน","Confidential","Active"),
    ("DDOM-004","Master Data","Vendor & Partner Master","Procurement","ข้อมูลหลักของ Vendor และ Partner","Internal","Active"),
    ("DDOM-005","Master Data","Chart of Accounts","Finance Team","ผังบัญชีและ Cost Center","Confidential","Active"),
    ("DDOM-006","Master Data","Location & Geography","Operations","ข้อมูลสถานที่และภูมิศาสตร์","Internal","Active"),
    # Transactional (6)
    ("DDOM-007","Transactional","Sales & Order Data","Sales Team","ข้อมูลคำสั่งซื้อและการขาย","Internal","Active"),
    ("DDOM-008","Transactional","Financial Transactions","Finance Team","รายการบัญชีและการชำระเงิน","Confidential","Active"),
    ("DDOM-009","Transactional","HR Transactions","HR Team","การประมวลผลเงินเดือนและการลา","Confidential","Active"),
    ("DDOM-010","Transactional","Procurement Transactions","Procurement","ข้อมูล PO และ Invoice","Internal","Active"),
    ("DDOM-011","Transactional","Service & Support Tickets","IT Team","ข้อมูล Service Request และ Incident","Internal","Active"),
    ("DDOM-012","Transactional","Digital Activity Data","Digital Team","Clickstream และ Event ดิจิทัล","Internal","Active"),
    # Analytical (5)
    ("DDOM-013","Analytical","Customer Intelligence","Data Team","ข้อมูลวิเคราะห์ลูกค้าเชิงลึก","Internal","Active"),
    ("DDOM-014","Analytical","Financial Analytics","Finance Team","ข้อมูลวิเคราะห์การเงิน","Confidential","Active"),
    ("DDOM-015","Analytical","Operational KPIs","Operations","ข้อมูล KPI การดำเนินงาน","Internal","Active"),
    ("DDOM-016","Analytical","Risk & Fraud Analytics","Risk Team","ข้อมูลวิเคราะห์ความเสี่ยงและ Fraud","Confidential","Active"),
    ("DDOM-017","Analytical","Business Intelligence Mart","Data Team","Data Mart สำหรับ BI และ Reporting","Internal","Active"),
    # Reference Data (4)
    ("DDOM-018","Reference Data","Currency & Exchange Rates","Finance Team","อัตราแลกเปลี่ยนและสกุลเงิน","Public","Active"),
    ("DDOM-019","Reference Data","Industry Codes & Standards","Governance","รหัสอุตสาหกรรมและมาตรฐาน","Public","Active"),
    ("DDOM-020","Reference Data","Regulatory Reference","Compliance","ข้อมูลอ้างอิง Regulation","Internal","Active"),
    ("DDOM-021","Reference Data","Product Classification","Product Team","การจัดหมวดหมู่ผลิตภัณฑ์","Internal","Active"),
    # Operational (5)
    ("DDOM-022","Operational","IT Asset & CMDB","IT Team","ฐานข้อมูล Configuration สินทรัพย์ IT","Internal","Active"),
    ("DDOM-023","Operational","Application Logs & Events","IT Team","Log และ Event ของระบบ","Internal","Active"),
    ("DDOM-024","Operational","Infrastructure Metrics","IT Team","Metrics ของ Infrastructure","Internal","Active"),
    ("DDOM-025","Operational","Security Events","Security Team","เหตุการณ์ Security และ Threat","Restricted","Active"),
    ("DDOM-026","Operational","API & Integration Data","IT Team","Log การเชื่อมต่อ API","Internal","Active"),
    # External (4)
    ("DDOM-027","External Data","Market & Competitive Data","Strategy","ข้อมูลตลาดและคู่แข่ง","Internal","Active"),
    ("DDOM-028","External Data","Social & Sentiment Data","Digital Team","ข้อมูล Social Media และ Sentiment","Internal","Active"),
    ("DDOM-029","External Data","Third-Party Enrichment","Data Team","ข้อมูลเสริมจากภายนอก","Internal","Active"),
    ("DDOM-030","External Data","Open & Government Data","Data Team","ข้อมูลสาธารณะและข้อมูลภาครัฐ","Public","Active"),
]

_EDA_SEED_DASSET = [
    ("DAST-001","DDOM-001","Customer Master DB","Database","Oracle DB","Active","ฐานข้อมูลหลักลูกค้า"),
    ("DAST-002","DDOM-001","MDM Platform","MDM","Informatica MDM","Active","Master Data Management Platform"),
    ("DAST-003","DDOM-001","Customer API Hub","API","MuleSoft","Active","API สำหรับเข้าถึงข้อมูลลูกค้า"),
    ("DAST-004","DDOM-002","Product Catalog DB","Database","PostgreSQL","Active","ฐานข้อมูล Product Catalog"),
    ("DAST-005","DDOM-002","PIM System","Database","Akeneo PIM","Active","Product Information Management"),
    ("DAST-006","DDOM-002","Product API","API","Kong Gateway","Active","API ผลิตภัณฑ์"),
    ("DAST-007","DDOM-003","HR Core DB","Database","Oracle HCM DB","Active","ฐานข้อมูลหลัก HR"),
    ("DAST-008","DDOM-003","Employee Directory","API","Azure AD","Active","Directory พนักงาน"),
    ("DAST-009","DDOM-003","Org Chart Service","API","Workday API","Active","Org Chart Service"),
    ("DAST-010","DDOM-004","Vendor DB","Database","PostgreSQL","Active","ฐานข้อมูล Vendor"),
    ("DAST-011","DDOM-004","Partner Portal DB","Database","MySQL","Active","ฐานข้อมูล Partner Portal"),
    ("DAST-012","DDOM-004","Supplier API","API","SAP Ariba API","Active","API Supplier"),
    ("DAST-013","DDOM-005","GL Master DB","Database","SAP HANA","Active","ฐานข้อมูล General Ledger"),
    ("DAST-014","DDOM-005","Account Hierarchy Service","API","SAP MDG","Active","บริการโครงสร้างบัญชี"),
    ("DAST-015","DDOM-005","Finance API","API","Internal API","Active","API การเงิน"),
    ("DAST-016","DDOM-006","Location DB","Database","PostgreSQL + PostGIS","Active","ฐานข้อมูล Location"),
    ("DAST-017","DDOM-006","GIS Platform","Database","Esri ArcGIS","Active","ระบบ GIS"),
    ("DAST-018","DDOM-006","Address Service","API","Google Maps API","Active","บริการ Address Validation"),
    ("DAST-019","DDOM-007","Order Management DB","Database","Oracle DB","Active","ฐานข้อมูล Order"),
    ("DAST-020","DDOM-007","CRM Transactions","Database","Salesforce DB","Active","ข้อมูล CRM Transactions"),
    ("DAST-021","DDOM-007","Sales API","API","Internal API","Active","API Sales"),
    ("DAST-022","DDOM-008","General Ledger DB","Database","SAP HANA","Active","ฐานข้อมูล GL"),
    ("DAST-023","DDOM-008","Payment Gateway DB","Database","MySQL","Active","ฐานข้อมูล Payment"),
    ("DAST-024","DDOM-008","Financial Events","Event Stream","Apache Kafka","Active","Financial Event Stream"),
    ("DAST-025","DDOM-009","Payroll DB","Database","Oracle Payroll DB","Active","ฐานข้อมูลเงินเดือน"),
    ("DAST-026","DDOM-009","Leave Management DB","Database","PostgreSQL","Active","ฐานข้อมูลการลา"),
    ("DAST-027","DDOM-009","HR Events","Event Stream","Kafka","Active","HR Event Stream"),
    ("DAST-028","DDOM-010","Purchase Order DB","Database","SAP S/4HANA DB","Active","ฐานข้อมูล PO"),
    ("DAST-029","DDOM-010","Invoice DB","Database","PostgreSQL","Active","ฐานข้อมูล Invoice"),
    ("DAST-030","DDOM-010","Spend Analytics DB","Data Warehouse","Snowflake","Active","ข้อมูลวิเคราะห์การจัดซื้อ"),
    ("DAST-031","DDOM-011","ITSM DB","Database","ServiceNow DB","Active","ฐานข้อมูล ITSM"),
    ("DAST-032","DDOM-011","Case Management DB","Database","Zendesk DB","Active","ฐานข้อมูล Case"),
    ("DAST-033","DDOM-011","Service Events","Event Stream","Kafka","Active","Service Event Stream"),
    ("DAST-034","DDOM-012","Clickstream DB","Data Lake","AWS S3","Active","ข้อมูล Clickstream"),
    ("DAST-035","DDOM-012","Session DB","Database","Redis","Active","ฐานข้อมูล Session"),
    ("DAST-036","DDOM-012","Digital Event Stream","Event Stream","Kafka","Active","Digital Activity Events"),
    ("DAST-037","DDOM-013","Customer DWH","Data Warehouse","Snowflake","Active","Customer Data Warehouse"),
    ("DAST-038","DDOM-013","Customer Analytics Lake","Data Lake","AWS S3","Active","Customer Data Lake"),
    ("DAST-039","DDOM-013","Segment Store","Database","Segment CDP","Active","Customer Segment"),
    ("DAST-040","DDOM-014","Finance DWH","Data Warehouse","Snowflake","Active","Financial Data Warehouse"),
    ("DAST-041","DDOM-014","FP&A DB","Database","Anaplan","Active","Financial Planning DB"),
    ("DAST-042","DDOM-014","Regulatory Reporting DB","Database","Oracle BI","Active","Regulatory Report DB"),
    ("DAST-043","DDOM-015","Operations DWH","Data Warehouse","Google BigQuery","Active","Operations Data Warehouse"),
    ("DAST-044","DDOM-015","KPI Mart","Data Warehouse","Power BI Premium","Active","KPI Data Mart"),
    ("DAST-045","DDOM-015","Performance Dashboard DB","Database","PostgreSQL","Active","Dashboard DB"),
    ("DAST-046","DDOM-016","Risk Model DB","Database","SAS Analytics","Active","ฐานข้อมูล Risk Model"),
    ("DAST-047","DDOM-016","Fraud Detection DB","Database","FICO Falcon","Active","Fraud Detection DB"),
    ("DAST-048","DDOM-016","Risk Dashboard","Database","Tableau","Active","Risk Dashboard DB"),
    ("DAST-049","DDOM-017","Enterprise DWH","Data Warehouse","Snowflake","Active","Enterprise Data Warehouse"),
    ("DAST-050","DDOM-017","Data Mart","Data Warehouse","Amazon Redshift","Active","Business Data Mart"),
    ("DAST-051","DDOM-017","BI Semantic Layer","Database","dbt","Active","BI Semantic Layer"),
    ("DAST-052","DDOM-018","FX Reference DB","Database","Bloomberg DB","Active","อัตราแลกเปลี่ยนอ้างอิง"),
    ("DAST-053","DDOM-018","Currency API","API","Open Exchange API","Active","Currency API"),
    ("DAST-054","DDOM-018","Rate Service","API","Internal","Active","Internal Rate Service"),
    ("DAST-055","DDOM-019","Industry Code DB","Database","PostgreSQL","Active","ฐานข้อมูลรหัสอุตสาหกรรม"),
    ("DAST-056","DDOM-019","ISIC Reference","File","Static File","Active","ISIC Reference Data"),
    ("DAST-057","DDOM-019","Standards API","API","Internal","Active","Standards API"),
    ("DAST-058","DDOM-020","Regulatory DB","Database","PostgreSQL","Active","ฐานข้อมูล Regulation"),
    ("DAST-059","DDOM-020","Compliance Reference","Database","MetricStream","Active","Compliance Reference"),
    ("DAST-060","DDOM-020","Rule Engine","API","Drools","Active","Business Rule Engine"),
    ("DAST-061","DDOM-021","Category DB","Database","PostgreSQL","Active","Product Category DB"),
    ("DAST-062","DDOM-021","Taxonomy Service","API","Internal","Active","Product Taxonomy"),
    ("DAST-063","DDOM-021","Classification API","API","Internal","Active","Product Classification API"),
    ("DAST-064","DDOM-022","CMDB","Database","ServiceNow CMDB","Active","Configuration Management DB"),
    ("DAST-065","DDOM-022","Asset Management DB","Database","Lansweeper","Active","IT Asset DB"),
    ("DAST-066","DDOM-022","Discovery DB","Database","Nmap DB","Active","Network Discovery DB"),
    ("DAST-067","DDOM-023","Log Aggregation","Data Lake","Elasticsearch","Active","Centralized Log Store"),
    ("DAST-068","DDOM-023","Event Bus","Event Stream","Kafka","Active","Application Event Bus"),
    ("DAST-069","DDOM-023","Audit Trail DB","Database","PostgreSQL","Active","Audit Log DB"),
    ("DAST-070","DDOM-024","Metrics DB","Time-Series","Prometheus","Active","Infrastructure Metrics"),
    ("DAST-071","DDOM-024","Time-Series DB","Time-Series","InfluxDB","Active","Time-Series Metrics"),
    ("DAST-072","DDOM-024","Capacity DB","Database","PostgreSQL","Active","Capacity Planning DB"),
    ("DAST-073","DDOM-025","SIEM DB","Database","Splunk","Active","SIEM Data Store"),
    ("DAST-074","DDOM-025","Threat Intel DB","Database","MISP","Active","Threat Intelligence"),
    ("DAST-075","DDOM-025","Incident DB","Database","PagerDuty DB","Active","Security Incident DB"),
    ("DAST-076","DDOM-026","API Gateway DB","Database","Kong DB","Active","API Gateway Config DB"),
    ("DAST-077","DDOM-026","Integration Log DB","Database","PostgreSQL","Active","Integration Log"),
    ("DAST-078","DDOM-026","Message Archive","Data Lake","AWS S3","Active","Message Archive"),
    ("DAST-079","DDOM-027","Market Intelligence DB","Database","Refinitiv DB","Active","Market Data"),
    ("DAST-080","DDOM-027","Competitive DB","Database","Crayon Data","Active","Competitive Intelligence"),
    ("DAST-081","DDOM-027","Industry Reports","File","SharePoint","Active","Industry Report Store"),
    ("DAST-082","DDOM-028","Social Media DB","Database","Sprinklr DB","Active","Social Media Data"),
    ("DAST-083","DDOM-028","Sentiment DB","Database","Brandwatch DB","Active","Sentiment Analysis"),
    ("DAST-084","DDOM-028","Brand Monitor","API","Mention API","Active","Brand Monitoring"),
    ("DAST-085","DDOM-029","Data Enrichment DB","Database","Dun & Bradstreet","Active","Third-Party Enrichment"),
    ("DAST-086","DDOM-029","Firmographic DB","Database","ZoomInfo","Active","B2B Firmographic Data"),
    ("DAST-087","DDOM-029","Contact Enrichment","API","Clearbit API","Active","Contact Enrichment API"),
    ("DAST-088","DDOM-030","Open Data DB","Database","PostgreSQL","Active","Open Data Store"),
    ("DAST-089","DDOM-030","Government Registry DB","Database","DBD Registry","Active","Thai Gov Registry"),
    ("DAST-090","DDOM-030","Public Data API","API","data.go.th","Active","Public Data API"),
]

# ── EAA Seed ──────────────────────────────────────────────────────────────────
_EAA_SEED_ACAP = [
    # Front Office (6)
    ("ACAP-001","Front Office","Customer Self-Service Portal","Core","ช่องทาง Self-Service สำหรับลูกค้า","High","Active"),
    ("ACAP-002","Front Office","CRM System","Core","ระบบบริหารความสัมพันธ์ลูกค้า","High","Active"),
    ("ACAP-003","Front Office","Digital Commerce Platform","Core","แพลตฟอร์ม E-Commerce และ Digital Sales","High","Active"),
    ("ACAP-004","Front Office","Customer Communication Platform","Support","ระบบสื่อสารกับลูกค้าแบบ Omnichannel","Medium","Active"),
    ("ACAP-005","Front Office","Service Desk & ITSM","Support","ระบบ Help Desk และ Service Management","High","Active"),
    ("ACAP-006","Front Office","Field Service Management","Support","ระบบบริหารงานภาคสนาม","Medium","Active"),
    # Back Office (6)
    ("ACAP-007","Back Office","ERP Financial Management","Core","ระบบบัญชีและการเงิน (ERP Core)","Critical","Active"),
    ("ACAP-008","Back Office","HR Information System","Core","ระบบบริหารทรัพยากรบุคคล","High","Active"),
    ("ACAP-009","Back Office","Procurement System","Core","ระบบจัดซื้อจัดหา","High","Active"),
    ("ACAP-010","Back Office","Document & Content Management","Support","ระบบจัดการเอกสารและ Content","Medium","Active"),
    ("ACAP-011","Back Office","Legal & Contract Management","Support","ระบบจัดการสัญญาและกฎหมาย","Medium","Active"),
    ("ACAP-012","Back Office","Project Portfolio Management","Support","ระบบบริหารโครงการและ Portfolio","High","Active"),
    # Integration (5)
    ("ACAP-013","Integration","API Management Platform","Core","แพลตฟอร์มจัดการ API","Critical","Active"),
    ("ACAP-014","Integration","Enterprise Service Bus","Core","Enterprise Service Bus สำหรับ Integration","High","Active"),
    ("ACAP-015","Integration","Event Streaming Platform","Core","แพลตฟอร์ม Event-Driven Integration","High","Active"),
    ("ACAP-016","Integration","iPaaS & Workflow Automation","Support","แพลตฟอร์ม Low-Code Integration","Medium","Active"),
    ("ACAP-017","Integration","Master Data Management","Core","ระบบบริหาร Master Data กลาง","High","Active"),
    # Analytics & BI (5)
    ("ACAP-018","Analytics & BI","Business Intelligence Platform","Core","แพลตฟอร์ม BI และ Dashboard","High","Active"),
    ("ACAP-019","Analytics & BI","Data Warehouse Platform","Core","Enterprise Data Warehouse","High","Active"),
    ("ACAP-020","Analytics & BI","Data Lakehouse Platform","Core","Modern Data Lakehouse","High","Active"),
    ("ACAP-021","Analytics & BI","Advanced Analytics Platform","Support","ระบบ Statistical และ Predictive Analytics","Medium","Active"),
    ("ACAP-022","Analytics & BI","Real-Time Analytics","Support","Real-Time Streaming Analytics","Medium","Active"),
    # DevOps (4)
    ("ACAP-023","DevOps","CI/CD Pipeline Platform","Core","แพลตฟอร์ม CI/CD","High","Active"),
    ("ACAP-024","DevOps","Artifact & Container Registry","Support","ระบบ Artifact และ Container Registry","Medium","Active"),
    ("ACAP-025","DevOps","Infrastructure as Code","Core","IaC Platform สำหรับ Provisioning","High","Active"),
    ("ACAP-026","DevOps","Developer Portal & Catalog","Support","Internal Developer Portal","Medium","Active"),
    # Mobile (5)
    ("ACAP-027","Mobile","Mobile Development Platform","Core","Framework พัฒนา Mobile App","High","Active"),
    ("ACAP-028","Mobile","Mobile Backend as a Service","Core","Backend สำหรับ Mobile (BaaS)","High","Active"),
    ("ACAP-029","Mobile","Push Notification Service","Support","ระบบ Push Notification","Medium","Active"),
    ("ACAP-030","Mobile","Mobile Analytics Platform","Support","การวิเคราะห์พฤติกรรมผู้ใช้ Mobile","Medium","Active"),
    ("ACAP-031","Mobile","Mobile Security Platform","Core","ระบบ Security สำหรับ Mobile App","High","Active"),
    # Core Systems (4)
    ("ACAP-032","Core Systems","Identity & Access Management","Core","ระบบ IAM และ SSO กลาง","Critical","Active"),
    ("ACAP-033","Core Systems","Payment Gateway","Core","ระบบรับชำระเงิน","Critical","Active"),
    ("ACAP-034","Core Systems","GRC & Compliance Platform","Core","ระบบ Governance, Risk & Compliance","High","Active"),
    ("ACAP-035","Core Systems","Collaboration Platform","Support","แพลตฟอร์มสื่อสารและทำงานร่วมกัน","High","Active"),
]

_EAA_SEED_APPSYS = [
    ("ASYS-001","ACAP-001","Salesforce Experience Cloud","Salesforce","Active","Current","Customer Community Portal"),
    ("ASYS-002","ACAP-001","Microsoft SharePoint Portal","Microsoft","Active","Current","Self-Service Intranet Portal"),
    ("ASYS-003","ACAP-001","Custom Web Portal","Internal","Active","Current","Bespoke Customer Portal"),
    ("ASYS-004","ACAP-002","Salesforce Sales Cloud","Salesforce","Active","Current","CRM สำหรับ Sales Team"),
    ("ASYS-005","ACAP-002","Microsoft Dynamics 365 CRM","Microsoft","Active","Current","CRM ครบวงจร"),
    ("ASYS-006","ACAP-002","HubSpot CRM","HubSpot","Active","Current","CRM สำหรับ SME"),
    ("ASYS-007","ACAP-003","Shopify Plus","Shopify","Active","Current","E-Commerce Platform"),
    ("ASYS-008","ACAP-003","Magento Commerce","Adobe","Active","Current","Enterprise E-Commerce"),
    ("ASYS-009","ACAP-003","WooCommerce","Automattic","Active","Current","Open-source E-Commerce"),
    ("ASYS-010","ACAP-004","Twilio Flex","Twilio","Active","Current","Omnichannel Contact Center"),
    ("ASYS-011","ACAP-004","SendGrid Email Platform","Twilio","Active","Current","Transactional Email"),
    ("ASYS-012","ACAP-004","Infobip","Infobip","Active","Current","SMS & Messaging Platform"),
    ("ASYS-013","ACAP-005","ServiceNow ITSM","ServiceNow","Active","Current","Enterprise ITSM"),
    ("ASYS-014","ACAP-005","Zendesk Support","Zendesk","Active","Current","Customer Support Platform"),
    ("ASYS-015","ACAP-005","Freshservice","Freshworks","Active","Current","IT Service Management"),
    ("ASYS-016","ACAP-006","ServiceMax","Salesforce","Active","Current","Field Service Management"),
    ("ASYS-017","ACAP-006","Microsoft Dynamics Field Service","Microsoft","Active","Current","Field Service"),
    ("ASYS-018","ACAP-006","ClickSoftware","Salesforce","Planned","Current","Field Workforce Scheduling"),
    ("ASYS-019","ACAP-007","SAP S/4HANA Finance","SAP","Active","Current","ERP Financial Core"),
    ("ASYS-020","ACAP-007","Oracle Financials Cloud","Oracle","Active","Current","Cloud Financials"),
    ("ASYS-021","ACAP-007","Microsoft Dynamics 365 Finance","Microsoft","Active","Current","Finance & Operations"),
    ("ASYS-022","ACAP-008","SAP SuccessFactors","SAP","Active","Current","Cloud HCM"),
    ("ASYS-023","ACAP-008","Workday HCM","Workday","Active","Current","HR & Finance Cloud"),
    ("ASYS-024","ACAP-008","Oracle HCM Cloud","Oracle","Active","Current","Human Capital Management"),
    ("ASYS-025","ACAP-009","SAP Ariba","SAP","Active","Current","Procurement Network"),
    ("ASYS-026","ACAP-009","Coupa","Coupa","Active","Current","Business Spend Management"),
    ("ASYS-027","ACAP-009","Oracle Procurement Cloud","Oracle","Active","Current","Cloud Procurement"),
    ("ASYS-028","ACAP-010","Microsoft SharePoint","Microsoft","Active","Current","Document Management"),
    ("ASYS-029","ACAP-010","OpenText Content Suite","OpenText","Active","Current","Enterprise Content"),
    ("ASYS-030","ACAP-010","Alfresco","Hyland","Active","Current","Open-source ECM"),
    ("ASYS-031","ACAP-011","DocuSign CLM","DocuSign","Active","Current","Contract Lifecycle Mgmt"),
    ("ASYS-032","ACAP-011","Ironclad CLM","Ironclad","Active","Current","Modern CLM Platform"),
    ("ASYS-033","ACAP-011","Agiloft","Agiloft","Active","Current","Flexible CLM"),
    ("ASYS-034","ACAP-012","Microsoft Project","Microsoft","Active","Current","Project Management"),
    ("ASYS-035","ACAP-012","Jira Software","Atlassian","Active","Current","Agile Project Tracking"),
    ("ASYS-036","ACAP-012","Smartsheet","Smartsheet","Active","Current","Work Management"),
    ("ASYS-037","ACAP-013","Kong Gateway Enterprise","Kong","Active","Current","API Gateway & Management"),
    ("ASYS-038","ACAP-013","AWS API Gateway","AWS","Active","Current","Cloud API Management"),
    ("ASYS-039","ACAP-013","MuleSoft Anypoint","Salesforce","Active","Current","Full API Lifecycle"),
    ("ASYS-040","ACAP-014","IBM MQ","IBM","Active","Current","Enterprise Message Queue"),
    ("ASYS-041","ACAP-014","MuleSoft ESB","Salesforce","Active","Current","Enterprise Service Bus"),
    ("ASYS-042","ACAP-014","WSO2 ESB","WSO2","Active","Current","Open-source ESB"),
    ("ASYS-043","ACAP-015","Apache Kafka","Apache","Active","Current","Event Streaming"),
    ("ASYS-044","ACAP-015","AWS Kinesis","AWS","Active","Current","Managed Streaming"),
    ("ASYS-045","ACAP-015","Azure Event Hub","Microsoft","Active","Current","Cloud Event Streaming"),
    ("ASYS-046","ACAP-016","MuleSoft Anypoint iPaaS","Salesforce","Active","Current","iPaaS Platform"),
    ("ASYS-047","ACAP-016","Boomi Integration","SAP","Active","Current","Low-code iPaaS"),
    ("ASYS-048","ACAP-016","Microsoft Power Automate","Microsoft","Active","Current","Workflow Automation"),
    ("ASYS-049","ACAP-017","SAP MDG","SAP","Active","Current","SAP Master Data Governance"),
    ("ASYS-050","ACAP-017","Informatica MDM","Informatica","Active","Current","Enterprise MDM"),
    ("ASYS-051","ACAP-017","Reltio MDM","Reltio","Active","Current","Cloud-Native MDM"),
    ("ASYS-052","ACAP-018","Microsoft Power BI","Microsoft","Active","Current","Self-Service BI"),
    ("ASYS-053","ACAP-018","Tableau","Salesforce","Active","Current","Visual Analytics"),
    ("ASYS-054","ACAP-018","Looker","Google","Active","Current","Data Platform BI"),
    ("ASYS-055","ACAP-019","Snowflake","Snowflake","Active","Current","Cloud Data Warehouse"),
    ("ASYS-056","ACAP-019","Google BigQuery","Google","Active","Current","Serverless Data Warehouse"),
    ("ASYS-057","ACAP-019","Amazon Redshift","AWS","Active","Current","Cloud Data Warehouse"),
    ("ASYS-058","ACAP-020","Databricks","Databricks","Active","Current","Data + AI Platform"),
    ("ASYS-059","ACAP-020","Azure Synapse Analytics","Microsoft","Active","Current","Unified Analytics"),
    ("ASYS-060","ACAP-020","AWS Lake Formation","AWS","Active","Current","Data Lake Builder"),
    ("ASYS-061","ACAP-021","SAS Analytics","SAS","Active","Current","Statistical Analytics"),
    ("ASYS-062","ACAP-021","IBM SPSS","IBM","Active","LTS","Statistical Analysis"),
    ("ASYS-063","ACAP-021","Alteryx Designer","Alteryx","Active","Current","Data Analytics"),
    ("ASYS-064","ACAP-022","Apache Flink","Apache","Active","Current","Stateful Stream Processing"),
    ("ASYS-065","ACAP-022","Spark Streaming","Apache","Active","Current","Real-Time Analytics"),
    ("ASYS-066","ACAP-022","ksqlDB","Confluent","Active","Current","Streaming SQL"),
    ("ASYS-067","ACAP-023","Jenkins","Jenkins","Active","Current","Open-source CI/CD"),
    ("ASYS-068","ACAP-023","GitLab CI/CD","GitLab","Active","Current","Integrated CI/CD"),
    ("ASYS-069","ACAP-023","GitHub Actions","GitHub","Active","Current","Cloud-native CI/CD"),
    ("ASYS-070","ACAP-024","Docker Hub","Docker","Active","Current","Container Registry"),
    ("ASYS-071","ACAP-024","Azure Container Registry","Microsoft","Active","Current","Cloud Registry"),
    ("ASYS-072","ACAP-024","AWS ECR","AWS","Active","Current","Elastic Container Registry"),
    ("ASYS-073","ACAP-025","Terraform","HashiCorp","Active","Current","Infrastructure as Code"),
    ("ASYS-074","ACAP-025","Pulumi","Pulumi","Active","Current","Modern IaC"),
    ("ASYS-075","ACAP-025","AWS CloudFormation","AWS","Active","Current","AWS Native IaC"),
    ("ASYS-076","ACAP-026","Backstage","Spotify/CNCF","Active","Current","Internal Developer Portal"),
    ("ASYS-077","ACAP-026","Port","Port","Active","Current","Developer Portal"),
    ("ASYS-078","ACAP-026","OpsLevel","OpsLevel","Active","Current","Service Catalog"),
    ("ASYS-079","ACAP-027","React Native","Meta","Active","Current","Cross-platform Mobile"),
    ("ASYS-080","ACAP-027","Flutter","Google","Active","Current","Cross-platform Mobile"),
    ("ASYS-081","ACAP-027","Ionic Framework","Ionic","Active","Current","Hybrid Mobile"),
    ("ASYS-082","ACAP-028","Firebase","Google","Active","Current","BaaS Platform"),
    ("ASYS-083","ACAP-028","AWS Amplify","AWS","Active","Current","Full-stack Mobile/Web"),
    ("ASYS-084","ACAP-028","Supabase","Supabase","Active","Current","Open-source BaaS"),
    ("ASYS-085","ACAP-029","Firebase Cloud Messaging","Google","Active","Current","Push Notification"),
    ("ASYS-086","ACAP-029","Apple Push Notification","Apple","Active","Current","iOS Push"),
    ("ASYS-087","ACAP-029","OneSignal","OneSignal","Active","Current","Multi-channel Notification"),
    ("ASYS-088","ACAP-030","Amplitude","Amplitude","Active","Current","Product Analytics"),
    ("ASYS-089","ACAP-030","Mixpanel","Mixpanel","Active","Current","Event Analytics"),
    ("ASYS-090","ACAP-030","AppsFlyer","AppsFlyer","Active","Current","Mobile Attribution"),
    ("ASYS-091","ACAP-031","Guardsquare DexGuard","Guardsquare","Active","Current","Android Security"),
    ("ASYS-092","ACAP-031","OneSpan Mobile Security","OneSpan","Active","Current","Mobile App Shield"),
    ("ASYS-093","ACAP-031","Appdome","Appdome","Active","Current","No-code Mobile Security"),
    ("ASYS-094","ACAP-032","Okta","Okta","Active","Current","Identity Cloud"),
    ("ASYS-095","ACAP-032","Microsoft Entra ID","Microsoft","Active","Current","Azure AD IAM"),
    ("ASYS-096","ACAP-032","Ping Identity","Ping Identity","Active","Current","Enterprise IAM"),
    ("ASYS-097","ACAP-033","Stripe","Stripe","Active","Current","Payment API"),
    ("ASYS-098","ACAP-033","2C2P","2C2P","Active","Current","SEA Payment Gateway"),
    ("ASYS-099","ACAP-033","Omise","Omise","Active","Current","Thailand Payment"),
    ("ASYS-100","ACAP-034","IBM OpenPages","IBM","Active","Current","GRC Platform"),
    ("ASYS-101","ACAP-034","MetricStream","MetricStream","Active","Current","Integrated GRC"),
    ("ASYS-102","ACAP-034","LogicGate","LogicGate","Active","Current","Modern GRC"),
    ("ASYS-103","ACAP-035","Microsoft Teams","Microsoft","Active","Current","Collaboration Hub"),
    ("ASYS-104","ACAP-035","Slack","Salesforce","Active","Current","Team Messaging"),
    ("ASYS-105","ACAP-035","Zoom","Zoom","Active","Current","Video Conferencing"),
]

# ── ETA Seed ──────────────────────────────────────────────────────────────────
_ETA_SEED_TSTD = [
    # Infrastructure (6)
    ("TSTD-001","Infrastructure","Server Virtualization","Adopt","มาตรฐาน Server Virtualization","Current"),
    ("TSTD-002","Infrastructure","Storage Architecture","Adopt","มาตรฐาน Shared & Object Storage","Current"),
    ("TSTD-003","Infrastructure","Network Architecture","Adopt","มาตรฐาน Network Design และ Segmentation","Current"),
    ("TSTD-004","Infrastructure","Load Balancing","Adopt","มาตรฐาน Load Balancing และ HA","Current"),
    ("TSTD-005","Infrastructure","Backup & Recovery","Adopt","มาตรฐาน Backup และ DR","Current"),
    ("TSTD-006","Infrastructure","Data Center Management","Adopt","มาตรฐานบริหาร Data Center","Current"),
    # Middleware (5)
    ("TSTD-007","Middleware","Application Server","Adopt","มาตรฐาน Application Server Runtime","Current"),
    ("TSTD-008","Middleware","Message Queue","Adopt","มาตรฐาน Asynchronous Messaging","Current"),
    ("TSTD-009","Middleware","Caching Platform","Adopt","มาตรฐาน In-Memory Caching","Current"),
    ("TSTD-010","Middleware","API Gateway","Adopt","มาตรฐาน API Gateway และ Management","Current"),
    ("TSTD-011","Middleware","Service Mesh","Trial","มาตรฐาน Service Mesh สำหรับ Microservices","Current"),
    # Data Platform (6)
    ("TSTD-012","Data Platform","Relational Database","Adopt","มาตรฐาน Relational DBMS","Current"),
    ("TSTD-013","Data Platform","NoSQL Database","Adopt","มาตรฐาน NoSQL Database","Current"),
    ("TSTD-014","Data Platform","Time-Series Database","Trial","มาตรฐาน Time-Series Data","Current"),
    ("TSTD-015","Data Platform","Search & Analytics Engine","Adopt","มาตรฐาน Full-Text Search","Current"),
    ("TSTD-016","Data Platform","Data Pipeline & ETL","Adopt","มาตรฐาน Data Pipeline","Current"),
    ("TSTD-017","Data Platform","Streaming Platform","Adopt","มาตรฐาน Event Streaming","Current"),
    # Security Tech (6)
    ("TSTD-018","Security Tech","Identity Provider","Adopt","มาตรฐาน IdP และ SSO","Current"),
    ("TSTD-019","Security Tech","Web Application Firewall","Adopt","มาตรฐาน WAF","Current"),
    ("TSTD-020","Security Tech","SIEM Platform","Adopt","มาตรฐาน Security Information & Event Mgmt","Current"),
    ("TSTD-021","Security Tech","Endpoint Detection & Response","Adopt","มาตรฐาน EDR","Current"),
    ("TSTD-022","Security Tech","Vulnerability Management","Adopt","มาตรฐาน Vulnerability Scanning","Current"),
    ("TSTD-023","Security Tech","PKI & Certificate Management","Adopt","มาตรฐาน Certificate Lifecycle","Current"),
    # DevOps Tools (5)
    ("TSTD-024","DevOps Tools","Source Control","Adopt","มาตรฐาน Version Control","Current"),
    ("TSTD-025","DevOps Tools","Container Runtime","Adopt","มาตรฐาน Container Runtime","Current"),
    ("TSTD-026","DevOps Tools","Container Orchestration","Adopt","มาตรฐาน Kubernetes","Current"),
    ("TSTD-027","DevOps Tools","CI/CD Pipeline","Adopt","มาตรฐาน CI/CD Automation","Current"),
    ("TSTD-028","DevOps Tools","Secret Management","Adopt","มาตรฐาน Secrets & Credentials","Current"),
    # Cloud Platform (6)
    ("TSTD-029","Cloud Platform","Public Cloud Provider","Adopt","มาตรฐาน Public Cloud","Current"),
    ("TSTD-030","Cloud Platform","Private Cloud Platform","Adopt","มาตรฐาน Private Cloud / On-Prem","Current"),
    ("TSTD-031","Cloud Platform","Serverless Computing","Trial","มาตรฐาน Serverless / FaaS","Current"),
    ("TSTD-032","Cloud Platform","Object Storage","Adopt","มาตรฐาน Object Storage","Current"),
    ("TSTD-033","Cloud Platform","Cloud Cost Management","Adopt","มาตรฐาน FinOps / Cloud Cost","Current"),
    ("TSTD-034","Cloud Platform","Cloud Security Posture","Adopt","มาตรฐาน CSPM","Current"),
    # Monitoring (4)
    ("TSTD-035","Monitoring","Infrastructure Monitoring","Adopt","มาตรฐาน Infra Monitoring","Current"),
    ("TSTD-036","Monitoring","APM & Distributed Tracing","Adopt","มาตรฐาน Application Performance","Current"),
    ("TSTD-037","Monitoring","Log Management","Adopt","มาตรฐาน Centralized Logging","Current"),
    ("TSTD-038","Monitoring","Synthetic Monitoring","Trial","มาตรฐาน Synthetic & Uptime","Current"),
    # AI/ML Platform (2)
    ("TSTD-039","AI/ML Platform","ML Model Platform","Trial","มาตรฐาน MLOps และ Model Registry","Current"),
    ("TSTD-040","AI/ML Platform","GenAI & LLM Platform","Assess","มาตรฐาน Generative AI","Current"),
]

_ETA_SEED_TPROD = [
    ("TPRD-001","TSTD-001","VMware vSphere","VMware","8.0","Current","Active","Enterprise Hypervisor"),
    ("TPRD-002","TSTD-001","Microsoft Hyper-V","Microsoft","2022","Current","Active","Windows Hypervisor"),
    ("TPRD-003","TSTD-001","Proxmox VE","Proxmox","8.1","Current","Active","Open-source Hypervisor"),
    ("TPRD-004","TSTD-002","NetApp ONTAP","NetApp","9.14","Current","Active","Enterprise NAS/SAN"),
    ("TPRD-005","TSTD-002","Pure Storage FlashArray","Pure Storage","Purity 6.x","Current","Active","All-Flash Storage"),
    ("TPRD-006","TSTD-002","Dell EMC PowerStore","Dell","3.6","Current","Active","Multi-cloud Storage"),
    ("TPRD-007","TSTD-003","Cisco Catalyst 9000","Cisco","17.x","Current","Active","Enterprise Switch"),
    ("TPRD-008","TSTD-003","Juniper Networks EX","Juniper","23.x","Current","Active","Enterprise Switch"),
    ("TPRD-009","TSTD-003","Arista Networks","Arista","4.30","Current","Active","Data Center Networking"),
    ("TPRD-010","TSTD-004","F5 BIG-IP","F5","17.x","Current","Active","ADC & LB"),
    ("TPRD-011","TSTD-004","NGINX Plus","F5","R31","Current","Active","Software LB"),
    ("TPRD-012","TSTD-004","HAProxy Enterprise","HAProxy","3.0","Current","Active","Open-source LB"),
    ("TPRD-013","TSTD-005","Veeam Backup & Replication","Veeam","12.x","Current","Active","VM Backup"),
    ("TPRD-014","TSTD-005","Commvault Complete","Commvault","2024","Current","Active","Enterprise Backup"),
    ("TPRD-015","TSTD-005","Veritas NetBackup","Veritas","10.x","LTS","Active","Enterprise Backup"),
    ("TPRD-016","TSTD-006","Ansible Automation Platform","Red Hat","2.4","Current","Active","IT Automation"),
    ("TPRD-017","TSTD-006","DCIM Platform","Nlyte","13.x","Current","Active","Data Center DCIM"),
    ("TPRD-018","TSTD-006","HPE iLO","HPE","6.x","Current","Active","Server Management"),
    ("TPRD-019","TSTD-007","Apache Tomcat","Apache","10.x","Current","Active","Java App Server"),
    ("TPRD-020","TSTD-007","JBoss EAP","Red Hat","8.x","Current","Active","Enterprise App Server"),
    ("TPRD-021","TSTD-007","IBM WebSphere Liberty","IBM","24.x","LTS","Active","Enterprise App Server"),
    ("TPRD-022","TSTD-008","RabbitMQ","Broadcom","3.12","Current","Active","AMQP Message Queue"),
    ("TPRD-023","TSTD-008","Apache ActiveMQ","Apache","6.x","Current","Active","JMS Message Broker"),
    ("TPRD-024","TSTD-008","IBM MQ","IBM","9.3","LTS","Active","Enterprise MQ"),
    ("TPRD-025","TSTD-009","Redis Enterprise","Redis","7.x","Current","Active","In-Memory Cache"),
    ("TPRD-026","TSTD-009","Memcached","Memcached","1.6","Current","Active","Distributed Cache"),
    ("TPRD-027","TSTD-009","Hazelcast Platform","Hazelcast","5.x","Current","Active","In-Memory Computing"),
    ("TPRD-028","TSTD-010","Kong Gateway Enterprise","Kong","3.x","Current","Active","API Gateway"),
    ("TPRD-029","TSTD-010","AWS API Gateway","AWS","v2","Current","Active","Cloud API Gateway"),
    ("TPRD-030","TSTD-010","NGINX API Gateway","F5","R31","Current","Active","Software API GW"),
    ("TPRD-031","TSTD-011","Istio","CNCF","1.21","Current","Active","Service Mesh"),
    ("TPRD-032","TSTD-011","Linkerd","CNCF","2.x","Current","Active","Lightweight Service Mesh"),
    ("TPRD-033","TSTD-011","Consul Connect","HashiCorp","1.18","Current","Active","Service Discovery"),
    ("TPRD-034","TSTD-012","Oracle Database","Oracle","19c/21c","LTS","Active","Enterprise RDBMS"),
    ("TPRD-035","TSTD-012","PostgreSQL","PostgreSQL","16.x","Current","Active","Open-source RDBMS"),
    ("TPRD-036","TSTD-012","MySQL Enterprise","Oracle","8.0","LTS","Active","Web-scale RDBMS"),
    ("TPRD-037","TSTD-013","MongoDB Atlas","MongoDB","7.x","Current","Active","Document Database"),
    ("TPRD-038","TSTD-013","Apache Cassandra","Apache","5.x","Current","Active","Wide-column NoSQL"),
    ("TPRD-039","TSTD-013","Amazon DynamoDB","AWS","N/A","Current","Active","Managed NoSQL"),
    ("TPRD-040","TSTD-014","InfluxDB","InfluxData","3.x","Current","Active","Time-Series DB"),
    ("TPRD-041","TSTD-014","TimescaleDB","Timescale","2.x","Current","Active","PostgreSQL Time-Series"),
    ("TPRD-042","TSTD-014","VictoriaMetrics","Victoria","1.x","Current","Active","High-Performance TS DB"),
    ("TPRD-043","TSTD-015","Elasticsearch","Elastic","8.x","Current","Active","Search Engine"),
    ("TPRD-044","TSTD-015","OpenSearch","AWS","2.x","Current","Active","Open-source Search"),
    ("TPRD-045","TSTD-015","Apache Solr","Apache","9.x","Current","Active","Enterprise Search"),
    ("TPRD-046","TSTD-016","Apache Airflow","Apache","2.x","Current","Active","Workflow Orchestration"),
    ("TPRD-047","TSTD-016","dbt","dbt Labs","1.8","Current","Active","Data Transformation"),
    ("TPRD-048","TSTD-016","Talend Data Integration","Qlik","8.x","LTS","Active","ETL Platform"),
    ("TPRD-049","TSTD-017","Apache Kafka","Apache","3.7","Current","Active","Event Streaming"),
    ("TPRD-050","TSTD-017","Apache Pulsar","Apache","3.x","Current","Active","Cloud-native Streaming"),
    ("TPRD-051","TSTD-017","Confluent Platform","Confluent","7.x","Current","Active","Managed Kafka"),
    ("TPRD-052","TSTD-018","Keycloak","Red Hat","24.x","Current","Active","Open-source IdP"),
    ("TPRD-053","TSTD-018","Okta","Okta","N/A","Current","Active","Identity Cloud"),
    ("TPRD-054","TSTD-018","Microsoft Entra ID","Microsoft","N/A","Current","Active","Azure Identity"),
    ("TPRD-055","TSTD-019","ModSecurity","Trustwave","3.x","Current","Active","Open-source WAF"),
    ("TPRD-056","TSTD-019","Imperva WAF","Imperva","N/A","Current","Active","Enterprise WAF"),
    ("TPRD-057","TSTD-019","AWS WAF","AWS","N/A","Current","Active","Cloud WAF"),
    ("TPRD-058","TSTD-020","Splunk Enterprise Security","Splunk","7.x","Current","Active","SIEM"),
    ("TPRD-059","TSTD-020","IBM QRadar","IBM","7.5","Current","Active","SIEM"),
    ("TPRD-060","TSTD-020","Microsoft Sentinel","Microsoft","N/A","Current","Active","Cloud SIEM"),
    ("TPRD-061","TSTD-021","CrowdStrike Falcon","CrowdStrike","N/A","Current","Active","Cloud EDR"),
    ("TPRD-062","TSTD-021","SentinelOne","SentinelOne","N/A","Current","Active","AI-powered EDR"),
    ("TPRD-063","TSTD-021","Microsoft Defender","Microsoft","N/A","Current","Active","Integrated EDR"),
    ("TPRD-064","TSTD-022","Tenable.io","Tenable","N/A","Current","Active","Cloud Vulnerability Mgmt"),
    ("TPRD-065","TSTD-022","Qualys VMDR","Qualys","N/A","Current","Active","Vulnerability Management"),
    ("TPRD-066","TSTD-022","Rapid7 InsightVM","Rapid7","N/A","Current","Active","Risk-based VM"),
    ("TPRD-067","TSTD-023","HashiCorp Vault","HashiCorp","1.17","Current","Active","Secrets Management"),
    ("TPRD-068","TSTD-023","DigiCert CertCentral","DigiCert","N/A","Current","Active","PKI & Certs"),
    ("TPRD-069","TSTD-023","Venafi TLS Protect","Venafi","N/A","Current","Active","Machine Identity"),
    ("TPRD-070","TSTD-024","GitHub Enterprise","GitHub","3.x","Current","Active","Source Control"),
    ("TPRD-071","TSTD-024","GitLab Self-Managed","GitLab","17.x","Current","Active","DevSecOps Platform"),
    ("TPRD-072","TSTD-024","Bitbucket","Atlassian","N/A","Current","Active","Git Repository"),
    ("TPRD-073","TSTD-025","Docker Engine","Docker","26.x","Current","Active","Container Runtime"),
    ("TPRD-074","TSTD-025","containerd","CNCF","1.7","Current","Active","Industry Standard Runtime"),
    ("TPRD-075","TSTD-025","CRI-O","CNCF","1.30","Current","Active","Kubernetes Container Runtime"),
    ("TPRD-076","TSTD-026","Amazon EKS","AWS","1.30","Current","Active","Managed Kubernetes"),
    ("TPRD-077","TSTD-026","Azure AKS","Microsoft","1.30","Current","Active","Managed Kubernetes"),
    ("TPRD-078","TSTD-026","Google GKE","Google","1.30","Current","Active","Managed Kubernetes"),
    ("TPRD-079","TSTD-027","Jenkins","Jenkins","2.x","Current","Active","Open-source CI/CD"),
    ("TPRD-080","TSTD-027","GitLab CI/CD","GitLab","N/A","Current","Active","Integrated CI/CD"),
    ("TPRD-081","TSTD-027","Azure DevOps","Microsoft","N/A","Current","Active","End-to-end DevOps"),
    ("TPRD-082","TSTD-028","HashiCorp Vault","HashiCorp","1.17","Current","Active","Secret Management"),
    ("TPRD-083","TSTD-028","AWS Secrets Manager","AWS","N/A","Current","Active","Cloud Secrets"),
    ("TPRD-084","TSTD-028","Azure Key Vault","Microsoft","N/A","Current","Active","Cloud Key Management"),
    ("TPRD-085","TSTD-029","Amazon Web Services","AWS","N/A","Current","Active","Public Cloud Leader"),
    ("TPRD-086","TSTD-029","Microsoft Azure","Microsoft","N/A","Current","Active","Enterprise Cloud"),
    ("TPRD-087","TSTD-029","Google Cloud Platform","Google","N/A","Current","Active","Data & AI Cloud"),
    ("TPRD-088","TSTD-030","VMware Cloud Foundation","VMware","5.x","Current","Active","Private Cloud"),
    ("TPRD-089","TSTD-030","OpenStack","OpenInfra","2024.1","Current","Active","Open-source Cloud"),
    ("TPRD-090","TSTD-030","Nutanix Cloud Platform","Nutanix","6.x","Current","Active","HCI Private Cloud"),
    ("TPRD-091","TSTD-031","AWS Lambda","AWS","N/A","Current","Active","Serverless Functions"),
    ("TPRD-092","TSTD-031","Azure Functions","Microsoft","4.x","Current","Active","Serverless Functions"),
    ("TPRD-093","TSTD-031","Google Cloud Run","Google","N/A","Current","Active","Container Serverless"),
    ("TPRD-094","TSTD-032","AWS S3","AWS","N/A","Current","Active","Object Storage Leader"),
    ("TPRD-095","TSTD-032","Azure Blob Storage","Microsoft","N/A","Current","Active","Azure Object Storage"),
    ("TPRD-096","TSTD-032","MinIO","MinIO","N/A","Current","Active","S3-compatible Storage"),
    ("TPRD-097","TSTD-033","AWS Cost Explorer","AWS","N/A","Current","Active","Cloud Cost Visibility"),
    ("TPRD-098","TSTD-033","CloudHealth","VMware","N/A","Current","Active","Multi-cloud FinOps"),
    ("TPRD-099","TSTD-033","Apptio Cloudability","IBM","N/A","Current","Active","Cloud Financial Mgmt"),
    ("TPRD-100","TSTD-034","AWS Security Hub","AWS","N/A","Current","Active","Cloud Security Posture"),
    ("TPRD-101","TSTD-034","Microsoft Defender for Cloud","Microsoft","N/A","Current","Active","Azure CSPM"),
    ("TPRD-102","TSTD-034","Prisma Cloud","Palo Alto","N/A","Current","Active","Cloud-Native Security"),
    ("TPRD-103","TSTD-035","Prometheus","CNCF","2.51","Current","Active","Metrics Collection"),
    ("TPRD-104","TSTD-035","Datadog","Datadog","N/A","Current","Active","Cloud Monitoring"),
    ("TPRD-105","TSTD-035","Zabbix","Zabbix","7.x","Current","Active","Open-source Monitoring"),
    ("TPRD-106","TSTD-036","Dynatrace","Dynatrace","N/A","Current","Active","AI-powered APM"),
    ("TPRD-107","TSTD-036","Elastic APM","Elastic","8.x","Current","Active","Open APM"),
    ("TPRD-108","TSTD-036","Jaeger","CNCF","1.57","Current","Active","Distributed Tracing"),
    ("TPRD-109","TSTD-037","ELK Stack","Elastic","8.x","Current","Active","Log Analytics"),
    ("TPRD-110","TSTD-037","Splunk Enterprise","Splunk","9.x","Current","Active","Log Management"),
    ("TPRD-111","TSTD-037","Graylog","Graylog","5.x","Current","Active","Open-source Log Mgmt"),
    ("TPRD-112","TSTD-038","Pingdom","Solarwinds","N/A","Current","Active","Uptime Monitoring"),
    ("TPRD-113","TSTD-038","Site24x7","Zoho","N/A","Current","Active","Full-stack Monitoring"),
    ("TPRD-114","TSTD-038","Grafana Synthetic","Grafana","N/A","Current","Active","Synthetic Monitoring"),
    ("TPRD-115","TSTD-039","MLflow","Databricks","2.x","Current","Active","ML Lifecycle"),
    ("TPRD-116","TSTD-039","Kubeflow","CNCF","1.9","Current","Active","ML on Kubernetes"),
    ("TPRD-117","TSTD-039","Amazon SageMaker","AWS","N/A","Current","Active","Managed ML Platform"),
    ("TPRD-118","TSTD-040","Azure OpenAI Service","Microsoft","N/A","Current","Active","Enterprise GenAI"),
    ("TPRD-119","TSTD-040","AWS Bedrock","AWS","N/A","Current","Active","Foundation Model API"),
    ("TPRD-120","TSTD-040","Google Vertex AI","Google","N/A","Current","Active","Unified AI Platform"),
]

_ESA_SEED_ABB = [
    # ── Identity (6) ─────────────────────────────────────────────────────────────
    ("ABB-001","Identity","Identity & Access Management","ยืนยันตัวตนและควบคุมสิทธิ์การเข้าถึงระบบ (IAM)","Critical","Required"),
    ("ABB-002","Identity","Privileged Access Management","จัดการ account สิทธิ์สูง (admin, service accounts, PAM)","Critical","Required"),
    ("ABB-003","Identity","Multi-Factor Authentication","ยืนยันตัวตนด้วยหลายปัจจัย (MFA/2FA)","Critical","Required"),
    ("ABB-004","Identity","Single Sign-On","ยืนยันตัวตนครั้งเดียวเข้าได้ทุกระบบ (SSO)","High","Required"),
    ("ABB-005","Identity","Identity Federation & SAML","เชื่อมต่อ identity ข้ามองค์กร/cloud (SAML, OIDC)","High","Required"),
    ("ABB-006","Identity","Certificate & PKI Management","ออกและจัดการ digital certificate และ PKI","High","Required"),
    # ── Network (7) ──────────────────────────────────────────────────────────────
    ("ABB-007","Network","Network Access Control","ควบคุมการเชื่อมต่อเครือข่ายก่อนอนุญาต (NAC)","High","Required"),
    ("ABB-008","Network","Next-Gen Firewall","ป้องกันและกรอง traffic ระดับ application (NGFW)","Critical","Required"),
    ("ABB-009","Network","Intrusion Detection & Prevention","ตรวจจับและป้องกันการบุกรุก (IDS/IPS)","High","Required"),
    ("ABB-010","Network","Zero Trust Network Access","ควบคุม access แบบ Zero Trust สำหรับ remote (ZTNA)","High","Required"),
    ("ABB-011","Network","VPN & Secure Remote Access","การเชื่อมต่อ VPN ที่ปลอดภัยสำหรับ remote user","Medium","Required"),
    ("ABB-012","Network","DNS Security","ป้องกัน DNS hijacking, DGA, และ exfiltration ผ่าน DNS","High","Required"),
    ("ABB-013","Network","DDoS Protection","ป้องกันการโจมตีแบบ Distributed Denial of Service","High","Required"),
    # ── Endpoint (5) ─────────────────────────────────────────────────────────────
    ("ABB-014","Endpoint","Endpoint Detection & Response","ตรวจจับและตอบสนองต่อภัยคุกคามบน endpoint (EDR/XDR)","Critical","Required"),
    ("ABB-015","Endpoint","Mobile Device Management","จัดการและรักษาความปลอดภัยอุปกรณ์พกพา (MDM/UEM)","Medium","Required"),
    ("ABB-016","Endpoint","Patch Management","บริหารจัดการ patch และ update ระบบปฏิบัติการ","High","Required"),
    ("ABB-017","Endpoint","Application Whitelisting","อนุญาตเฉพาะ application ที่กำหนด (application control)","High","Required"),
    ("ABB-018","Endpoint","Host-based Intrusion Prevention","ป้องกันการบุกรุกระดับ host (HIPS)","Medium","Required"),
    # ── Data (6) ─────────────────────────────────────────────────────────────────
    ("ABB-019","Data","Data Loss Prevention","ป้องกันข้อมูลสำคัญรั่วไหลออกนอกองค์กร (DLP)","High","Required"),
    ("ABB-020","Data","Encryption & Key Management","เข้ารหัสข้อมูลทั้ง at-rest และ in-transit พร้อมจัดการ key","High","Required"),
    ("ABB-021","Data","Database Activity Monitoring","ตรวจสอบและบันทึก query/activity ใน database (DAM)","High","Required"),
    ("ABB-022","Data","Data Classification","จัดประเภทข้อมูลตาม sensitivity (Public, Internal, Confidential, Secret)","Medium","Required"),
    ("ABB-023","Data","Backup & Disaster Recovery","สำรองข้อมูลและกู้คืนระบบหลังเกิดเหตุ (BDR)","Critical","Required"),
    ("ABB-024","Data","Data Masking & Tokenization","ปกปิดข้อมูลส่วนตัว/sensitive สำหรับ non-prod environment","Medium","Required"),
    # ── Application (6) ──────────────────────────────────────────────────────────
    ("ABB-025","Application","Web Application Firewall","ป้องกัน web application จาก OWASP Top 10 (WAF)","High","Required"),
    ("ABB-026","Application","API Security Gateway","ควบคุม rate limit, auth, และป้องกัน API","High","Required"),
    ("ABB-027","Application","Static Application Security Testing","วิเคราะห์ source code หา vulnerability (SAST)","High","Required"),
    ("ABB-028","Application","Dynamic Application Security Testing","ทดสอบ running application หา vulnerability (DAST)","High","Required"),
    ("ABB-029","Application","Software Composition Analysis","ตรวจสอบ open-source dependency vulnerability (SCA)","High","Required"),
    ("ABB-030","Application","Secrets Management","จัดการ API key, password, certificate ใน application","High","Required"),
    # ── Monitoring (6) ───────────────────────────────────────────────────────────
    ("ABB-031","Monitoring","SIEM","รวบรวมและวิเคราะห์ log/event ด้านความปลอดภัย (SIEM)","Critical","Required"),
    ("ABB-032","Monitoring","Vulnerability Management","ค้นหา ประเมิน และจัดการช่องโหว่อย่างต่อเนื่อง","High","Required"),
    ("ABB-033","Monitoring","User & Entity Behavior Analytics","วิเคราะห์พฤติกรรมผิดปกติของ user/entity (UEBA)","High","Required"),
    ("ABB-034","Monitoring","Threat Intelligence Platform","รวบรวมและวิเคราะห์ข้อมูล threat intelligence (TIP)","High","Required"),
    ("ABB-035","Monitoring","Security Orchestration & Automation","อัตโนมัติการตอบสนองต่อ incident (SOAR)","High","Required"),
    ("ABB-036","Monitoring","Network Traffic Analysis","วิเคราะห์ traffic เครือข่ายหา anomaly (NTA/NDR)","High","Required"),
    # ── Governance (5) ───────────────────────────────────────────────────────────
    ("ABB-037","Governance","Security Policy Management","จัดทำ บริหาร และบังคับใช้ security policy","Medium","Required"),
    ("ABB-038","Governance","Risk Management Framework","ประเมินและจัดการความเสี่ยงด้านความมั่นคงปลอดภัย","High","Required"),
    ("ABB-039","Governance","Compliance & Audit Management","จัดการ compliance (PDPA, ISO27001, PCI-DSS) และการตรวจสอบ","High","Required"),
    ("ABB-040","Governance","Security Awareness Training","ฝึกอบรมบุคลากรด้าน security awareness","Medium","Required"),
    ("ABB-041","Governance","Third-Party Risk Management","ประเมินและจัดการความเสี่ยงจาก vendor/third party","High","Required"),
    # ── Cloud (5) ────────────────────────────────────────────────────────────────
    ("ABB-042","Cloud","Cloud Security Posture Management","ตรวจสอบและแก้ไข misconfiguration บน cloud (CSPM)","High","Required"),
    ("ABB-043","Cloud","Cloud Workload Protection Platform","ปกป้อง workload บน VM, container, serverless (CWPP)","High","Required"),
    ("ABB-044","Cloud","Cloud Access Security Broker","ควบคุมการใช้งาน cloud services (CASB)","High","Required"),
    ("ABB-045","Cloud","Container & Kubernetes Security","รักษาความปลอดภัย container image และ cluster","High","Required"),
    ("ABB-046","Cloud","Infrastructure as Code Security","ตรวจสอบ IaC template (Terraform, ARM) หา misconfiguration","Medium","Required"),
    # ── Physical & OT (4) ────────────────────────────────────────────────────────
    ("ABB-047","Physical","Physical Access Control","ควบคุมการเข้า-ออก พื้นที่ทางกายภาพ (badge, biometric)","High","Required"),
    ("ABB-048","Physical","CCTV & Surveillance","ระบบกล้องวงจรปิดและการเฝ้าระวังพื้นที่","Medium","Required"),
    ("ABB-049","OT/ICS","OT/ICS Security Monitoring","ตรวจสอบและป้องกันระบบควบคุมอุตสาหกรรม (SCADA/OT)","Critical","Required"),
    ("ABB-050","OT/ICS","Industrial Firewall & DMZ","แยก OT network จาก IT network ด้วย industrial firewall","Critical","Required"),
]

_ESA_SEED_SBB = [
    # ── ABB-001 Identity & Access Management (3 SBBs) ────────────────────────────
    ("SBB-001","ABB-001",None,"Microsoft Entra ID","Latest","Cloud","Active","Azure AD / Entra ID — IAM หลักขององค์กร"),
    ("SBB-002","ABB-001",None,"Okta Workforce Identity","Latest","Cloud","Active","Identity platform สำหรับ enterprise"),
    ("SBB-003","ABB-001",None,"ForgeRock Identity Platform","7.x","On-Premise","Active","Open-source IAM สำหรับ on-premise / hybrid"),
    # ── ABB-002 Privileged Access Management (3 SBBs) ────────────────────────────
    ("SBB-004","ABB-002",None,"CyberArk PAM","14.x","On-Premise","Active","Privileged session management + vault"),
    ("SBB-005","ABB-002",None,"HashiCorp Vault Enterprise","1.15","Hybrid","Active","Secrets & privileged credential management"),
    ("SBB-006","ABB-002",None,"BeyondTrust Password Safe","23.x","Hybrid","Active","PAM + session monitoring + password rotation"),
    # ── ABB-003 Multi-Factor Authentication (3 SBBs) ─────────────────────────────
    ("SBB-007","ABB-003",None,"Microsoft Authenticator","Latest","Cloud","Active","MFA app สำหรับ Microsoft 365"),
    ("SBB-008","ABB-003",None,"Duo Security","Latest","Cloud","Active","MFA platform ครอบคลุม VPN, web, SSH"),
    ("SBB-009","ABB-003",None,"RSA SecurID","8.x","On-Premise","Active","Hardware/Software token MFA"),
    # ── ABB-004 Single Sign-On (3 SBBs) ──────────────────────────────────────────
    ("SBB-010","ABB-004",None,"Microsoft ADFS","Latest","On-Premise","Active","SSO สำหรับ on-premise Active Directory"),
    ("SBB-011","ABB-004",None,"Okta SSO","Latest","Cloud","Active","Cloud SSO ครอบคลุม SaaS + on-prem app"),
    ("SBB-012","ABB-004",None,"Ping Identity PingFederate","12.x","Hybrid","Active","Enterprise SSO + federation hub"),
    # ── ABB-005 Identity Federation & SAML (3 SBBs) ──────────────────────────────
    ("SBB-013","ABB-005",None,"Okta Identity Federation","Latest","Cloud","Active","SAML/OIDC federation กับ external IdP"),
    ("SBB-014","ABB-005",None,"Microsoft Entra ID B2B","Latest","Cloud","Active","Guest/partner identity federation บน Azure"),
    ("SBB-015","ABB-005",None,"Shibboleth IdP","4.x","On-Premise","Active","Open-source SAML IdP สำหรับ education/gov"),
    # ── ABB-006 Certificate & PKI Management (3 SBBs) ────────────────────────────
    ("SBB-016","ABB-006",None,"Microsoft AD Certificate Services","Latest","On-Premise","Active","Internal PKI สำหรับ certificate ภายในองค์กร"),
    ("SBB-017","ABB-006",None,"DigiCert CertCentral","Latest","Cloud","Active","Public certificate lifecycle management"),
    ("SBB-018","ABB-006",None,"Venafi Trust Protection Platform","22.x","Hybrid","Active","Machine identity + PKI automation"),
    # ── ABB-007 Network Access Control (3 SBBs) ──────────────────────────────────
    ("SBB-019","ABB-007",None,"Cisco ISE","3.x","On-Premise","Active","NAC + 802.1X + RADIUS policy"),
    ("SBB-020","ABB-007",None,"Aruba ClearPass","6.x","On-Premise","Active","Policy engine + NAC + guest access"),
    ("SBB-021","ABB-007",None,"Forescout Platform","23.x","Hybrid","Active","Agentless NAC + device visibility"),
    # ── ABB-008 Next-Gen Firewall (3 SBBs) ───────────────────────────────────────
    ("SBB-022","ABB-008",None,"Palo Alto NGFW","11.x","On-Premise","Active","Next-gen firewall + threat prevention"),
    ("SBB-023","ABB-008",None,"Fortinet FortiGate","7.x","On-Premise","Active","NGFW + SD-WAN integrated"),
    ("SBB-024","ABB-008",None,"Check Point NGFW","R81","On-Premise","Active","NGFW + Threat Emulation + IPS"),
    # ── ABB-009 Intrusion Detection & Prevention (3 SBBs) ────────────────────────
    ("SBB-025","ABB-009",None,"Cisco Firepower IPS","7.x","On-Premise","Active","Intrusion prevention ร่วมกับ FTD"),
    ("SBB-026","ABB-009",None,"Snort IDS/IPS","3.x","On-Premise","Active","Open-source IDS/IPS engine"),
    ("SBB-027","ABB-009",None,"Suricata IDS","7.x","On-Premise","Active","High-performance open-source IDS/IPS"),
    # ── ABB-010 Zero Trust Network Access (3 SBBs) ───────────────────────────────
    ("SBB-028","ABB-010",None,"Zscaler Private Access (ZPA)","Latest","Cloud","Active","Zero Trust access สำหรับ remote worker"),
    ("SBB-029","ABB-010",None,"Palo Alto Prisma Access","Latest","Cloud","Active","ZTNA + SASE platform"),
    ("SBB-030","ABB-010",None,"Cloudflare Access","Latest","Cloud","Active","Zero Trust access ผ่าน Cloudflare edge"),
    # ── ABB-011 VPN & Secure Remote Access (3 SBBs) ──────────────────────────────
    ("SBB-031","ABB-011",None,"Cisco AnyConnect / Secure Client","5.x","On-Premise","Active","SSL VPN client สำหรับ remote access"),
    ("SBB-032","ABB-011",None,"Fortinet FortiClient VPN","7.x","On-Premise","Active","VPN + endpoint compliance"),
    ("SBB-033","ABB-011",None,"Palo Alto GlobalProtect","6.x","Hybrid","Active","VPN + HIP check + ZTNA integration"),
    # ── ABB-012 DNS Security (3 SBBs) ────────────────────────────────────────────
    ("SBB-034","ABB-012",None,"Cisco Umbrella","Latest","Cloud","Active","DNS security + secure web gateway"),
    ("SBB-035","ABB-012",None,"Infoblox DNS Security","Latest","Hybrid","Active","DNS firewall + DDI platform"),
    ("SBB-036","ABB-012",None,"Cloudflare Gateway","Latest","Cloud","Active","DNS filtering + secure web gateway"),
    # ── ABB-013 DDoS Protection (3 SBBs) ─────────────────────────────────────────
    ("SBB-037","ABB-013",None,"Cloudflare DDoS Protection","Latest","Cloud","Active","Layer 3/4/7 DDoS mitigation"),
    ("SBB-038","ABB-013",None,"Imperva DDoS Protection","Latest","Cloud","Active","DDoS + CDN + bot protection"),
    ("SBB-039","ABB-013",None,"Akamai Prolexic","Latest","Cloud","Active","High-capacity DDoS scrubbing"),
    # ── ABB-014 Endpoint Detection & Response (3 SBBs) ───────────────────────────
    ("SBB-040","ABB-014",None,"CrowdStrike Falcon","Latest","Cloud","Active","EDR/XDR — AI-powered threat detection"),
    ("SBB-041","ABB-014",None,"Microsoft Defender for Endpoint","Latest","Cloud","Active","EDR ใน Microsoft 365 Defender stack"),
    ("SBB-042","ABB-014",None,"SentinelOne Singularity","Latest","Cloud","Active","Autonomous AI EDR/XDR platform"),
    # ── ABB-015 Mobile Device Management (3 SBBs) ────────────────────────────────
    ("SBB-043","ABB-015",None,"Microsoft Intune","Latest","Cloud","Active","UEM/MDM สำหรับ Windows, iOS, Android"),
    ("SBB-044","ABB-015",None,"VMware Workspace ONE","Latest","Hybrid","Active","UEM + app management + conditional access"),
    ("SBB-045","ABB-015",None,"Jamf Pro","Latest","Cloud","Active","MDM เฉพาะ macOS + iOS"),
    # ── ABB-016 Patch Management (3 SBBs) ────────────────────────────────────────
    ("SBB-046","ABB-016",None,"Microsoft SCCM / Endpoint Manager","Latest","On-Premise","Active","Patch + software deployment สำหรับ Windows"),
    ("SBB-047","ABB-016",None,"Ivanti Patch Management","Latest","Hybrid","Active","Multi-OS patch management"),
    ("SBB-048","ABB-016",None,"ManageEngine Patch Manager Plus","Latest","Hybrid","Active","Automated patching + compliance reporting"),
    # ── ABB-017 Application Whitelisting (3 SBBs) ────────────────────────────────
    ("SBB-049","ABB-017",None,"Carbon Black App Control","Latest","On-Premise","Active","Application whitelisting + file integrity"),
    ("SBB-050","ABB-017",None,"Airlock Digital","Latest","On-Premise","Active","Allow-listing สำหรับ Windows environment"),
    ("SBB-051","ABB-017",None,"Microsoft AppLocker","Latest","On-Premise","Active","Built-in Windows application control policy"),
    # ── ABB-018 Host-based Intrusion Prevention (3 SBBs) ─────────────────────────
    ("SBB-052","ABB-018",None,"Symantec Endpoint Security","14.x","On-Premise","Active","HIPS + AV + device control"),
    ("SBB-053","ABB-018",None,"Trend Micro Deep Security","20.x","Hybrid","Active","HIPS + integrity monitoring + anti-malware"),
    ("SBB-054","ABB-018",None,"OSSEC HIDS","3.x","On-Premise","Active","Open-source HIDS + log analysis"),
    # ── ABB-019 Data Loss Prevention (3 SBBs) ────────────────────────────────────
    ("SBB-055","ABB-019",None,"Forcepoint DLP","Latest","On-Premise","Active","DLP ครอบคลุม network, endpoint, cloud"),
    ("SBB-056","ABB-019",None,"Microsoft Purview DLP","Latest","Cloud","Active","DLP สำหรับ Microsoft 365 + cloud workload"),
    ("SBB-057","ABB-019",None,"Symantec DLP","15.x","On-Premise","Active","Enterprise DLP + data discovery"),
    # ── ABB-020 Encryption & Key Management (3 SBBs) ─────────────────────────────
    ("SBB-058","ABB-020",None,"Thales CipherTrust","Latest","Hybrid","Active","Encryption + KMS + HSM"),
    ("SBB-059","ABB-020",None,"AWS Key Management Service","Latest","Cloud","Active","Cloud-native KMS สำหรับ AWS workload"),
    ("SBB-060","ABB-020",None,"HashiCorp Vault","1.15","Hybrid","Active","Secrets + dynamic credentials + encryption"),
    # ── ABB-021 Database Activity Monitoring (3 SBBs) ────────────────────────────
    ("SBB-061","ABB-021",None,"IBM Guardium","11.x","On-Premise","Active","DAM + data masking + compliance reporting"),
    ("SBB-062","ABB-021",None,"Imperva Database Security","Latest","Hybrid","Active","Real-time DB monitoring + threat analytics"),
    ("SBB-063","ABB-021",None,"McAfee Database Security","Latest","On-Premise","Active","Database intrusion prevention + auditing"),
    # ── ABB-022 Data Classification (3 SBBs) ─────────────────────────────────────
    ("SBB-064","ABB-022",None,"Microsoft Purview Information Protection","Latest","Cloud","Active","Data classification + sensitivity labeling"),
    ("SBB-065","ABB-022",None,"Titus Classification Suite","Latest","Hybrid","Active","Email/document classification + labeling"),
    ("SBB-066","ABB-022",None,"Boldon James Classifier","Latest","On-Premise","Active","Metadata-based data classification"),
    # ── ABB-023 Backup & Disaster Recovery (3 SBBs) ──────────────────────────────
    ("SBB-067","ABB-023",None,"Veeam Backup & Replication","12.x","On-Premise","Active","Backup/restore สำหรับ VM + cloud workload"),
    ("SBB-068","ABB-023",None,"Commvault Complete","Latest","Hybrid","Active","Enterprise backup + data management"),
    ("SBB-069","ABB-023",None,"Zerto","Latest","Cloud","Active","Continuous replication + disaster recovery"),
    # ── ABB-024 Data Masking & Tokenization (3 SBBs) ─────────────────────────────
    ("SBB-070","ABB-024",None,"Delphix Data Masking","Latest","On-Premise","Active","Dynamic data masking สำหรับ non-prod"),
    ("SBB-071","ABB-024",None,"Protegrity","Latest","Hybrid","Active","Tokenization + field-level encryption"),
    ("SBB-072","ABB-024",None,"IBM InfoSphere Optim","Latest","On-Premise","Active","Data masking + test data management"),
    # ── ABB-025 Web Application Firewall (3 SBBs) ────────────────────────────────
    ("SBB-073","ABB-025",None,"F5 Advanced WAF","16.x","On-Premise","Active","WAF + bot protection + L7 DDoS"),
    ("SBB-074","ABB-025",None,"Cloudflare WAF","Latest","Cloud","Active","Cloud WAF ครอบคลุม OWASP Top 10"),
    ("SBB-075","ABB-025",None,"Imperva WAF","Latest","Hybrid","Active","WAF + DDoS + API protection"),
    # ── ABB-026 API Security Gateway (3 SBBs) ────────────────────────────────────
    ("SBB-076","ABB-026",None,"Apigee API Gateway","Latest","Cloud","Active","API management + security สำหรับ Google Cloud"),
    ("SBB-077","ABB-026",None,"Kong API Gateway","3.x","Hybrid","Active","Open-source API gateway + plugins"),
    ("SBB-078","ABB-026",None,"AWS API Gateway","Latest","Cloud","Active","Managed API gateway บน AWS"),
    # ── ABB-027 Static Application Security Testing (3 SBBs) ─────────────────────
    ("SBB-079","ABB-027",None,"Checkmarx SAST","Latest","On-Premise","Active","Static code analysis สำหรับ Java, .NET, Python"),
    ("SBB-080","ABB-027",None,"Veracode Static Analysis","Latest","Cloud","Active","Cloud-based SAST + IDE integration"),
    ("SBB-081","ABB-027",None,"SonarQube","10.x","On-Premise","Active","Code quality + security vulnerability scanning"),
    # ── ABB-028 Dynamic Application Security Testing (3 SBBs) ────────────────────
    ("SBB-082","ABB-028",None,"OWASP ZAP","Latest","On-Premise","Active","Open-source DAST tool สำหรับ web app"),
    ("SBB-083","ABB-028",None,"Burp Suite Enterprise","Latest","On-Premise","Active","Professional web vulnerability scanner"),
    ("SBB-084","ABB-028",None,"Veracode DAST","Latest","Cloud","Active","Cloud-based DAST + API security testing"),
    # ── ABB-029 Software Composition Analysis (3 SBBs) ───────────────────────────
    ("SBB-085","ABB-029",None,"Snyk","Latest","Cloud","Active","SCA + container vulnerability scanning"),
    ("SBB-086","ABB-029",None,"Black Duck (Synopsys)","Latest","Hybrid","Active","Open-source license + security scanning"),
    ("SBB-087","ABB-029",None,"Mend (WhiteSource)","Latest","Cloud","Active","SCA + fix recommendations"),
    # ── ABB-030 Secrets Management (3 SBBs) ──────────────────────────────────────
    ("SBB-088","ABB-030",None,"HashiCorp Vault","1.15","Hybrid","Active","Secrets management สำหรับ application"),
    ("SBB-089","ABB-030",None,"AWS Secrets Manager","Latest","Cloud","Active","Managed secrets rotation บน AWS"),
    ("SBB-090","ABB-030",None,"CyberArk Conjur","Latest","Hybrid","Active","Secrets management สำหรับ DevOps pipeline"),
    # ── ABB-031 SIEM (3 SBBs) ────────────────────────────────────────────────────
    ("SBB-091","ABB-031",None,"Microsoft Sentinel","Latest","Cloud","Active","Cloud-native SIEM + SOAR บน Azure"),
    ("SBB-092","ABB-031",None,"Splunk Enterprise Security","9.x","On-Premise","Active","Enterprise SIEM พร้อม analytics"),
    ("SBB-093","ABB-031",None,"IBM QRadar","7.5","On-Premise","Active","SIEM + UBA + threat intelligence"),
    # ── ABB-032 Vulnerability Management (3 SBBs) ────────────────────────────────
    ("SBB-094","ABB-032",None,"Tenable Nessus / Tenable.io","Latest","Hybrid","Active","Vulnerability scanner ครอบคลุม network/cloud"),
    ("SBB-095","ABB-032",None,"Qualys VMDR","Latest","Cloud","Active","Cloud-native vulnerability + compliance"),
    ("SBB-096","ABB-032",None,"Rapid7 InsightVM","Latest","Hybrid","Active","Vulnerability management + risk scoring"),
    # ── ABB-033 User & Entity Behavior Analytics (3 SBBs) ────────────────────────
    ("SBB-097","ABB-033",None,"Microsoft Sentinel UEBA","Latest","Cloud","Active","UEBA ใน Microsoft Sentinel"),
    ("SBB-098","ABB-033",None,"Splunk UBA","Latest","On-Premise","Active","ML-based user behavior analytics"),
    ("SBB-099","ABB-033",None,"Varonis Data Security Platform","Latest","Hybrid","Active","UEBA + data access governance"),
    # ── ABB-034 Threat Intelligence Platform (3 SBBs) ────────────────────────────
    ("SBB-100","ABB-034",None,"MISP (Threat Intelligence Platform)","Latest","On-Premise","Active","Open-source threat intelligence sharing"),
    ("SBB-101","ABB-034",None,"Recorded Future","Latest","Cloud","Active","Commercial threat intelligence + risk scores"),
    ("SBB-102","ABB-034",None,"CrowdStrike Falcon Intelligence","Latest","Cloud","Active","AI-powered threat intelligence"),
    # ── ABB-035 Security Orchestration & Automation (3 SBBs) ─────────────────────
    ("SBB-103","ABB-035",None,"Splunk SOAR (Phantom)","Latest","On-Premise","Active","Security automation + playbook execution"),
    ("SBB-104","ABB-035",None,"Microsoft Sentinel SOAR","Latest","Cloud","Active","Logic App-based SOAR ใน Sentinel"),
    ("SBB-105","ABB-035",None,"Palo Alto XSOAR","Latest","Hybrid","Active","Enterprise SOAR + case management"),
    # ── ABB-036 Network Traffic Analysis (3 SBBs) ────────────────────────────────
    ("SBB-106","ABB-036",None,"Darktrace","Latest","Hybrid","Active","AI-powered network traffic analysis"),
    ("SBB-107","ABB-036",None,"Vectra AI","Latest","Cloud","Active","NDR + AI threat detection"),
    ("SBB-108","ABB-036",None,"ExtraHop Reveal(x)","Latest","Hybrid","Active","Network detection + response (NDR)"),
    # ── ABB-037 Security Policy Management (3 SBBs) ──────────────────────────────
    ("SBB-109","ABB-037",None,"Microsoft Purview Compliance Manager","Latest","Cloud","Active","Security policy + compliance score"),
    ("SBB-110","ABB-037",None,"Telos Xacta","Latest","Hybrid","Active","Policy management + continuous authorization"),
    ("SBB-111","ABB-037",None,"TrustArc Policy Manager","Latest","Cloud","Active","Privacy + policy management platform"),
    # ── ABB-038 Risk Management Framework (3 SBBs) ───────────────────────────────
    ("SBB-112","ABB-038",None,"ServiceNow GRC","Latest","Cloud","Active","Risk + compliance management platform"),
    ("SBB-113","ABB-038",None,"RSA Archer Risk Management","6.x","On-Premise","Active","Enterprise risk + control management"),
    ("SBB-114","ABB-038",None,"MetricStream GRC","Latest","Cloud","Active","Integrated GRC + risk analytics"),
    # ── ABB-039 Compliance & Audit Management (3 SBBs) ───────────────────────────
    ("SBB-115","ABB-039",None,"RSA Archer","6.x","On-Premise","Active","Compliance + audit management"),
    ("SBB-116","ABB-039",None,"Workiva Compliance","Latest","Cloud","Active","Compliance reporting + audit trail"),
    ("SBB-117","ABB-039",None,"AuditBoard","Latest","Cloud","Active","Audit management + SOX + compliance"),
    # ── ABB-040 Security Awareness Training (3 SBBs) ─────────────────────────────
    ("SBB-118","ABB-040",None,"KnowBe4","Latest","Cloud","Active","Security awareness training + phishing sim"),
    ("SBB-119","ABB-040",None,"Proofpoint Security Awareness","Latest","Cloud","Active","Phishing simulation + training"),
    ("SBB-120","ABB-040",None,"SANS Security Awareness","Latest","Cloud","Active","Role-based security training"),
    # ── ABB-041 Third-Party Risk Management (3 SBBs) ─────────────────────────────
    ("SBB-121","ABB-041",None,"BitSight Security Ratings","Latest","Cloud","Active","Third-party risk rating + monitoring"),
    ("SBB-122","ABB-041",None,"OneTrust Vendor Risk","Latest","Cloud","Active","Vendor risk assessment + questionnaires"),
    ("SBB-123","ABB-041",None,"ProcessUnity TPRM","Latest","Cloud","Active","Third-party risk + lifecycle management"),
    # ── ABB-042 Cloud Security Posture Management (3 SBBs) ───────────────────────
    ("SBB-124","ABB-042",None,"Microsoft Defender for Cloud","Latest","Cloud","Active","CSPM + CWPP สำหรับ Azure / multi-cloud"),
    ("SBB-125","ABB-042",None,"Prisma Cloud CSPM","Latest","Cloud","Active","Multi-cloud security posture management"),
    ("SBB-126","ABB-042",None,"Wiz","Latest","Cloud","Active","Cloud security graph + misconfiguration detection"),
    # ── ABB-043 Cloud Workload Protection Platform (3 SBBs) ──────────────────────
    ("SBB-127","ABB-043",None,"Prisma Cloud CWPP","Latest","Cloud","Active","Cloud workload protection — VM, container, serverless"),
    ("SBB-128","ABB-043",None,"Microsoft Defender for Cloud Workloads","Latest","Cloud","Active","Workload protection ใน Azure Defender"),
    ("SBB-129","ABB-043",None,"Trend Micro Cloud One","Latest","Cloud","Active","Cloud security + workload protection"),
    # ── ABB-044 Cloud Access Security Broker (3 SBBs) ────────────────────────────
    ("SBB-130","ABB-044",None,"Microsoft Defender for Cloud Apps","Latest","Cloud","Active","CASB ใน Microsoft 365 — ควบคุม shadow IT"),
    ("SBB-131","ABB-044",None,"Netskope CASB","Latest","Cloud","Active","Inline + API CASB + DLP"),
    ("SBB-132","ABB-044",None,"Skyhigh Security CASB","Latest","Cloud","Active","Cloud access governance + threat protection"),
    # ── ABB-045 Container & Kubernetes Security (3 SBBs) ─────────────────────────
    ("SBB-133","ABB-045",None,"Aqua Security Platform","Latest","Hybrid","Active","Container/K8s security — image scan + runtime"),
    ("SBB-134","ABB-045",None,"Sysdig Secure","Latest","Cloud","Active","Runtime container security + Falco-based"),
    ("SBB-135","ABB-045",None,"Prisma Cloud Container Security","Latest","Cloud","Active","Container image scanning + runtime protection"),
    # ── ABB-046 Infrastructure as Code Security (3 SBBs) ─────────────────────────
    ("SBB-136","ABB-046",None,"Checkov by Bridgecrew","Latest","On-Premise","Active","IaC scanning — Terraform, ARM, CloudFormation"),
    ("SBB-137","ABB-046",None,"Terraform Sentinel","Latest","Hybrid","Active","Policy-as-code สำหรับ Terraform"),
    ("SBB-138","ABB-046",None,"KICS (Keeping Infrastructure as Code Secure)","Latest","On-Premise","Active","Open-source IaC security scanner"),
    # ── ABB-047 Physical Access Control (3 SBBs) ─────────────────────────────────
    ("SBB-139","ABB-047",None,"HID Global Access Control","Latest","On-Premise","Active","Smart card + biometric physical access"),
    ("SBB-140","ABB-047",None,"Lenel S2 OnGuard","Latest","On-Premise","Active","Physical access control + visitor management"),
    ("SBB-141","ABB-047",None,"Genetec Security Center","Latest","Hybrid","Active","Unified physical security platform"),
    # ── ABB-048 CCTV & Surveillance (3 SBBs) ─────────────────────────────────────
    ("SBB-142","ABB-048",None,"Milestone XProtect VMS","Latest","On-Premise","Active","Video management system สำหรับ CCTV"),
    ("SBB-143","ABB-048",None,"Axis Camera Station","Latest","On-Premise","Active","IP camera management + analytics"),
    ("SBB-144","ABB-048",None,"Genetec Omnicast","Latest","Hybrid","Active","Enterprise video surveillance platform"),
    # ── ABB-049 OT/ICS Security Monitoring (3 SBBs) ──────────────────────────────
    ("SBB-145","ABB-049",None,"Claroty Platform","Latest","On-Premise","Active","OT/ICS asset visibility + threat detection"),
    ("SBB-146","ABB-049",None,"Dragos Platform","Latest","On-Premise","Active","ICS/OT threat detection + incident response"),
    ("SBB-147","ABB-049",None,"Nozomi Networks","Latest","Hybrid","Active","OT + IoT security monitoring"),
    # ── ABB-050 Industrial Firewall & DMZ (3 SBBs) ───────────────────────────────
    ("SBB-148","ABB-050",None,"Fortinet FortiGate Rugged","Latest","On-Premise","Active","Industrial NGFW สำหรับ OT-IT segmentation"),
    ("SBB-149","ABB-050",None,"Cisco Industrial FW (IR1101)","Latest","On-Premise","Active","Industrial router + firewall สำหรับ OT"),
    ("SBB-150","ABB-050",None,"Tofino Xenon Industrial Security","Latest","On-Premise","Active","Deep packet inspection สำหรับ SCADA protocol"),
]

@contextmanager
def get_esa_db():
    conn = sqlite3.connect(ESA_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_esa_db():
    import hashlib
    now = datetime.utcnow().isoformat()
    _COVLEVEL = ["Covered","Covered","Covered","Covered","Partial","Partial","Planned"]

    with get_esa_db() as conn:
        conn.executescript(ESA_DDL)
        # Seed ABB
        if conn.execute("SELECT COUNT(*) FROM abb").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO abb(id,domain,name,description,criticality,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],now,now) for r in _ESA_SEED_ABB]
            )
        # Seed SBB
        if conn.execute("SELECT COUNT(*) FROM sbb").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO sbb(id,abb_id,vendor_id,product_name,version,deployment_type,status,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],now,now) for r in _ESA_SEED_SBB]
            )
        # Seed Coverage — each app covers exactly 10 ABBs (deterministic), with linked SBB
        if conn.execute("SELECT COUNT(*) FROM abb_app_coverage").fetchone()[0] == 0:
            try:
                _ac = sqlite3.connect(DB_PATH)
                app_rows = _ac.execute("SELECT id FROM applications ORDER BY id").fetchall()
                _ac.close()
            except Exception:
                app_rows = []
            abb_ids = [r[0] for r in conn.execute("SELECT id FROM abb ORDER BY id").fetchall()]
            # Build sbb lookup: abb_id → [sbb_id, ...]
            sbb_map: dict = {}
            for sbb_id, abb_id in conn.execute("SELECT id, abb_id FROM sbb ORDER BY id").fetchall():
                sbb_map.setdefault(abb_id, []).append(sbb_id)
            coverage_rows = []
            for (app_id,) in app_rows:
                # Pick 10 ABBs per app via deterministic score sort
                scored = sorted(
                    (int(hashlib.md5(f"{app_id}:{a}".encode()).hexdigest(), 16), a)
                    for a in abb_ids
                )
                for _, abb_id in scored[:10]:
                    sbbs = sbb_map.get(abb_id, [])
                    h    = int(hashlib.md5(f"{app_id}:{abb_id}".encode()).hexdigest(), 16)
                    sbb_id   = sbbs[h % len(sbbs)] if sbbs else None
                    cov_lvl  = _COVLEVEL[h % len(_COVLEVEL)]
                    coverage_rows.append((
                        f"COV-{app_id}-{abb_id}",
                        abb_id, str(app_id), sbb_id, cov_lvl, now, now
                    ))
            conn.executemany(
                "INSERT OR IGNORE INTO abb_app_coverage"
                "(id,abb_id,app_id,sbb_id,coverage_level,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                coverage_rows
            )
            print(f"  Coverage seeded: {len(coverage_rows)} rows"
                  f" ({len(app_rows)} apps × 10 ABBs, with sbb_id linked)")
    print(f"ESA DB ready: {ESA_DB_PATH}")

# ─── EA DOMAINS DB ─────────────────────────────────────────────────────────────
@contextmanager
def get_ea_domains_db():
    conn = sqlite3.connect(EA_DOMAINS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_ea_domains_db():
    import hashlib
    now = datetime.utcnow().isoformat()

    _BAM_LEVELS  = ["Primary","Primary","Primary","Supporting","Supporting","Planned"]
    _DATA_ROLES  = ["Owner","Owner","Producer","Consumer","Consumer","Planned"]
    _FIT_LEVELS  = ["Good Fit","Good Fit","Partial Fit","Partial Fit","Workaround","Gap"]
    _COMPLIANCE  = ["Compliant","Compliant","Compliant","Partial","Partial","Non-Compliant"]

    with get_ea_domains_db() as conn:
        conn.executescript(EA_DOMAINS_DDL)

        # ── EBA seed ───────────────────────────────────────────────────────────
        if conn.execute("SELECT COUNT(*) FROM bcap").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO bcap(id,domain,name,description,priority,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],now,now) for r in _EBA_SEED_BCAP]
            )
        if conn.execute("SELECT COUNT(*) FROM bprocess").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO bprocess(id,bcap_id,name,type,framework,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],now,now) for r in _EBA_SEED_BPROCESS]
            )
        if conn.execute("SELECT COUNT(*) FROM bcap_app_map").fetchone()[0] == 0:
            try:
                _ac = sqlite3.connect(DB_PATH)
                app_rows = _ac.execute("SELECT id FROM applications ORDER BY id").fetchall()
                _ac.close()
            except Exception:
                app_rows = []
            bcap_ids = [r[0] for r in conn.execute("SELECT id FROM bcap ORDER BY id").fetchall()]
            bprc_map: dict = {}
            for bprc_id, bcap_id in conn.execute("SELECT id, bcap_id FROM bprocess ORDER BY id").fetchall():
                bprc_map.setdefault(bcap_id, []).append(bprc_id)
            rows = []
            for (app_id,) in app_rows:
                scored = sorted(
                    (int(hashlib.md5(f"eba:{app_id}:{c}".encode()).hexdigest(), 16), c)
                    for c in bcap_ids
                )
                for _, bcap_id in scored[:10]:
                    h = int(hashlib.md5(f"eba:{app_id}:{bcap_id}".encode()).hexdigest(), 16)
                    prcs = bprc_map.get(bcap_id, [])
                    bprc_id = prcs[h % len(prcs)] if prcs else None
                    rows.append((f"BAM-{app_id}-{bcap_id}", bcap_id, str(app_id), bprc_id, _BAM_LEVELS[h % len(_BAM_LEVELS)], now, now))
            conn.executemany(
                "INSERT OR IGNORE INTO bcap_app_map(id,bcap_id,app_id,bprocess_id,support_level,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                rows
            )
            print(f"  EBA coverage seeded: {len(rows)} rows")

        # ── EDA seed ───────────────────────────────────────────────────────────
        if conn.execute("SELECT COUNT(*) FROM ddomain").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO ddomain(id,domain,name,owner,description,classification,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],now,now) for r in _EDA_SEED_DDOMAIN]
            )
        if conn.execute("SELECT COUNT(*) FROM dasset").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO dasset(id,ddomain_id,name,type,platform,status,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],now,now) for r in _EDA_SEED_DASSET]
            )
        if conn.execute("SELECT COUNT(*) FROM ddomain_app_map").fetchone()[0] == 0:
            try:
                _ac = sqlite3.connect(DB_PATH)
                app_rows = _ac.execute("SELECT id FROM applications ORDER BY id").fetchall()
                _ac.close()
            except Exception:
                app_rows = []
            ddom_ids = [r[0] for r in conn.execute("SELECT id FROM ddomain ORDER BY id").fetchall()]
            dasset_map: dict = {}
            for da_id, dd_id in conn.execute("SELECT id, ddomain_id FROM dasset ORDER BY id").fetchall():
                dasset_map.setdefault(dd_id, []).append(da_id)
            rows = []
            for (app_id,) in app_rows:
                scored = sorted(
                    (int(hashlib.md5(f"eda:{app_id}:{d}".encode()).hexdigest(), 16), d)
                    for d in ddom_ids
                )
                for _, dd_id in scored[:8]:
                    h = int(hashlib.md5(f"eda:{app_id}:{dd_id}".encode()).hexdigest(), 16)
                    das = dasset_map.get(dd_id, [])
                    da_id = das[h % len(das)] if das else None
                    rows.append((f"DAM-{app_id}-{dd_id}", dd_id, str(app_id), da_id, _DATA_ROLES[h % len(_DATA_ROLES)], now, now))
            conn.executemany(
                "INSERT OR IGNORE INTO ddomain_app_map(id,ddomain_id,app_id,dasset_id,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                rows
            )
            print(f"  EDA coverage seeded: {len(rows)} rows")

        # ── EAA seed ───────────────────────────────────────────────────────────
        if conn.execute("SELECT COUNT(*) FROM acap").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO acap(id,domain,name,type,description,priority,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],now,now) for r in _EAA_SEED_ACAP]
            )
        if conn.execute("SELECT COUNT(*) FROM appsys").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO appsys(id,acap_id,name,vendor,status,lifecycle,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],now,now) for r in _EAA_SEED_APPSYS]
            )
        if conn.execute("SELECT COUNT(*) FROM acap_app_map").fetchone()[0] == 0:
            try:
                _ac = sqlite3.connect(DB_PATH)
                app_rows = _ac.execute("SELECT id FROM applications ORDER BY id").fetchall()
                _ac.close()
            except Exception:
                app_rows = []
            acap_ids = [r[0] for r in conn.execute("SELECT id FROM acap ORDER BY id").fetchall()]
            asys_map: dict = {}
            for as_id, ac_id in conn.execute("SELECT id, acap_id FROM appsys ORDER BY id").fetchall():
                asys_map.setdefault(ac_id, []).append(as_id)
            rows = []
            for (app_id,) in app_rows:
                scored = sorted(
                    (int(hashlib.md5(f"eaa:{app_id}:{c}".encode()).hexdigest(), 16), c)
                    for c in acap_ids
                )
                for _, acap_id in scored[:8]:
                    h = int(hashlib.md5(f"eaa:{app_id}:{acap_id}".encode()).hexdigest(), 16)
                    sys_ = asys_map.get(acap_id, [])
                    asys_id = sys_[h % len(sys_)] if sys_ else None
                    rows.append((f"AAM-{app_id}-{acap_id}", acap_id, str(app_id), asys_id, _FIT_LEVELS[h % len(_FIT_LEVELS)], now, now))
            conn.executemany(
                "INSERT OR IGNORE INTO acap_app_map(id,acap_id,app_id,appsys_id,fit_level,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                rows
            )
            print(f"  EAA coverage seeded: {len(rows)} rows")

        # ── ETA seed ───────────────────────────────────────────────────────────
        if conn.execute("SELECT COUNT(*) FROM tstd").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO tstd(id,domain,name,radar_status,description,lifecycle,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],now,now) for r in _ETA_SEED_TSTD]
            )
        if conn.execute("SELECT COUNT(*) FROM tprod").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO tprod(id,tstd_id,name,vendor,version,lifecycle,status,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],now,now) for r in _ETA_SEED_TPROD]
            )
        if conn.execute("SELECT COUNT(*) FROM tstd_app_map").fetchone()[0] == 0:
            try:
                _ac = sqlite3.connect(DB_PATH)
                app_rows = _ac.execute("SELECT id FROM applications ORDER BY id").fetchall()
                _ac.close()
            except Exception:
                app_rows = []
            tstd_ids = [r[0] for r in conn.execute("SELECT id FROM tstd ORDER BY id").fetchall()]
            tprod_map: dict = {}
            for tp_id, ts_id in conn.execute("SELECT id, tstd_id FROM tprod ORDER BY id").fetchall():
                tprod_map.setdefault(ts_id, []).append(tp_id)
            rows = []
            for (app_id,) in app_rows:
                scored = sorted(
                    (int(hashlib.md5(f"eta:{app_id}:{t}".encode()).hexdigest(), 16), t)
                    for t in tstd_ids
                )
                for _, tstd_id in scored[:10]:
                    h = int(hashlib.md5(f"eta:{app_id}:{tstd_id}".encode()).hexdigest(), 16)
                    prds = tprod_map.get(tstd_id, [])
                    tprod_id = prds[h % len(prds)] if prds else None
                    rows.append((f"TAM-{app_id}-{tstd_id}", tstd_id, str(app_id), tprod_id, _COMPLIANCE[h % len(_COMPLIANCE)], now, now))
            conn.executemany(
                "INSERT OR IGNORE INTO tstd_app_map(id,tstd_id,app_id,tprod_id,compliance,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                rows
            )
            print(f"  ETA coverage seeded: {len(rows)} rows")

    print(f"EA Domains DB ready: {EA_DOMAINS_DB_PATH}")

# ─── CROSS-DB CONNECTION (SQLite ATTACH) ──────────────────────────────────────
@contextmanager
def get_connected_db():
    """Opens appport.db and ATTACHes vendor.db (AS vendor) + appport_audit.db (AS audit).

    Enables cross-DB JOINs using qualified names:
        main.*   → appport.db   (applications, projects, roadmap_items …)
        vendor.* → vendor.db    (vendors, vendor_engagements, vendor_capabilities)
        audit.*  → appport_audit.db (audit_log)

    All three databases share the same connection and commit atomically.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"ATTACH DATABASE '{VENDOR_DB_PATH}' AS vendor")
    conn.execute(f"ATTACH DATABASE '{AUDIT_DB_PATH}'  AS audit")
    conn.execute(f"ATTACH DATABASE '{ESA_DB_PATH}'          AS esa")
    conn.execute(f"ATTACH DATABASE '{EA_DOMAINS_DB_PATH}'  AS ead")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            conn.execute("DETACH DATABASE vendor")
            conn.execute("DETACH DATABASE audit")
            conn.execute("DETACH DATABASE esa")
            conn.execute("DETACH DATABASE ead")
        except Exception:
            pass
        conn.close()

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
              actor_ip: str = None,
              resource_type: str = "APP",   # APP | VENDOR | ENGAGEMENT | PROJECT | SYSTEM
              resource_id: str = None,
              before_state: dict = None, after_state: dict = None,
              risk_flags: list = None, extra: dict = None,
              duration_ms: int = None, status_code: int = None,
              message: str = None):
    """Non-blocking write to audit_log table (includes resource_type for cross-DB traceability)."""
    try:
        with get_audit_db() as conn:
            conn.execute("""INSERT INTO audit_log
                (log_id, ts, category, event_type, severity, actor_ip,
                 resource_type, resource_id, before_state, after_state,
                 risk_flags, extra, duration_ms, status_code, message)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                str(uuid.uuid4()),
                datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                category, event_type, severity, actor_ip,
                resource_type, resource_id,
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
CREATE TABLE IF NOT EXISTS roadmap_items (
    id           TEXT PRIMARY KEY,
    app_id       TEXT,
    title        TEXT NOT NULL,
    lane         TEXT DEFAULT 'New',
    start_qtr    TEXT NOT NULL,
    end_qtr      TEXT NOT NULL,
    wave         INTEGER DEFAULT 1,
    budget       REAL DEFAULT 0,
    owner        TEXT DEFAULT '',
    status       TEXT DEFAULT 'Planning',
    priority     TEXT DEFAULT 'Medium',
    color        TEXT DEFAULT '',
    notes        TEXT DEFAULT '',
    created_at   TEXT,
    updated_at   TEXT
);
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

CREATE TABLE IF NOT EXISTS projects (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    roadmap_id      TEXT DEFAULT '',
    type            TEXT DEFAULT 'Upgrade',
    status          TEXT DEFAULT 'Planning',
    priority        TEXT DEFAULT 'Medium',
    health          TEXT DEFAULT 'Green',
    strategic_theme TEXT DEFAULT '',
    pm              TEXT DEFAULT '',
    sponsor         TEXT DEFAULT '',
    budget          REAL DEFAULT 0,
    actual_cost     REAL DEFAULT 0,
    team_size       INTEGER DEFAULT 0,
    planned_start   TEXT DEFAULT '',
    planned_end     TEXT DEFAULT '',
    actual_start    TEXT DEFAULT '',
    actual_end      TEXT DEFAULT '',
    completion_pct  INTEGER DEFAULT 0,
    description     TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TEXT,
    updated_at      TEXT
);
CREATE TABLE IF NOT EXISTS project_apps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    TEXT NOT NULL,
    app_id        TEXT NOT NULL,
    role          TEXT DEFAULT 'Primary',
    impact_level  TEXT DEFAULT 'Medium',
    notes         TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS project_milestones (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    name          TEXT NOT NULL,
    type          TEXT DEFAULT 'Custom',
    planned_date  TEXT DEFAULT '',
    actual_date   TEXT DEFAULT '',
    status        TEXT DEFAULT 'Pending',
    notes         TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS arb_requests (
    id              TEXT PRIMARY KEY,
    request_code    TEXT UNIQUE NOT NULL,
    title           TEXT NOT NULL,
    request_type    TEXT DEFAULT 'New Project',
    review_level    TEXT DEFAULT 'Desk Review',
    status          TEXT DEFAULT 'Draft',
    business_objective TEXT DEFAULT '',
    change_summary  TEXT DEFAULT '',
    business_owner  TEXT DEFAULT '',
    requester_user  TEXT DEFAULT '',
    target_date     TEXT DEFAULT '',
    project_id      TEXT DEFAULT '',
    roadmap_id      TEXT DEFAULT '',
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    submitted_at    TEXT DEFAULT '',
    closed_at       TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS arb_request_applications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id  TEXT NOT NULL,
    application_id  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS arb_impact_profile (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id        TEXT UNIQUE NOT NULL,
    business_impact       TEXT DEFAULT 'None',
    data_impact           TEXT DEFAULT 'None',
    application_impact    TEXT DEFAULT 'None',
    technology_impact     TEXT DEFAULT 'None',
    security_impact       TEXT DEFAULT 'None',
    integration_impact    TEXT DEFAULT 'None',
    compliance_impact     TEXT DEFAULT 'None',
    has_pii               INTEGER DEFAULT 0,
    internet_facing       INTEGER DEFAULT 0,
    new_integration       INTEGER DEFAULT 0,
    new_vendor            INTEGER DEFAULT 0,
    new_technology        INTEGER DEFAULT 0,
    expected_exception    INTEGER DEFAULT 0,
    context_diagram       INTEGER DEFAULT 0,
    data_flow             INTEGER DEFAULT 0,
    interface_list        INTEGER DEFAULT 0,
    security_consideration INTEGER DEFAULT 0,
    solution_summary      INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS arb_reviewers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id  TEXT NOT NULL,
    reviewer_user   TEXT NOT NULL,
    reviewer_role   TEXT DEFAULT 'Reviewer',
    assigned_by     TEXT DEFAULT '',
    assigned_at     TEXT NOT NULL,
    responded_at    TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS arb_comments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id  TEXT NOT NULL,
    reviewer_user   TEXT NOT NULL,
    domain          TEXT DEFAULT 'General',
    comment_type    TEXT DEFAULT 'General',
    comment_text    TEXT NOT NULL,
    severity        TEXT DEFAULT 'Info',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS arb_findings (
    id              TEXT PRIMARY KEY,
    arb_request_id  TEXT NOT NULL,
    category        TEXT DEFAULT 'General',
    domain          TEXT DEFAULT 'General',
    severity        TEXT DEFAULT 'Medium',
    description     TEXT NOT NULL,
    recommended_action TEXT DEFAULT '',
    owner           TEXT DEFAULT '',
    due_date        TEXT DEFAULT '',
    status          TEXT DEFAULT 'Open',
    created_by      TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS arb_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id  TEXT UNIQUE NOT NULL,
    decision_type   TEXT NOT NULL,
    decision_summary TEXT DEFAULT '',
    rationale       TEXT DEFAULT '',
    key_risks       TEXT DEFAULT '',
    required_next_steps TEXT DEFAULT '',
    decided_by      TEXT NOT NULL,
    decided_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS arb_actions (
    id              TEXT PRIMARY KEY,
    arb_request_id  TEXT NOT NULL,
    finding_id      TEXT DEFAULT '',
    action_description TEXT NOT NULL,
    action_type     TEXT DEFAULT 'Condition',
    owner           TEXT DEFAULT '',
    due_date        TEXT DEFAULT '',
    required_evidence TEXT DEFAULT '',
    status          TEXT DEFAULT 'Open',
    closure_note    TEXT DEFAULT '',
    closed_at       TEXT DEFAULT '',
    created_by      TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS arb_recommendations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arb_request_id  TEXT NOT NULL,
    rec_type        TEXT DEFAULT 'artifact',
    ref_code        TEXT DEFAULT '',
    ref_name        TEXT NOT NULL,
    reason_text     TEXT DEFAULT '',
    is_mandatory    INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'Pending'
);
"""

def _seed_projects(conn, now: str):
    """Seed 15 realistic PPM projects linked to roadmap items and apps."""
    projects = [
        ("PRJ-001","Core Banking System Upgrade","RM-0001","Upgrade","Executing - Development","Critical","Yellow","Modernization","Somchai K.","CTO",2500000,1800000,12,"2025-01-15","2025-09-30","2025-02-01","","55","Upgrade Core Banking AS/400 to modern platform","Delayed 2 wks — vendor delivery"),
        ("PRJ-002","ERP Cloud Migration","RM-0002","Migrate","Executing - Requirements","High","Green","Digital Transformation","Nattaya P.","CFO",4800000,900000,15,"2025-04-01","2026-03-31","2025-04-10","","20","Migrate on-premise ERP to cloud with full data migration and cutover",""),
        ("PRJ-003","Legacy HR System Retirement","RM-0003","Retire","Maintenance","High","Green","Cost Reduction","Wanchai S.","HR Director",300000,280000,5,"2025-01-10","2025-06-30","2025-01-15","2025-06-25","100","Retire legacy HR system and migrate all users to WorkDay HCM","Completed on time"),
        ("PRJ-004","New Customer Digital Portal","RM-0004","New","Executing - HLD","High","Green","Digital Transformation","Pattara L.","CDO",3200000,600000,10,"2025-04-01","2026-06-30","2025-04-15","","18","Greenfield customer-facing portal with omni-channel experience","On track"),
        ("PRJ-005","Data Warehouse Modernization","RM-0005","Modernize","Planning - Definition","Medium","Green","Innovation","Kanchana T.","CTO",5500000,0,8,"2025-07-01","2026-12-31","","","0","Migrate legacy DWH to cloud-native lakehouse architecture (Databricks)","Kickoff scheduled Q3-2025"),
        ("PRJ-006","Middleware Platform Update","RM-0006","Upgrade","Executing - Development","Medium","Yellow","Modernization","Chai W.","Infra Director",1200000,700000,6,"2025-04-01","2025-12-31","2025-04-05","","45","Upgrade ESB middleware to API gateway-based integration platform","Resource constraint — 1 engineer on leave"),
        ("PRJ-007","AI/ML Platform Buildout","RM-0007","New","Initiation - Conceptual","High","Green","Innovation","Thanaporn R.","CTO",8000000,0,0,"2026-01-15","2027-06-30","","","0","Enterprise AI/ML platform for predictive analytics and LLM workloads","Budget approved; vendor selection in progress"),
        ("PRJ-008","Zero-Trust Security Platform","RM-0008","Upgrade","Executing - Testing","Critical","Green","Risk Reduction","Prasert N.","CISO",1800000,1100000,9,"2025-01-05","2025-09-30","2025-01-10","","62","Implement zero-trust network access and identity-centric security","On schedule"),
        ("PRJ-009","ERP Phase-out & Data Archive","RM-0009","Migrate","Planning - Definition","Medium","Green","Cost Reduction","Montri A.","ERP Director",2200000,0,7,"2025-07-01","2026-06-30","","","0","Phase out legacy ERP and archive historical data to cold storage","Dependency on PRJ-002 completion"),
        ("PRJ-010","DevSecOps Pipeline","RM-0010","New","Executing - Deployment","Medium","Green","Digital Transformation","Apinya C.","CTO",950000,400000,6,"2025-04-01","2025-12-31","2025-04-01","","42","Build automated CI/CD pipeline with integrated security scanning","Jenkins → GitHub Actions migration 60% done"),
        ("PRJ-011","Customer Data Platform (CDP)","","New","Executing - Requirements","High","Green","Innovation","Siriporn W.","CMO",3800000,0,0,"2026-01-01","2027-03-31","","","0","Unified customer data platform for 360-degree customer view","Awaiting board approval"),
        ("PRJ-012","SAP S4HANA Optimization","","Enhance","Executing - Development","Medium","Green","Cost Reduction","Somchai K.","CFO",600000,250000,4,"2025-03-01","2025-08-31","2025-03-05","","40","Performance tuning and module optimization for SAP S/4HANA Finance",""),
        ("PRJ-013","Network Infrastructure Refresh","","Upgrade","Planning - Definition","Medium","Green","Risk Reduction","Wichai B.","Infra Director",2800000,0,0,"2025-10-01","2026-06-30","","","0","Replace end-of-life network equipment across 5 data centers",""),
        ("PRJ-014","PDPA Compliance Remediation","","Enhance","Closing","High","Green","Compliance","Thida K.","DPO",450000,430000,6,"2025-01-01","2025-05-31","2025-01-03","2025-05-28","100","Remediate data handling processes across all customer-facing systems for PDPA","Completed ahead of schedule"),
        ("PRJ-015","API Gateway Consolidation","","Modernize","On Hold","Low","Red","Modernization","Chai W.","Infra Director",700000,150000,3,"2025-02-01","2025-10-31","2025-02-10","","15","Consolidate 4 disparate API gateways into unified platform","On hold — resource reallocation to PRJ-008"),
    ]
    for p in projects:
        conn.execute("""INSERT OR IGNORE INTO projects
            (id,name,roadmap_id,type,status,priority,health,strategic_theme,pm,sponsor,
             budget,actual_cost,team_size,planned_start,planned_end,actual_start,actual_end,
             completion_pct,description,notes,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (*p, now, now))

    # project_apps: link projects → applications
    pa = [
        ("PRJ-001","APP-001","Primary","High",""),
        ("PRJ-001","APP-003","Migration Source","High","Legacy AS/400 being replaced"),
        ("PRJ-002","APP-002","Primary","High",""),
        ("PRJ-002","APP-015","Supporting","Medium","Integration dependency"),
        ("PRJ-002","APP-020","Supporting","Low",""),
        ("PRJ-003","APP-004","Primary","High","WorkDay HCM target system"),
        ("PRJ-004","APP-045","Primary","High","New app under development"),
        ("PRJ-004","APP-002","Supporting","Medium","CRM integration"),
        ("PRJ-005","APP-008","Primary","High","Legacy DWH being modernized"),
        ("PRJ-005","APP-005","Supporting","High","AI Analytics will consume new DWH"),
        ("PRJ-006","APP-006","Primary","High",""),
        ("PRJ-006","APP-007","Supporting","Medium",""),
        ("PRJ-007","APP-005","Supporting","High","AI Hub dependency"),
        ("PRJ-008","APP-010","Primary","High",""),
        ("PRJ-008","APP-001","Supporting","High",""),
        ("PRJ-008","APP-002","Supporting","Medium",""),
        ("PRJ-009","APP-015","Primary","High","Legacy ERP to be phased out"),
        ("PRJ-009","APP-002","Migration Target","High",""),
        ("PRJ-010","APP-010","Supporting","Medium",""),
        ("PRJ-010","APP-006","Supporting","Low",""),
        ("PRJ-012","APP-001","Primary","Medium",""),
        ("PRJ-014","APP-002","Primary","High",""),
        ("PRJ-014","APP-004","Primary","High",""),
        ("PRJ-014","APP-045","Supporting","Medium",""),
        ("PRJ-015","APP-006","Primary","Medium",""),
        ("PRJ-015","APP-007","Primary","Medium",""),
    ]
    conn.executemany("""INSERT OR IGNORE INTO project_apps
        (project_id,app_id,role,impact_level,notes) VALUES (?,?,?,?,?)""", pa)

    # project_milestones
    ms = [
        # PRJ-001
        ("MS-001-1","PRJ-001","Project Kickoff","Kickoff","2025-01-15","2025-02-01","Completed",""),
        ("MS-001-2","PRJ-001","Requirements & Design","Design","2025-02-15","2025-03-10","Completed",""),
        ("MS-001-3","PRJ-001","Development & Config","Development","2025-03-15","2025-04-20","Completed",""),
        ("MS-001-4","PRJ-001","SIT Testing","Custom","2025-05-01","2025-05-28","Completed",""),
        ("MS-001-5","PRJ-001","UAT","UAT","2025-06-01","","Delayed","Delayed — waiting on business signoff"),
        ("MS-001-6","PRJ-001","Go-Live","Go-Live","2025-08-01","","Pending",""),
        ("MS-001-7","PRJ-001","Project Closure","Closure","2025-09-30","","Pending",""),
        # PRJ-002
        ("MS-002-1","PRJ-002","Kickoff","Kickoff","2025-04-01","2025-04-10","Completed",""),
        ("MS-002-2","PRJ-002","Architecture Design","Design","2025-04-15","2025-05-05","Completed",""),
        ("MS-002-3","PRJ-002","Data Migration Prep","Custom","2025-06-01","","In Progress",""),
        ("MS-002-4","PRJ-002","UAT Phase 1","UAT","2025-10-01","","Pending",""),
        ("MS-002-5","PRJ-002","Cutover & Go-Live","Go-Live","2026-02-01","","Pending",""),
        # PRJ-003 (Completed)
        ("MS-003-1","PRJ-003","Kickoff","Kickoff","2025-01-10","2025-01-15","Completed",""),
        ("MS-003-2","PRJ-003","Data Migration","Development","2025-02-01","2025-02-28","Completed",""),
        ("MS-003-3","PRJ-003","UAT","UAT","2025-04-01","2025-04-25","Completed",""),
        ("MS-003-4","PRJ-003","Go-Live","Go-Live","2025-06-01","2025-06-10","Completed","Ahead of schedule"),
        ("MS-003-5","PRJ-003","System Decomm","Closure","2025-06-30","2025-06-25","Completed",""),
        # PRJ-008
        ("MS-008-1","PRJ-008","Kickoff","Kickoff","2025-01-05","2025-01-10","Completed",""),
        ("MS-008-2","PRJ-008","Identity Platform Deploy","Development","2025-02-01","2025-02-15","Completed",""),
        ("MS-008-3","PRJ-008","Policy Rollout Phase 1","Custom","2025-04-01","2025-04-12","Completed",""),
        ("MS-008-4","PRJ-008","Policy Rollout Phase 2","Custom","2025-06-01","","In Progress",""),
        ("MS-008-5","PRJ-008","Full ZTA Coverage","Go-Live","2025-08-01","","Pending",""),
        # PRJ-010
        ("MS-010-1","PRJ-010","Kickoff","Kickoff","2025-04-01","2025-04-01","Completed",""),
        ("MS-010-2","PRJ-010","Pipeline Design","Design","2025-04-15","2025-04-20","Completed",""),
        ("MS-010-3","PRJ-010","CI/CD Migration","Development","2025-05-01","2025-05-15","Completed",""),
        ("MS-010-4","PRJ-010","Security Scanning Integration","Custom","2025-07-01","","In Progress",""),
        ("MS-010-5","PRJ-010","Full Rollout","Go-Live","2025-10-01","","Pending",""),
    ]
    conn.executemany("""INSERT OR IGNORE INTO project_milestones
        (id,project_id,name,type,planned_date,actual_date,status,notes) VALUES (?,?,?,?,?,?,?,?)""", ms)
    print(f"  Seeded {len(projects)} projects, {len(pa)} app-links, {len(ms)} milestones")


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

        # Migration: re-assign compliance if DB still has old 6-standard format
        _NEW_STANDARDS = {"TOGAF 10th Ed.", "COBIT 2019", "ITIL 4", "ISO/IEC 27001",
                          "NIST CSF 2.0", "GDPR / Thailand PDPA", "ISO 22301"}
        try:
            _sample = conn.execute(
                "SELECT compliance FROM applications WHERE compliance IS NOT NULL AND compliance!='[]' LIMIT 30"
            ).fetchall()
            _found = {v for row in _sample for v in json.loads(row[0] or "[]")}
            if _found and not (_found & _NEW_STANDARDS):   # none of the new standards present
                print("  Migration: re-assigning compliance with expanded standards…")
                _rows = [dict(r) for r in conn.execute("SELECT * FROM applications").fetchall()]
                _rows = _assign_compliance(_rows)
                conn.executemany(
                    "UPDATE applications SET compliance=? WHERE id=?",
                    [(r["compliance"], r["id"]) for r in _rows]
                )
                print(f"    Updated compliance for {len(_rows)} apps")
        except Exception as _ex:
            print(f"  Warning: compliance migration skipped ({_ex})")

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
        if conn.execute("SELECT COUNT(*) FROM roadmap_items").fetchone()[0] == 0:
            now = datetime.now().strftime("%Y-%m-%d")
            sample_items = [
                ("RM-0001", "APP-001", "Core Banking Upgrade",     "Upgrade",   "2025-Q1", "2025-Q3", 1, 2500000, "IT Director", "In Progress", "High",   "#00d68f", ""),
                ("RM-0002", "APP-002", "ERP Migration to Cloud",   "Migrate",   "2025-Q2", "2026-Q1", 1, 4800000, "EA Team",     "Planning",    "High",   "#4a9eff", ""),
                ("RM-0003", "APP-005", "Legacy HR System Retire",  "Retire",    "2025-Q1", "2025-Q2", 1,  300000, "HR Owner",    "In Progress", "Medium", "#ff4757", "Migrate users to new HCM"),
                ("RM-0004", None,      "New Customer Portal",      "New",       "2025-Q2", "2026-Q2", 1, 3200000, "Digital Team","Planning",    "High",   "#7b61ff", "Greenfield project"),
                ("RM-0005", "APP-008", "Data Warehouse Modernize", "Modernize", "2025-Q3", "2026-Q4", 2, 5500000, "Data Team",   "Planning",    "Medium", "#ffa000", ""),
                ("RM-0006", "APP-003", "Middleware Platform Update","Upgrade",  "2025-Q2", "2025-Q4", 1, 1200000, "Infra Team",  "Planning",    "Medium", "#00d68f", ""),
                ("RM-0007", None,      "AI/ML Platform",           "New",       "2026-Q1", "2027-Q2", 3, 8000000, "CTO Office",  "Planning",    "High",   "#7b61ff", "Strategic initiative"),
                ("RM-0008", "APP-010", "Security Platform Upgrade","Upgrade",   "2025-Q1", "2025-Q3", 1, 1800000, "CISO",        "In Progress", "High",   "#00d68f", "Zero Trust implementation"),
                ("RM-0009", "APP-015", "ERP Phase-out",            "Migrate",   "2025-Q3", "2026-Q2", 2, 2200000, "ERP Team",    "Planning",    "Medium", "#4a9eff", ""),
                ("RM-0010", None,      "DevSecOps Pipeline",       "New",       "2025-Q2", "2025-Q4", 1,  950000, "DevOps Team", "In Progress", "Medium", "#7b61ff", ""),
            ]
            for item in sample_items:
                conn.execute("""INSERT OR IGNORE INTO roadmap_items
                    (id,app_id,title,lane,start_qtr,end_qtr,wave,budget,owner,status,priority,color,notes,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (*item, now, now))
            print(f"  Seeded {len(sample_items)} roadmap items")
        # ── PPM Projects seed ──────────────────────────────────────────────────
        if conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0:
            _seed_projects(conn, now if 'now' in dir() else datetime.now().strftime("%Y-%m-%d"))

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

class RoadmapItemWrite(BaseModel):
    app_id:    Optional[str] = None
    title:     str
    lane:      Optional[str] = "New"
    start_qtr: str           # e.g. "2025-Q1"
    end_qtr:   str           # e.g. "2026-Q2"
    wave:      Optional[int] = 1
    budget:    Optional[float] = 0
    owner:     Optional[str] = ""
    status:    Optional[str] = "Planning"
    priority:  Optional[str] = "Medium"
    color:     Optional[str] = ""
    notes:     Optional[str] = ""

# ── Auth dependency ────────────────────────────────────────────────────────────
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
_bearer = HTTPBearer(auto_error=False)

def _require_auth(creds: Optional[Any] = Depends(_bearer)) -> dict:
    # FIX #4: When auth is disabled, give limited viewer role (not admin)
    if not _AUTH_ENABLED:
        return {"sub": "anonymous", "roles": ["editor"], "menus": ["*"], "display_name": "Anonymous (No-Auth Mode)"}
    token = creds.credentials if creds else None
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = _verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

# FIX #6: Role-based write guard dependencies ──────────────────────────────────
def _require_writer(current_user: dict = Depends(_require_auth)) -> dict:
    """editor or admin can create/update/delete data objects."""
    roles = set(current_user.get("roles", []))
    if not roles.intersection({"editor", "admin"}):
        raise HTTPException(403, "Write access requires editor or admin role")
    return current_user

def _require_vendor_writer(current_user: dict = Depends(_require_auth)) -> dict:
    """vendor, editor, or admin can write vendor / engagement data."""
    roles = set(current_user.get("roles", []))
    if not roles.intersection({"vendor", "editor", "admin"}):
        raise HTTPException(403, "Vendor write access requires vendor, editor, or admin role")
    return current_user

def _require_admin_role(current_user: dict = Depends(_require_auth)) -> dict:
    """Only admin can perform this action."""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(403, "Admin role required")
    return current_user

class LoginBody(BaseModel):
    username: str
    password: str

class UpdateUserBody(BaseModel):
    menus: Optional[list] = None
    roles: Optional[list] = None
    active: Optional[bool] = None
    display_name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None

class CreateUserBody(BaseModel):
    username: str
    password: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[list] = None
    menus: Optional[list] = None

class ChangePasswordBody(BaseModel):
    username: str
    current_password: str
    new_password: str

class ProjectWrite(BaseModel):
    name: Optional[str] = None
    roadmap_id: Optional[str] = ""
    type: Optional[str] = "Upgrade"
    status: Optional[str] = "Planning"
    priority: Optional[str] = "Medium"
    health: Optional[str] = "Green"
    strategic_theme: Optional[str] = ""
    pm: Optional[str] = ""
    sponsor: Optional[str] = ""
    budget: Optional[float] = 0
    actual_cost: Optional[float] = 0
    team_size: Optional[int] = 0
    planned_start: Optional[str] = ""
    planned_end: Optional[str] = ""
    actual_start: Optional[str] = ""
    actual_end: Optional[str] = ""
    completion_pct: Optional[int] = 0
    description: Optional[str] = ""
    notes: Optional[str] = ""

class ProjectAppLink(BaseModel):
    app_id: str
    role: Optional[str] = "Primary"
    impact_level: Optional[str] = "Medium"
    notes: Optional[str] = ""

class ProjectMilestoneWrite(BaseModel):
    name: str
    type: Optional[str] = "Custom"
    planned_date: Optional[str] = ""
    actual_date: Optional[str] = ""
    status: Optional[str] = "Pending"
    notes: Optional[str] = ""

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

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def r_auth_login(body: LoginBody):
    # FIX #4: No-auth mode no longer grants admin (limited editor token)
    if not _AUTH_ENABLED:
        exp = datetime.now().timestamp() + 8 * 3600  # 8-hour expiry (not year 2286)
        return {
            "token": _create_jwt({"sub": "anonymous", "roles": ["editor"], "menus": ["*"], "exp": exp}),
            "user": {"username": "anonymous", "display_name": "Anonymous (No-Auth Mode)", "roles": ["editor"], "menus": ["*"]},
        }
    username = (body.username or "").strip().lower()
    password = body.password or ""
    # FIX #2: Check rate limit before looking up user (prevents user enumeration timing)
    _check_login_rate(username)
    users = _UCFG.get("users", {})
    user = users.get(username)
    if not user or not user.get("active", True):
        _record_failed_attempt(username)
        raise HTTPException(401, "Invalid credentials")
    if not _verify_password(password, user.get("password_hash", "")):
        _record_failed_attempt(username)
        raise HTTPException(401, "Invalid credentials")
    # Successful login — clear failed attempts
    _clear_failed_attempts(username)
    expire_mins = _UCFG.get("token_expire_minutes", 480)
    exp = datetime.now().timestamp() + expire_mins * 60
    payload = {"sub": username, "roles": user.get("roles", []), "menus": user.get("menus", []),
               "display_name": user.get("display_name", username), "email": user.get("email", ""), "exp": exp}
    token = _create_jwt(payload)
    return {"token": token, "user": {"username": username, **{k: v for k, v in payload.items() if k != "sub"}}}

@app.get("/api/auth/me")
def r_auth_me(current_user: dict = Depends(_require_auth)):
    return current_user

@app.post("/api/auth/logout")
def r_auth_logout(creds: Optional[Any] = Depends(_bearer), current_user: dict = Depends(_require_auth)):
    # FIX #3: Blacklist the token so it cannot be reused after logout
    token = creds.credentials if creds else None
    if token:
        _blacklist_token(token)
    return {"message": "Logged out"}

@app.get("/api/auth/users")
def r_auth_users(current_user: dict = Depends(_require_auth)):
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(403, "Admin only")
    if not _UCFG: return []
    result = []
    for uname, udata in _UCFG.get("users", {}).items():
        result.append({"username": uname, "display_name": udata.get("display_name", uname),
                       "email": udata.get("email", ""), "roles": udata.get("roles", []),
                       "menus": udata.get("menus", []), "active": udata.get("active", True)})
    return result

@app.put("/api/auth/users/{username}")
def r_auth_update_user(username: str, body: UpdateUserBody, current_user: dict = Depends(_require_auth)):
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(403, "Admin only")
    if not _UCFG: raise HTTPException(503, "Auth not configured")
    users = _UCFG.get("users", {})
    if username not in users: raise HTTPException(404, "User not found")
    u = users[username]
    # FIX #9: Validate roles before updating
    if body.roles is not None:
        invalid_roles = [r for r in body.roles if r not in _ALLOWED_ROLES]
        if invalid_roles:
            raise HTTPException(400, f"Invalid roles: {invalid_roles}. Allowed values: {sorted(_ALLOWED_ROLES)}")
        u["roles"] = body.roles
    if body.menus        is not None: u["menus"]        = body.menus
    if body.active       is not None: u["active"]       = body.active
    if body.display_name is not None: u["display_name"] = body.display_name
    if body.email        is not None: u["email"]        = body.email
    if body.password:
        # FIX #7: Enforce password complexity on admin-set password too
        _validate_password_strength(body.password)
        u["password_hash"] = _hash_password(body.password)
    cfg_path = os.path.join(_BASE, "users.config.json")
    with open(cfg_path, "w") as f:
        json.dump(_UCFG, f, indent=2, ensure_ascii=False)
    return {"username": username, "message": "Updated"}

@app.post("/api/auth/users", status_code=201)
def r_auth_create_user(body: CreateUserBody, current_user: dict = Depends(_require_auth)):
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(403, "Admin only")
    if not _UCFG: raise HTTPException(503, "Auth not configured")
    # FIX #9: Validate that requested roles are from the allowed set
    requested_roles = body.roles or ["viewer"]
    invalid_roles = [r for r in requested_roles if r not in _ALLOWED_ROLES]
    if invalid_roles:
        raise HTTPException(400, f"Invalid roles: {invalid_roles}. Allowed values: {sorted(_ALLOWED_ROLES)}")
    # FIX #7: Enforce password complexity on new users
    _validate_password_strength(body.password)
    users = _UCFG.setdefault("users", {})
    if body.username in users:
        raise HTTPException(409, f"User '{body.username}' already exists")
    users[body.username] = {
        "password_hash": _hash_password(body.password),
        "display_name": body.display_name or body.username,
        "email": body.email or "",
        "roles": requested_roles,
        "menus": body.menus or ["dashboard"],
        "active": True,
    }
    cfg_path = os.path.join(_BASE, "users.config.json")
    with open(cfg_path, "w") as f:
        json.dump(_UCFG, f, indent=2, ensure_ascii=False)
    # FIX #10: removed dead _load_users_config() call — _UCFG already mutated in-place
    return {"username": body.username, "message": "Created"}

@app.delete("/api/auth/users/{username}")
def r_auth_delete_user(username: str, current_user: dict = Depends(_require_auth)):
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(403, "Admin only")
    if not _UCFG: raise HTTPException(503, "Auth not configured")
    users = _UCFG.get("users", {})
    if username not in users: raise HTTPException(404, "User not found")
    if username == current_user.get("username"):
        raise HTTPException(400, "Cannot delete your own account")
    del users[username]
    cfg_path = os.path.join(_BASE, "users.config.json")
    with open(cfg_path, "w") as f:
        json.dump(_UCFG, f, indent=2, ensure_ascii=False)
    # FIX #10: removed dead _load_users_config() call — _UCFG already mutated in-place
    return {"username": username, "message": "Deleted"}

@app.post("/api/auth/change-password")
def r_auth_change_password(body: ChangePasswordBody, current_user: dict = Depends(_require_auth)):
    if not _UCFG: raise HTTPException(503, "Auth not configured")
    is_admin = "admin" in current_user.get("roles", [])

    # BUG-B fix: normalize username before ownership check and lookup (login stores lowercased)
    target_username = (body.username or "").strip().lower()
    caller_username = current_user.get("sub", "")

    # Ownership: non-admin can only change their own password
    if target_username != caller_username and not is_admin:
        raise HTTPException(403, "Cannot change another user's password")

    users = _UCFG.get("users", {})
    if target_username not in users:
        raise HTTPException(404, "User not found")
    u = users[target_username]

    # BUG-A fix: admin resetting another user's password does NOT need current_password.
    # For self-change (including admin changing own password), current_password is required.
    if target_username == caller_username:
        # FIX #1: correct arg order — plain text first, stored hash second
        if not _verify_password(body.current_password, u.get("password_hash", "")):
            raise HTTPException(401, "Current password is incorrect")

    # BUG-C fix: new password must differ from current password
    if _verify_password(body.new_password, u.get("password_hash", "")):
        raise HTTPException(400, "New password must be different from the current password")

    # FIX #7: Enforce password complexity (min 8 + upper + lower + digit)
    _validate_password_strength(body.new_password)
    u["password_hash"] = _hash_password(body.new_password)
    cfg_path = os.path.join(_BASE, "users.config.json")
    with open(cfg_path, "w") as f:
        json.dump(_UCFG, f, indent=2, ensure_ascii=False)
    # FIX #10: removed dead _load_users_config() call — _UCFG already mutated in-place
    return {"message": "Password changed successfully"}

@app.get("/api/system/stats")
def r_system_stats(current_user: dict = Depends(_require_auth)):
    import shutil, time
    db_path = DB_PATH
    db_size = "—"
    if os.path.exists(db_path):
        sz = os.path.getsize(db_path)
        if sz >= 1024*1024: db_size = f"{sz/1024/1024:.1f} MB"
        elif sz >= 1024: db_size = f"{sz/1024:.1f} KB"
        else: db_size = f"{sz} B"
    app_count = 0
    try:
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) FROM applications WHERE status!='decommissioned'").fetchone()
            app_count = row[0] if row else 0
    except Exception: pass
    user_count = len(_UCFG.get("users", {})) if _UCFG else 0
    return {
        "db_size": db_size,
        "app_count": app_count,
        "user_count": user_count,
        "uptime": "Running",
        "version": "1.0.0",
    }

# ── Roadmap Items ─────────────────────────────────────────────────────────────
def _next_rm_id(conn) -> str:
    row = conn.execute("SELECT id FROM roadmap_items ORDER BY CAST(SUBSTR(id,4) AS INTEGER) DESC LIMIT 1").fetchone()
    if not row: return "RM-0001"
    return f"RM-{int(row[0].split('-')[1])+1:04d}"

def _rm_row(r) -> dict:
    return dict(r)

@app.get("/api/roadmap")
def r_roadmap_list(current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM roadmap_items ORDER BY start_qtr").fetchall()
    return [_rm_row(r) for r in rows]

@app.post("/api/roadmap", status_code=201)
def r_roadmap_create(body: RoadmapItemWrite, current_user: dict = Depends(_require_writer)):
    if not body.title.strip(): raise HTTPException(400, "title required")
    with get_db() as conn:
        rid = _next_rm_id(conn)
        now = datetime.now().strftime("%Y-%m-%d")
        d = body.model_dump() if hasattr(body, 'model_dump') else body.dict()
        conn.execute("""INSERT INTO roadmap_items
            (id,app_id,title,lane,start_qtr,end_qtr,wave,budget,owner,status,priority,color,notes,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, d.get('app_id'), d['title'], d.get('lane','New'), d['start_qtr'], d['end_qtr'],
             d.get('wave',1), d.get('budget',0), d.get('owner',''), d.get('status','Planning'),
             d.get('priority','Medium'), d.get('color',''), d.get('notes',''), now, now))
    return {"id": rid}

@app.put("/api/roadmap/{item_id}")
def r_roadmap_update(item_id: str, body: RoadmapItemWrite, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        if not conn.execute("SELECT id FROM roadmap_items WHERE id=?", (item_id,)).fetchone():
            raise HTTPException(404, "Not found")
        now = datetime.now().strftime("%Y-%m-%d")
        d = body.model_dump() if hasattr(body, 'model_dump') else body.dict()
        conn.execute("""UPDATE roadmap_items SET
            app_id=?,title=?,lane=?,start_qtr=?,end_qtr=?,wave=?,budget=?,owner=?,
            status=?,priority=?,color=?,notes=?,updated_at=? WHERE id=?""",
            (d.get('app_id'), d['title'], d.get('lane','New'), d['start_qtr'], d['end_qtr'],
             d.get('wave',1), d.get('budget',0), d.get('owner',''), d.get('status','Planning'),
             d.get('priority','Medium'), d.get('color',''), d.get('notes',''), now, item_id))
    return {"id": item_id, "message": "Updated"}

@app.delete("/api/roadmap/{item_id}")
def r_roadmap_delete(item_id: str, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        if not conn.execute("SELECT id FROM roadmap_items WHERE id=?", (item_id,)).fetchone():
            raise HTTPException(404, "Not found")
        conn.execute("DELETE FROM roadmap_items WHERE id=?", (item_id,))
    return {"message": "Deleted"}

# ─── ROUTES ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    """Public healthcheck endpoint for Railway — no auth required."""
    return {"status": "ok", "version": APP_VERSION}

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
    # Replaced 7 separate COUNT/SUM queries with a single aggregate query
    with get_db() as conn:
        row = conn.execute("""
            SELECT
                COUNT(*)                                                        AS total_apps,
                SUM(CASE WHEN status='Active'               THEN 1 ELSE 0 END) AS active_apps,
                SUM(CASE WHEN criticality='Mission Critical' THEN 1 ELSE 0 END) AS mission_critical,
                COALESCE(SUM(tco), 0)                                           AS total_tco,
                COUNT(DISTINCT domain)                                          AS domains,
                ROUND(AVG(CAST(health AS REAL)), 1)                             AS avg_health
            FROM applications WHERE decommissioned=0
        """).fetchone()
        decomm = conn.execute("SELECT COUNT(*) FROM applications WHERE decommissioned=1").fetchone()[0]
        result = dict(row)
        result["decommissioned"] = decomm
        return result

@app.get("/api/apps")
def r_list(status: Optional[str]=None, domain: Optional[str]=None,
           bcg: Optional[str]=None, ea_group: Optional[str]=None,
           search: Optional[str]=None, show_decomm: bool=False,
           current_user: dict = Depends(_require_auth)):
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
def r_create(body: AppWrite, request: Request, current_user: dict = Depends(_require_writer)):
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
def r_update(app_id: str, body: AppWrite, request: Request, current_user: dict = Depends(_require_writer)):
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
def r_decommission(app_id: str, body: DecommBody, request: Request, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        row = conn.execute("SELECT id, decommissioned, name, criticality FROM applications WHERE id=?", (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        if row["decommissioned"]: raise HTTPException(400, "Already decommissioned")
        conn.execute("""UPDATE applications SET decommissioned=1, status='Decommissioned',
            decomm_date=?, decomm_reason=?, last_updated=? WHERE id=?""",
            (body.decomm_date, body.decomm_reason, datetime.now().strftime("%Y-%m-%d"), app_id))

    risks = ["MISSION_CRITICAL_DECOMMISSION"] if row["criticality"] == "Mission Critical" else []

    # CASCADE: update open vendor_engagements linked to this app
    cascade_count = 0
    with get_vendor_db() as vconn:
        open_engs = vconn.execute(
            "SELECT engagement_id FROM vendor_engagements WHERE app_id=? AND status!='Completed'",
            (app_id,)
        ).fetchall()
        cascade_count = len(open_engs)
        if cascade_count:
            tag = f"[APP DECOMMISSIONED: {body.decomm_date}]"
            vconn.execute("""
                UPDATE vendor_engagements SET
                    notes = CASE WHEN notes IS NULL OR notes='' THEN ? ELSE notes || ' | ' || ? END,
                    remediation_status = CASE WHEN remediation_status='Open' THEN 'Deferred' ELSE remediation_status END
                WHERE app_id=? AND status!='Completed'""",
                (tag, tag, app_id))
            risks.append("OPEN_ENGAGEMENTS_DEFERRED")

    actor = request.client.host if request.client else None
    write_log(
        category="AUDIT", event_type="APP_DECOMMISSION",
        severity="WARNING" if risks else "INFO",
        actor_ip=actor, resource_type="APP", resource_id=app_id,
        after_state={"decomm_date": body.decomm_date, "decomm_reason": body.decomm_reason,
                     "cascaded_engagements": cascade_count},
        risk_flags=risks if risks else None,
        message=f"Decommissioned {app_id} ({row['name']}) on {body.decomm_date}"
              + (f" — {cascade_count} open engagement(s) deferred" if cascade_count else "")
    )
    return {"id": app_id, "message": "Decommissioned",
            "cascaded_engagements": cascade_count}

class RestoreBody(BaseModel):
    restore_reason: Optional[str] = "ยกเลิกการปลดระวาง"
    restore_status: Optional[str] = "Active"   # Active | Phase-out | To-retire

@app.post("/api/apps/{app_id}/restore")
def r_restore(app_id: str, body: RestoreBody, request: Request, current_user: dict = Depends(_require_writer)):
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
def r_import(body: ImportBody, request: Request = None, current_user: dict = Depends(_require_writer)):
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
              status: Optional[str]=None, search: Optional[str]=None,
              current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        # Build WHERE conditions
        where, p = ["1=1"], []
        if tier:   where.append("v.tier=?");   p.append(tier)
        if type:   where.append("v.type=?");   p.append(type)
        if status: where.append("v.status=?"); p.append(status)
        if search:
            where.append("(v.name LIKE ? OR v.type LIKE ? OR v.contact_name LIKE ?)")
            p.extend([f"%{search}%"]*3)
        where_clause = " AND ".join(where)
        # Single aggregate query — replaces 3 per-row queries (N+3 → 1)
        sql = f"""
            SELECT v.*,
                   COALESCE(c.cap_count, 0) AS cap_count,
                   COALESCE(e.eng_count, 0) AS eng_count,
                   e.last_engagement
            FROM vendors v
            LEFT JOIN (
                SELECT vendor_id, COUNT(*) AS cap_count
                FROM vendor_capabilities
                GROUP BY vendor_id
            ) c ON c.vendor_id = v.vendor_id
            LEFT JOIN (
                SELECT vendor_id,
                       COUNT(*)                                   AS eng_count,
                       MAX(CASE WHEN status='Completed' THEN end_date END) AS last_engagement
                FROM vendor_engagements
                GROUP BY vendor_id
            ) e ON e.vendor_id = v.vendor_id
            WHERE {where_clause}
            ORDER BY v.tier, v.name
        """
        rows = conn.execute(sql, p).fetchall()
        result = []
        for r in rows:
            d = _vrow(r)
            d["cap_count"]      = r["cap_count"]
            d["eng_count"]      = r["eng_count"]
            d["last_engagement"] = r["last_engagement"]
            result.append(d)
    return result

@app.get("/api/vendors/stats")
def r_vendors_stats(current_user: dict = Depends(_require_auth)):
    with get_vendor_db() as conn:
        ytd_start = f"{datetime.now().year}-01-01"
        # 1 query for all vendor aggregates
        v = conn.execute("""
            SELECT
                COUNT(*)                                                   AS total_vendors,
                SUM(CASE WHEN tier='Preferred' THEN 1 ELSE 0 END)         AS preferred,
                SUM(CASE WHEN tier='Approved'  THEN 1 ELSE 0 END)         AS approved
            FROM vendors
        """).fetchone()
        # 1 query for all engagement aggregates
        e = conn.execute("""
            SELECT
                COUNT(*)                                                           AS total_eng,
                SUM(CASE WHEN status='In Progress'          THEN 1  ELSE 0 END)   AS in_progress,
                SUM(CASE WHEN status='Planned'              THEN 1  ELSE 0 END)   AS planned,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN critical ELSE 0 END), 0) AS open_critical,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN high     ELSE 0 END), 0) AS open_high,
                COALESCE(SUM(CASE WHEN start_date>=?        THEN cost    ELSE 0 END), 0) AS cost_ytd,
                ROUND(AVG(CASE WHEN score IS NOT NULL       THEN score   END), 1)  AS avg_score
            FROM vendor_engagements
        """, (ytd_start,)).fetchone()
        return {
            "total_vendors": v["total_vendors"],
            "preferred":     v["preferred"],
            "approved":      v["approved"],
            "total_eng":     e["total_eng"],
            "in_progress":   e["in_progress"],
            "planned":       e["planned"],
            "open_critical": int(e["open_critical"]),
            "open_high":     int(e["open_high"]),
            "cost_ytd":      int(e["cost_ytd"]),
            "avg_score":     e["avg_score"] or 0.0,
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
def r_vendor_create(body: VendorWrite, current_user: dict = Depends(_require_vendor_writer)):
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
def r_vendor_update(vendor_id: str, body: VendorWrite, current_user: dict = Depends(_require_vendor_writer)):
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
                  remediation_status: Optional[str]=None,
                  current_user: dict = Depends(_require_auth)):
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
def r_engagement_create(body: EngagementWrite, current_user: dict = Depends(_require_vendor_writer)):
    if not body.vendor_id: raise HTTPException(400, "vendor_id is required")
    if not body.type:       raise HTTPException(400, "type is required")
    # Cross-DB FK validation: ensure app_id exists in appport.db (if provided)
    if body.app_id:
        with get_db() as appconn:
            if not appconn.execute(
                "SELECT id FROM applications WHERE id=? AND decommissioned=0", (body.app_id,)
            ).fetchone():
                raise HTTPException(400, f"app_id '{body.app_id}' not found or is decommissioned")
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
def r_engagement_update(engagement_id: str, body: EngagementWrite, current_user: dict = Depends(_require_vendor_writer)):
    today = datetime.now().strftime("%Y-%m-%d")
    # Cross-DB: if caller changes app_id, verify it exists and is not decommissioned
    if body.app_id:
        with get_db() as appconn:
            if not appconn.execute(
                "SELECT id FROM applications WHERE id=? AND decommissioned=0", (body.app_id,)
            ).fetchone():
                raise HTTPException(400, f"app_id '{body.app_id}' not found or is decommissioned")
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
    current_user: dict = Depends(_require_auth),
):
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
        count_sql = "SELECT COUNT(*) FROM audit_log WHERE 1=1"
        count_args: list = []
        if category: count_sql += " AND category=?"; count_args.append(category)
        if severity:  count_sql += " AND severity=?"; count_args.append(severity)
        total_row = conn.execute(count_sql, count_args).fetchone()
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

# ─── CROSS-DB DASHBOARD KPI ────────────────────────────────────────────────────
@app.get("/api/dashboard/kpi")
def r_dashboard_kpi(current_user: dict = Depends(_require_auth)):
    """
    Unified KPI aggregating all 3 databases in a single response.
    Covers: Application Portfolio · Vendor & Security · Audit Activity
    """
    today = datetime.now().strftime("%Y-%m-%d")
    ytd_start = f"{datetime.now().year}-01-01"

    # ── appport.db ─────────────────────────────────────────────────────────────
    with get_db() as ac:
        apps = ac.execute("""
            SELECT
                COUNT(*)                                                           AS total_apps,
                SUM(CASE WHEN status='Active'            THEN 1 ELSE 0 END)       AS active_apps,
                SUM(CASE WHEN criticality='Mission Critical' THEN 1 ELSE 0 END)   AS mission_critical,
                SUM(CASE WHEN status IN ('To-retire','Phase-out') THEN 1 ELSE 0 END) AS retiring_apps,
                COALESCE(SUM(tco), 0)                                             AS total_tco,
                COUNT(DISTINCT domain)                                            AS domains,
                ROUND(AVG(CAST(health AS REAL)), 1)                               AS avg_health,
                ROUND(AVG(CAST(tech_debt AS REAL)), 1)                            AS avg_tech_debt,
                SUM(CASE WHEN pi_spi=1 THEN 1 ELSE 0 END)                        AS pi_spi_apps,
                SUM(CASE WHEN dr=1     THEN 1 ELSE 0 END)                         AS dr_covered
            FROM applications WHERE decommissioned=0
        """).fetchone()
        # Projects
        prj = ac.execute("""
            SELECT
                COUNT(*)                                                          AS total_projects,
                SUM(CASE WHEN status='Active'    THEN 1 ELSE 0 END)              AS active_projects,
                SUM(CASE WHEN health='At Risk'   THEN 1 ELSE 0 END)              AS at_risk_projects,
                COALESCE(SUM(budget), 0)                                          AS total_budget,
                COALESCE(SUM(actual_cost), 0)                                     AS total_actual_cost
            FROM projects
        """).fetchone()

    # ── vendor.db ──────────────────────────────────────────────────────────────
    with get_vendor_db() as vc:
        vnd = vc.execute("""
            SELECT
                COUNT(*)                                                          AS total_vendors,
                SUM(CASE WHEN tier='Preferred' THEN 1 ELSE 0 END)                AS preferred_vendors,
                SUM(CASE WHEN status='Active'  THEN 1 ELSE 0 END)                AS active_vendors
            FROM vendors
        """).fetchone()
        eng = vc.execute("""
            SELECT
                COUNT(*)                                                          AS total_engagements,
                SUM(CASE WHEN status='In Progress' THEN 1 ELSE 0 END)            AS active_engagements,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN critical ELSE 0 END), 0) AS open_critical_findings,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN high     ELSE 0 END), 0) AS open_high_findings,
                COALESCE(SUM(CASE WHEN start_date>=?   THEN cost    ELSE 0 END), 0) AS vendor_cost_ytd,
                ROUND(AVG(CASE WHEN score IS NOT NULL  THEN score   END), 1)      AS avg_vendor_score
            FROM vendor_engagements
        """, (ytd_start,)).fetchone()

    # ── audit.db ───────────────────────────────────────────────────────────────
    with get_audit_db() as auc:
        aud = auc.execute("""
            SELECT
                COUNT(*)                                                          AS total_log_entries,
                SUM(CASE WHEN severity='ERROR'   AND ts>=? THEN 1 ELSE 0 END)    AS errors_today,
                SUM(CASE WHEN severity='WARNING' AND ts>=? THEN 1 ELSE 0 END)    AS warnings_today,
                SUM(CASE WHEN risk_flags IS NOT NULL AND risk_flags!='null' THEN 1 ELSE 0 END) AS risk_events,
                SUM(CASE WHEN category='AUTH'    AND ts>=? THEN 1 ELSE 0 END)    AS auth_events_today
            FROM audit_log
        """, (today, today, today)).fetchone()

    return {
        "generated_at": datetime.now().isoformat(),
        "applications": {
            "total":            apps["total_apps"],
            "active":           apps["active_apps"],
            "mission_critical": apps["mission_critical"],
            "retiring":         apps["retiring_apps"],
            "total_tco":        int(apps["total_tco"]),
            "domains":          apps["domains"],
            "avg_health":       apps["avg_health"],
            "avg_tech_debt":    apps["avg_tech_debt"],
            "pi_spi_count":     apps["pi_spi_apps"],
            "dr_covered":       apps["dr_covered"],
        },
        "projects": {
            "total":        prj["total_projects"],
            "active":       prj["active_projects"],
            "at_risk":      prj["at_risk_projects"],
            "total_budget": int(prj["total_budget"]),
            "actual_cost":  int(prj["total_actual_cost"]),
        },
        "vendors": {
            "total":              vnd["total_vendors"],
            "preferred":          vnd["preferred_vendors"],
            "active":             vnd["active_vendors"],
            "total_engagements":  eng["total_engagements"],
            "active_engagements": eng["active_engagements"],
            "open_critical":      int(eng["open_critical_findings"]),
            "open_high":          int(eng["open_high_findings"]),
            "cost_ytd":           int(eng["vendor_cost_ytd"]),
            "avg_score":          eng["avg_vendor_score"] or 0.0,
        },
        "audit": {
            "total_entries":   aud["total_log_entries"],
            "errors_today":    aud["errors_today"],
            "warnings_today":  aud["warnings_today"],
            "risk_events":     aud["risk_events"],
            "auth_events_today": aud["auth_events_today"],
        },
    }


# ─── CROSS-DB APP FULL PROFILE ─────────────────────────────────────────────────
@app.get("/api/apps/{app_id}/full-profile")
def r_app_full_profile(app_id: str, current_user: dict = Depends(_require_auth)):
    """
    Returns a 360° view of one application by joining all 3 databases:
      appport.db  → application record + projects
      vendor.db   → security engagements
      audit.db    → recent audit trail (last 50 events)
    """
    # ── appport.db ─────────────────────────────────────────────────────────────
    with get_db() as ac:
        app_row = ac.execute(
            "SELECT * FROM applications WHERE id=?", (app_id,)
        ).fetchone()
        if not app_row:
            raise HTTPException(404, f"Application '{app_id}' not found")
        app_data = dict(app_row)
        # parse JSON columns
        for col in ("stack", "compliance"):
            try:    app_data[col] = json.loads(app_data[col]) if app_data.get(col) else []
            except: pass
        # Projects linked to this app
        projects = [dict(r) for r in ac.execute("""
            SELECT p.id, p.name, p.status, p.health, p.priority,
                   p.planned_start, p.planned_end, p.completion_pct,
                   pa.role AS app_role
            FROM project_apps pa
            JOIN projects p ON p.id = pa.project_id
            WHERE pa.app_id=?
            ORDER BY p.planned_start DESC
        """, (app_id,)).fetchall()]

    # ── vendor.db ──────────────────────────────────────────────────────────────
    with get_vendor_db() as vc:
        engagements = []
        for r in vc.execute("""
            SELECT e.*, v.name AS vendor_name, v.tier AS vendor_tier
            FROM vendor_engagements e
            JOIN vendors v ON v.vendor_id = e.vendor_id
            WHERE e.app_id=?
            ORDER BY e.start_date DESC
        """, (app_id,)).fetchall():
            engagements.append(_erow(r))
        # Security posture summary for this app
        sec = vc.execute("""
            SELECT
                COUNT(*)                                                          AS total_engagements,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN critical ELSE 0 END), 0) AS open_critical,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN high     ELSE 0 END), 0) AS open_high,
                COALESCE(SUM(CASE WHEN remediation_status!='Closed' THEN medium   ELSE 0 END), 0) AS open_medium,
                COALESCE(SUM(cost), 0)                                            AS total_cost,
                ROUND(AVG(CASE WHEN score IS NOT NULL THEN score END), 1)         AS avg_score
            FROM vendor_engagements WHERE app_id=?
        """, (app_id,)).fetchone()

    # ── audit.db ───────────────────────────────────────────────────────────────
    with get_audit_db() as auc:
        audit_rows = auc.execute("""
            SELECT log_id, ts, category, event_type, severity,
                   actor_ip, resource_type, risk_flags, message
            FROM audit_log
            WHERE resource_id=?
            ORDER BY ts DESC LIMIT 50
        """, (app_id,)).fetchall()
        audit_history = []
        for r in audit_rows:
            d = dict(r)
            try:    d["risk_flags"] = json.loads(d["risk_flags"]) if d.get("risk_flags") else None
            except: pass
            audit_history.append(d)

    return {
        "app":         app_data,
        "projects":    projects,
        "security": {
            "summary":     dict(sec) if sec else {},
            "engagements": engagements,
        },
        "audit_history": audit_history,
    }


# ─── PPM PROJECT ENDPOINTS ─────────────────────────────────────────────────────
def _next_project_id(conn) -> str:
    row = conn.execute(
        "SELECT id FROM projects ORDER BY CAST(SUBSTR(id,5) AS INTEGER) DESC LIMIT 1"
    ).fetchone()
    if not row: return "PRJ-001"
    return f"PRJ-{int(row[0].split('-')[1])+1:03d}"

def _project_row(conn, prj_id: str) -> dict:
    row = conn.execute("SELECT * FROM projects WHERE id=?", (prj_id,)).fetchone()
    if not row: return None
    d = dict(row)
    d["apps"] = [dict(r) for r in conn.execute(
        "SELECT pa.*, a.name as app_name, a.domain, a.criticality FROM project_apps pa "
        "LEFT JOIN applications a ON pa.app_id=a.id WHERE pa.project_id=?", (prj_id,))]
    d["milestones"] = [dict(r) for r in conn.execute(
        "SELECT * FROM project_milestones WHERE project_id=? ORDER BY planned_date", (prj_id,))]
    # join roadmap info
    if d.get("roadmap_id"):
        rm = conn.execute("SELECT title,lane,start_qtr,end_qtr FROM roadmap_items WHERE id=?",
                          (d["roadmap_id"],)).fetchone()
        d["roadmap_info"] = dict(rm) if rm else None
    else:
        d["roadmap_info"] = None
    return d

@app.get("/api/projects")
def r_projects_list(status: Optional[str]=None, priority: Optional[str]=None,
                    health: Optional[str]=None, theme: Optional[str]=None,
                    current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        sql = "SELECT p.*, (SELECT COUNT(*) FROM project_apps WHERE project_id=p.id) as app_count FROM projects p WHERE 1=1"
        params = []
        if status:   sql += " AND p.status=?";   params.append(status)
        if priority: sql += " AND p.priority=?"; params.append(priority)
        if health:   sql += " AND p.health=?";   params.append(health)
        if theme:    sql += " AND p.strategic_theme=?"; params.append(theme)
        sql += " ORDER BY CAST(SUBSTR(p.id,5) AS INTEGER)"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        # attach roadmap titles
        rm_map = {r["id"]: r["title"] for r in conn.execute("SELECT id,title FROM roadmap_items").fetchall()}
        for r in rows:
            r["roadmap_title"] = rm_map.get(r.get("roadmap_id",""), "")
        return rows

@app.get("/api/projects/{prj_id}")
def r_project_get(prj_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        d = _project_row(conn, prj_id)
        if not d: raise HTTPException(404, "Project not found")
        return d

@app.post("/api/projects", status_code=201)
def r_project_create(body: ProjectWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        prj_id = _next_project_id(conn)
        conn.execute("""INSERT INTO projects
            (id,name,roadmap_id,type,status,priority,health,strategic_theme,pm,sponsor,
             budget,actual_cost,team_size,planned_start,planned_end,actual_start,actual_end,
             completion_pct,description,notes,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            prj_id, body.name or "New Project",
            body.roadmap_id or "", body.type or "Upgrade", body.status or "Planning",
            body.priority or "Medium", body.health or "Green", body.strategic_theme or "",
            body.pm or "", body.sponsor or "", body.budget or 0, body.actual_cost or 0,
            body.team_size or 0, body.planned_start or "", body.planned_end or "",
            body.actual_start or "", body.actual_end or "", body.completion_pct or 0,
            body.description or "", body.notes or "", now, now))
        return _project_row(conn, prj_id)

@app.put("/api/projects/{prj_id}")
def r_project_update(prj_id: str, body: ProjectWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        if not conn.execute("SELECT id FROM projects WHERE id=?", (prj_id,)).fetchone():
            raise HTTPException(404, "Project not found")
        fields = {k: v for k, v in body.model_dump().items() if v is not None}
        fields["updated_at"] = now
        sets = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE projects SET {sets} WHERE id=?", (*fields.values(), prj_id))
        return _project_row(conn, prj_id)

@app.delete("/api/projects/{prj_id}", status_code=204)
def r_project_delete(prj_id: str, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        if not conn.execute("SELECT id FROM projects WHERE id=?", (prj_id,)).fetchone():
            raise HTTPException(404, "Project not found")
        conn.execute("DELETE FROM project_apps WHERE project_id=?", (prj_id,))
        conn.execute("DELETE FROM project_milestones WHERE project_id=?", (prj_id,))
        conn.execute("DELETE FROM projects WHERE id=?", (prj_id,))

@app.put("/api/projects/{prj_id}/apps")
def r_project_set_apps(prj_id: str, links: List[ProjectAppLink],
                       current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        if not conn.execute("SELECT id FROM projects WHERE id=?", (prj_id,)).fetchone():
            raise HTTPException(404, "Project not found")
        conn.execute("DELETE FROM project_apps WHERE project_id=?", (prj_id,))
        conn.executemany("""INSERT INTO project_apps (project_id,app_id,role,impact_level,notes)
                           VALUES (?,?,?,?,?)""",
                         [(prj_id, lk.app_id, lk.role, lk.impact_level, lk.notes) for lk in links])
        return _project_row(conn, prj_id)

@app.put("/api/projects/{prj_id}/milestones")
def r_project_set_milestones(prj_id: str, milestones: List[ProjectMilestoneWrite],
                              current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        if not conn.execute("SELECT id FROM projects WHERE id=?", (prj_id,)).fetchone():
            raise HTTPException(404, "Project not found")
        conn.execute("DELETE FROM project_milestones WHERE project_id=?", (prj_id,))
        existing_ids = {r[0] for r in conn.execute("SELECT id FROM project_milestones").fetchall()}
        for i, ms in enumerate(milestones):
            ms_id = f"MS-{prj_id[4:]}-{i+1}"
            while ms_id in existing_ids: ms_id += "x"
            conn.execute("""INSERT INTO project_milestones
                (id,project_id,name,type,planned_date,actual_date,status,notes)
                VALUES (?,?,?,?,?,?,?,?)""",
                (ms_id, prj_id, ms.name, ms.type, ms.planned_date, ms.actual_date, ms.status, ms.notes))
        return _project_row(conn, prj_id)

@app.get("/api/projects-app-impact")
def r_project_app_impact(current_user: dict = Depends(_require_auth)):
    """Return per-app project impact summary for App Impact view."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT a.id, a.name, a.domain, a.criticality,
                   COUNT(pa.id) as project_count,
                   GROUP_CONCAT(p.id || '|' || p.name || '|' || p.status || '|' || p.health || '|' || pa.role, ';;') as projects_info
            FROM applications a
            LEFT JOIN project_apps pa ON pa.app_id = a.id
            LEFT JOIN projects p ON p.id = pa.project_id
            WHERE pa.id IS NOT NULL
            GROUP BY a.id
            ORDER BY COUNT(pa.id) DESC
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            projects_info = []
            if d["projects_info"]:
                for item in d["projects_info"].split(";;"):
                    parts = item.split("|")
                    if len(parts) == 5:
                        projects_info.append({"id": parts[0], "name": parts[1],
                                              "status": parts[2], "health": parts[3], "role": parts[4]})
            d["projects_info"] = projects_info
            result.append(d)
        return result

# ─── ESA API ───────────────────────────────────────────────────────────────────

class AbbWrite(BaseModel):
    domain:      str
    name:        str
    description: Optional[str] = None
    criticality: Optional[str] = "High"
    status:      Optional[str] = "Required"

class SbbWrite(BaseModel):
    abb_id:          str
    vendor_id:       Optional[str] = None
    product_name:    str
    version:         Optional[str] = None
    deployment_type: Optional[str] = "On-Premise"
    status:          Optional[str] = "Active"
    note:            Optional[str] = None

class CoverageWrite(BaseModel):
    abb_id:         str
    app_id:         str
    sbb_id:         Optional[str] = None
    coverage_level: Optional[str] = "None"
    note:           Optional[str] = None

# ── ABB ──────────────────────────────────────────────────────────────────────

@app.get("/api/esa/abb")
def esa_list_abb(domain: Optional[str]=None, current_user: dict = Depends(_require_auth)):
    with get_esa_db() as conn:
        sql, p = "SELECT * FROM abb WHERE 1=1", []
        if domain: sql += " AND domain=?"; p.append(domain)
        rows = conn.execute(sql + " ORDER BY domain, name", p).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/esa/abb", status_code=201)
def esa_create_abb(body: AbbWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    new_id = "ABB-" + uuid.uuid4().hex[:6].upper()
    with get_esa_db() as conn:
        conn.execute(
            "INSERT INTO abb(id,domain,name,description,criticality,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (new_id, body.domain, body.name, body.description, body.criticality, body.status, now, now)
        )
    return {"id": new_id}

@app.put("/api/esa/abb/{abb_id}")
def esa_update_abb(abb_id: str, body: AbbWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM abb WHERE id=?", (abb_id,)).fetchone():
            raise HTTPException(404, f"ABB {abb_id} not found")
        conn.execute(
            "UPDATE abb SET domain=?,name=?,description=?,criticality=?,status=?,updated_at=? WHERE id=?",
            (body.domain, body.name, body.description, body.criticality, body.status, now, abb_id)
        )
    return {"id": abb_id}

@app.delete("/api/esa/abb/{abb_id}")
def esa_delete_abb(abb_id: str, current_user: dict = Depends(_require_writer)):
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM abb WHERE id=?", (abb_id,)).fetchone():
            raise HTTPException(404, f"ABB {abb_id} not found")
        conn.execute("DELETE FROM abb_app_coverage WHERE abb_id=?", (abb_id,))
        conn.execute("DELETE FROM sbb WHERE abb_id=?", (abb_id,))
        conn.execute("DELETE FROM abb WHERE id=?", (abb_id,))
    return {"deleted": abb_id}

# ── SBB ──────────────────────────────────────────────────────────────────────

@app.get("/api/esa/sbb")
def esa_list_sbb(abb_id: Optional[str]=None, current_user: dict = Depends(_require_auth)):
    with get_esa_db() as conn:
        sql = """
            SELECT s.*, a.name AS abb_name, a.domain AS abb_domain
            FROM sbb s JOIN abb a ON s.abb_id=a.id WHERE 1=1
        """
        p = []
        if abb_id: sql += " AND s.abb_id=?"; p.append(abb_id)
        rows = conn.execute(sql + " ORDER BY a.domain, a.name, s.product_name", p).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/esa/sbb", status_code=201)
def esa_create_sbb(body: SbbWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    new_id = "SBB-" + uuid.uuid4().hex[:6].upper()
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM abb WHERE id=?", (body.abb_id,)).fetchone():
            raise HTTPException(400, f"ABB {body.abb_id} not found")
        conn.execute(
            "INSERT INTO sbb(id,abb_id,vendor_id,product_name,version,deployment_type,status,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (new_id, body.abb_id, body.vendor_id, body.product_name, body.version, body.deployment_type, body.status, body.note, now, now)
        )
    return {"id": new_id}

@app.put("/api/esa/sbb/{sbb_id}")
def esa_update_sbb(sbb_id: str, body: SbbWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM sbb WHERE id=?", (sbb_id,)).fetchone():
            raise HTTPException(404, f"SBB {sbb_id} not found")
        conn.execute(
            "UPDATE sbb SET abb_id=?,vendor_id=?,product_name=?,version=?,deployment_type=?,status=?,note=?,updated_at=? WHERE id=?",
            (body.abb_id, body.vendor_id, body.product_name, body.version, body.deployment_type, body.status, body.note, now, sbb_id)
        )
    return {"id": sbb_id}

@app.delete("/api/esa/sbb/{sbb_id}")
def esa_delete_sbb(sbb_id: str, current_user: dict = Depends(_require_writer)):
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM sbb WHERE id=?", (sbb_id,)).fetchone():
            raise HTTPException(404, f"SBB {sbb_id} not found")
        conn.execute("UPDATE abb_app_coverage SET sbb_id=NULL WHERE sbb_id=?", (sbb_id,))
        conn.execute("DELETE FROM sbb WHERE id=?", (sbb_id,))
    return {"deleted": sbb_id}

# ── Coverage ─────────────────────────────────────────────────────────────────

@app.get("/api/esa/coverage")
def esa_list_coverage(app_id: Optional[str]=None, abb_id: Optional[str]=None,
                      current_user: dict = Depends(_require_auth)):
    with get_connected_db() as conn:
        sql = """
            SELECT c.*, a.name AS abb_name, a.domain AS abb_domain, a.criticality,
                   s.product_name AS sbb_name,
                   ap.name AS app_name
            FROM esa.abb_app_coverage c
            JOIN esa.abb a ON c.abb_id=a.id
            LEFT JOIN esa.sbb s ON c.sbb_id=s.id
            LEFT JOIN main.applications ap ON c.app_id=ap.id
            WHERE 1=1
        """
        p = []
        if app_id: sql += " AND c.app_id=?"; p.append(app_id)
        if abb_id: sql += " AND c.abb_id=?"; p.append(abb_id)
        rows = conn.execute(sql + " ORDER BY a.domain, a.name", p).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/esa/coverage", status_code=201)
def esa_upsert_coverage(body: CoverageWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_esa_db() as conn:
        existing = conn.execute(
            "SELECT id FROM abb_app_coverage WHERE abb_id=? AND app_id=?",
            (body.abb_id, body.app_id)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE abb_app_coverage SET sbb_id=?,coverage_level=?,note=?,updated_at=? WHERE id=?",
                (body.sbb_id, body.coverage_level, body.note, now, existing["id"])
            )
            return {"id": existing["id"], "action": "updated"}
        else:
            new_id = "COV-" + uuid.uuid4().hex[:6].upper()
            conn.execute(
                "INSERT INTO abb_app_coverage(id,abb_id,app_id,sbb_id,coverage_level,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (new_id, body.abb_id, body.app_id, body.sbb_id, body.coverage_level, body.note, now, now)
            )
            return {"id": new_id, "action": "created"}

@app.delete("/api/esa/coverage/{cov_id}")
def esa_delete_coverage(cov_id: str, current_user: dict = Depends(_require_writer)):
    with get_esa_db() as conn:
        if not conn.execute("SELECT 1 FROM abb_app_coverage WHERE id=?", (cov_id,)).fetchone():
            raise HTTPException(404, f"Coverage {cov_id} not found")
        conn.execute("DELETE FROM abb_app_coverage WHERE id=?", (cov_id,))
    return {"deleted": cov_id}

@app.get("/api/esa/apps/{app_id}/security")
def esa_app_security(app_id: str, current_user: dict = Depends(_require_auth)):
    """Security coverage summary for one application."""
    with get_connected_db() as conn:
        app_row = conn.execute("SELECT id, name FROM main.applications WHERE id=?", (app_id,)).fetchone()
        if not app_row:
            raise HTTPException(404, f"App {app_id} not found")
        rows = conn.execute("""
            SELECT a.id AS abb_id, a.domain, a.name AS abb_name, a.criticality, a.status AS abb_status,
                   c.id AS cov_id, c.coverage_level, c.note,
                   s.product_name AS sbb_name, s.id AS sbb_id
            FROM esa.abb a
            LEFT JOIN esa.abb_app_coverage c ON a.id=c.abb_id AND c.app_id=?
            LEFT JOIN esa.sbb s ON c.sbb_id=s.id
            ORDER BY a.domain, a.name
        """, (app_id,)).fetchall()
        total   = len(rows)
        covered = sum(1 for r in rows if r["coverage_level"] in ("Full","Covered","Partial"))
        planned = sum(1 for r in rows if r["coverage_level"] == "Planned")
        gaps    = sum(1 for r in rows if r["coverage_level"] in (None,"None","Not Covered"))
    return {
        "app_id":       app_id,
        "app_name":     app_row["name"],
        "total_abb":    total,
        "covered":      covered,
        "planned":      planned,
        "gaps":         gaps,
        "coverage_pct": round(covered / total * 100, 1) if total else 0,
        "items": [dict(r) for r in rows]
    }

# ── Gaps + Summary ────────────────────────────────────────────────────────────

@app.get("/api/esa/gaps")
def esa_gaps(current_user: dict = Depends(_require_auth)):
    """ABBs that have no SBB assigned (product gap) or Critical ABBs with low app coverage."""
    with get_esa_db() as conn:
        no_sbb = conn.execute("""
            SELECT a.id, a.domain, a.name, a.criticality
            FROM abb a
            WHERE NOT EXISTS (SELECT 1 FROM sbb s WHERE s.abb_id=a.id AND s.status='Active')
            ORDER BY a.criticality DESC, a.domain
        """).fetchall()
        no_coverage = conn.execute("""
            SELECT a.id, a.domain, a.name, a.criticality,
                   COUNT(s.id) AS sbb_count
            FROM abb a
            JOIN sbb s ON s.abb_id=a.id AND s.status='Active'
            WHERE NOT EXISTS (SELECT 1 FROM abb_app_coverage c WHERE c.abb_id=a.id)
            GROUP BY a.id
            ORDER BY a.criticality DESC
        """).fetchall()
    return {
        "no_sbb":      [dict(r) for r in no_sbb],
        "no_coverage": [dict(r) for r in no_coverage],
        "total_gaps":  len(no_sbb) + len(no_coverage)
    }

@app.get("/api/esa/summary")
def esa_summary(current_user: dict = Depends(_require_auth)):
    """Domain-level summary: ABB count, SBB count, coverage %."""
    with get_esa_db() as conn:
        domains = conn.execute("""
            SELECT a.domain,
                   COUNT(DISTINCT a.id)                                        AS abb_count,
                   COUNT(DISTINCT s.id)                                        AS sbb_count,
                   COUNT(DISTINCT CASE WHEN s.status='Active' THEN s.id END)   AS active_sbb,
                   COUNT(DISTINCT c.id)                                        AS coverage_count,
                   SUM(CASE WHEN c.coverage_level='Full'    THEN 1 ELSE 0 END) AS full_count,
                   SUM(CASE WHEN c.coverage_level='Partial' THEN 1 ELSE 0 END) AS partial_count
            FROM abb a
            LEFT JOIN sbb s         ON s.abb_id=a.id
            LEFT JOIN abb_app_coverage c ON c.abb_id=a.id
            GROUP BY a.domain
            ORDER BY a.domain
        """).fetchall()
        totals = conn.execute("""
            SELECT COUNT(*) AS total_abb,
                   (SELECT COUNT(*) FROM sbb WHERE status='Active') AS active_sbb,
                   (SELECT COUNT(*) FROM abb WHERE NOT EXISTS
                       (SELECT 1 FROM sbb WHERE abb_id=abb.id AND status='Active')) AS abb_no_sbb
            FROM abb
        """).fetchone()
    return {
        "domains": [dict(r) for r in domains],
        "totals":  dict(totals)
    }

# ─── EA DOMAINS API ────────────────────────────────────────────────────────────

# ── Pydantic models ────────────────────────────────────────────────────────────
class BCapWrite(BaseModel):
    domain: str; name: str; description: Optional[str]=None
    priority: Optional[str]="High"; status: Optional[str]="Active"

class BProcessWrite(BaseModel):
    bcap_id: str; name: str; type: Optional[str]="Core"
    framework: Optional[str]=None; description: Optional[str]=None

class BCapMapWrite(BaseModel):
    bcap_id: str; app_id: str; bprocess_id: Optional[str]=None
    support_level: Optional[str]="None"; note: Optional[str]=None

class DDomainWrite(BaseModel):
    domain: str; name: str; owner: Optional[str]=None
    description: Optional[str]=None; classification: Optional[str]="Internal"
    status: Optional[str]="Active"

class DAssetWrite(BaseModel):
    ddomain_id: str; name: str; type: Optional[str]="Database"
    platform: Optional[str]=None; status: Optional[str]="Active"
    description: Optional[str]=None

class DomainMapWrite(BaseModel):
    ddomain_id: str; app_id: str; dasset_id: Optional[str]=None
    role: Optional[str]="None"; note: Optional[str]=None

class ACapWrite(BaseModel):
    domain: str; name: str; type: Optional[str]="Core"
    description: Optional[str]=None; priority: Optional[str]="High"
    status: Optional[str]="Active"

class AppSysWrite(BaseModel):
    acap_id: str; name: str; vendor: Optional[str]=None
    status: Optional[str]="Active"; lifecycle: Optional[str]="Current"
    description: Optional[str]=None

class ACapMapWrite(BaseModel):
    acap_id: str; app_id: str; appsys_id: Optional[str]=None
    fit_level: Optional[str]="None"; note: Optional[str]=None

class TStdWrite(BaseModel):
    domain: str; name: str; radar_status: Optional[str]="Adopt"
    description: Optional[str]=None; lifecycle: Optional[str]="Current"

class TProdWrite(BaseModel):
    tstd_id: str; name: str; vendor: Optional[str]=None
    version: Optional[str]=None; lifecycle: Optional[str]="Current"
    status: Optional[str]="Active"; description: Optional[str]=None

class TStdMapWrite(BaseModel):
    tstd_id: str; app_id: str; tprod_id: Optional[str]=None
    compliance: Optional[str]="None"; note: Optional[str]=None

# ─── TECH CATALOG MODELS (B32.43) ────────────────────────────────────────────
class TechCatalogWrite(BaseModel):
    name: str; vendor: Optional[str]=None; category: Optional[str]=None
    sub_category: Optional[str]=None; tier: Optional[str]="Tier 2"
    standard_status: Optional[str]="Approved"; website_url: Optional[str]=None
    tags: Optional[str]=None; description: Optional[str]=None

class TechVersionWrite(BaseModel):
    version_label: str; major: Optional[int]=None; minor: Optional[int]=None
    patch: Optional[int]=None; build: Optional[str]=None
    release_type: Optional[str]="GA"; release_date: Optional[str]=None
    eol_date: Optional[str]=None; ext_support_end: Optional[str]=None
    lifecycle_phase: Optional[str]="Active"; release_notes_url: Optional[str]=None
    is_latest: Optional[int]=0; is_lts: Optional[int]=0

class TechServerWrite(BaseModel):
    hostname: str; ip_address: Optional[str]=None
    environment: Optional[str]="Production"; server_type: Optional[str]=None
    location: Optional[str]=None; os_name: Optional[str]=None
    os_version: Optional[str]=None; cpu_core: Optional[int]=None
    ram_gb: Optional[int]=None; managed_by: Optional[str]=None
    status: Optional[str]="Active"; note: Optional[str]=None

class TechUsageWrite(BaseModel):
    tech_id: str; version_id: Optional[str]=None
    usage_target_type: Optional[str]="App"; app_id: Optional[str]=None
    server_id: Optional[str]=None; environment: Optional[str]="Production"
    usage_type: Optional[str]=None; installed_version: Optional[str]=None
    install_date: Optional[str]=None; upgrade_plan: Optional[str]=None
    note: Optional[str]=None

class TechVulnUpdateWrite(BaseModel):
    status: Optional[str]=None; remediation: Optional[str]=None
    remediation_date: Optional[str]=None; assigned_to: Optional[str]=None
    severity: Optional[str]=None

class TechRadarWrite(BaseModel):
    tech_id: str; radar_date: str; ring: str
    quadrant: Optional[str]=None; rationale: Optional[str]=None
    decided_by: Optional[str]=None; prev_ring: Optional[str]=None

# ─── NVD CVE FETCH (B32.43) ──────────────────────────────────────────────────
def _parse_nvd_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

def _fetch_nvd_cves_for_tech(tech_id: str, tech_name: str):
    """Fetch CVEs from NVD API 2.0 for a given technology and upsert into tech_vulnerabilities."""
    if not _NVD_AVAILABLE:
        return {"error": "requests library not installed"}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": tech_name, "resultsPerPage": 20}
    try:
        resp = _requests_lib.get(url, params=params, timeout=20)
        if resp.status_code != 200:
            return {"error": f"NVD API returned {resp.status_code}"}
        data = resp.json()
        fetched_at = datetime.utcnow().isoformat()
        inserted = 0; updated = 0
        with get_ea_domains_db() as conn:
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                # description (English)
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                # CVSS score (try v31 then v30 then v2)
                cvss_score = None; severity = "Info"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metrics = cve.get("metrics", {}).get(metric_key, [])
                    if metrics:
                        cd = metrics[0].get("cvssData", {})
                        cvss_score = cd.get("baseScore")
                        severity = cd.get("baseSeverity", _parse_nvd_severity(cvss_score or 0))
                        break
                if cvss_score and not severity:
                    severity = _parse_nvd_severity(cvss_score)
                published = cve.get("published", "")[:10] if cve.get("published") else ""
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                existing = conn.execute("SELECT id FROM tech_vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
                now = datetime.utcnow().isoformat()
                if existing:
                    conn.execute("UPDATE tech_vulnerabilities SET severity=?,cvss_score=?,description=?,published_date=?,fetched_at=?,updated_at=? WHERE cve_id=?",
                                 (severity, cvss_score, desc, published, fetched_at, now, cve_id))
                    updated += 1
                else:
                    nid = "TVL-" + uuid.uuid4().hex[:6].upper()
                    conn.execute("""INSERT INTO tech_vulnerabilities(id,tech_id,cve_id,severity,cvss_score,description,
                                   published_date,nvd_url,status,source,fetched_at,created_at,updated_at)
                                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                 (nid, tech_id, cve_id, severity, cvss_score, desc, published, nvd_url,
                                  "Open", "NVD", fetched_at, now, now))
                    inserted += 1
        return {"inserted": inserted, "updated": updated, "total_fetched": len(data.get("vulnerabilities", []))}
    except Exception as e:
        return {"error": str(e)}

def _nvd_daily_refresh():
    """Background thread: refresh CVEs for all tech_catalog entries every 24h."""
    time.sleep(300)  # wait 5 min after startup before first run
    while True:
        try:
            with get_ea_domains_db() as conn:
                techs = conn.execute("SELECT id, name FROM tech_catalog WHERE standard_status != 'Banned'").fetchall()
            for tech in techs:
                _fetch_nvd_cves_for_tech(tech["id"], tech["name"])
                time.sleep(6)  # 6s between requests (stay within NVD rate limit)
        except Exception:
            pass
        time.sleep(86400)  # 24 hours

# ─── ARB LITE MODELS ────────────────────────────────────────────────────────────
class ArbRequestWrite(BaseModel):
    title:              Optional[str] = None
    request_type:       Optional[str] = None
    review_level:       Optional[str] = None
    status:             Optional[str] = None
    business_objective: Optional[str] = None
    change_summary:     Optional[str] = None
    business_owner:     Optional[str] = None
    requester_user:     Optional[str] = None
    target_date:        Optional[str] = None
    project_id:         Optional[str] = None
    roadmap_id:         Optional[str] = None
    application_ids:    Optional[List[str]] = None
    impact:             Optional[dict] = None

class ArbCommentWrite(BaseModel):
    domain:       Optional[str] = 'General'
    comment_type: Optional[str] = 'General'
    comment_text: str
    severity:     Optional[str] = 'Info'

class ArbFindingWrite(BaseModel):
    category:           Optional[str] = 'General'
    domain:             Optional[str] = 'General'
    severity:           Optional[str] = 'Medium'
    description:        str
    recommended_action: Optional[str] = ''
    owner:              Optional[str] = ''
    due_date:           Optional[str] = ''

class ArbFindingUpdate(BaseModel):
    severity:           Optional[str] = None
    description:        Optional[str] = None
    recommended_action: Optional[str] = None
    owner:              Optional[str] = None
    due_date:           Optional[str] = None
    status:             Optional[str] = None

class ArbDecisionWrite(BaseModel):
    decision_type:      str
    decision_summary:   Optional[str] = ''
    rationale:          Optional[str] = ''
    key_risks:          Optional[str] = ''
    required_next_steps:Optional[str] = ''

class ArbActionWrite(BaseModel):
    finding_id:         Optional[str] = ''
    action_description: str
    action_type:        Optional[str] = 'Condition'
    owner:              Optional[str] = ''
    due_date:           Optional[str] = ''
    required_evidence:  Optional[str] = ''

class ArbActionUpdate(BaseModel):
    action_description: Optional[str] = None
    action_type:        Optional[str] = None
    owner:              Optional[str] = None
    due_date:           Optional[str] = None
    required_evidence:  Optional[str] = None
    status:             Optional[str] = None
    closure_note:       Optional[str] = None

class ArbReviewerWrite(BaseModel):
    reviewer_user: str
    reviewer_role: Optional[str] = 'Reviewer'

# ────────────────────────────── EBA ────────────────────────────────────────────

@app.get("/api/eba/bcap")
def eba_list_bcap(domain: Optional[str]=None, current_user: dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql, p = "SELECT * FROM bcap WHERE 1=1", []
        if domain: sql += " AND domain=?"; p.append(domain)
        return [dict(r) for r in conn.execute(sql+" ORDER BY domain,name",p).fetchall()]

@app.post("/api/eba/bcap", status_code=201)
def eba_create_bcap(body: BCapWrite, current_user: dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="BCAP-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("INSERT INTO bcap(id,domain,name,description,priority,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.domain,body.name,body.description,body.priority,body.status,now,now))
    return {"id":nid}

@app.put("/api/eba/bcap/{bid}")
def eba_update_bcap(bid:str, body:BCapWrite, current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bcap WHERE id=?",(bid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE bcap SET domain=?,name=?,description=?,priority=?,status=?,updated_at=? WHERE id=?",
                     (body.domain,body.name,body.description,body.priority,body.status,now,bid))
    return {"id":bid}

@app.delete("/api/eba/bcap/{bid}")
def eba_delete_bcap(bid:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bcap WHERE id=?",(bid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM bcap_app_map WHERE bcap_id=?",(bid,))
        conn.execute("DELETE FROM bprocess WHERE bcap_id=?",(bid,))
        conn.execute("DELETE FROM bcap WHERE id=?",(bid,))
    return {"deleted":bid}

@app.get("/api/eba/bprocess")
def eba_list_bprocess(bcap_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql="SELECT p.*,c.name AS bcap_name,c.domain FROM bprocess p JOIN bcap c ON p.bcap_id=c.id WHERE 1=1"; p=[]
        if bcap_id: sql+=" AND p.bcap_id=?"; p.append(bcap_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY c.domain,c.name,p.name",p).fetchall()]

@app.post("/api/eba/bprocess", status_code=201)
def eba_create_bprocess(body:BProcessWrite, current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="BPRC-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bcap WHERE id=?",(body.bcap_id,)).fetchone(): raise HTTPException(400,"BCap not found")
        conn.execute("INSERT INTO bprocess(id,bcap_id,name,type,framework,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.bcap_id,body.name,body.type,body.framework,body.description,now,now))
    return {"id":nid}

@app.put("/api/eba/bprocess/{pid}")
def eba_update_bprocess(pid:str,body:BProcessWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bprocess WHERE id=?",(pid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE bprocess SET bcap_id=?,name=?,type=?,framework=?,description=?,updated_at=? WHERE id=?",
                     (body.bcap_id,body.name,body.type,body.framework,body.description,now,pid))
    return {"id":pid}

@app.delete("/api/eba/bprocess/{pid}")
def eba_delete_bprocess(pid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bprocess WHERE id=?",(pid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM bprocess WHERE id=?",(pid,))
    return {"deleted":pid}

@app.get("/api/eba/coverage")
def eba_list_coverage(app_id: Optional[str]=None, bcap_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        sql="""SELECT m.*,c.name AS bcap_name,c.domain AS bcap_domain,c.priority,
                      p.name AS bprocess_name, ap.name AS app_name
               FROM ead.bcap_app_map m JOIN ead.bcap c ON m.bcap_id=c.id
               LEFT JOIN ead.bprocess p ON m.bprocess_id=p.id
               LEFT JOIN main.applications ap ON m.app_id=ap.id WHERE 1=1"""; ps=[]
        if app_id: sql+=" AND m.app_id=?"; ps.append(app_id)
        if bcap_id: sql+=" AND m.bcap_id=?"; ps.append(bcap_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY c.domain,c.name",ps).fetchall()]

@app.post("/api/eba/coverage", status_code=201)
def eba_upsert_coverage(body:BCapMapWrite, current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        ex=conn.execute("SELECT id FROM bcap_app_map WHERE bcap_id=? AND app_id=?",(body.bcap_id,body.app_id)).fetchone()
        if ex:
            conn.execute("UPDATE bcap_app_map SET bprocess_id=?,support_level=?,note=?,updated_at=? WHERE id=?",
                         (body.bprocess_id,body.support_level,body.note,now,ex["id"]))
            return {"id":ex["id"],"action":"updated"}
        nid="BAM-"+uuid.uuid4().hex[:6].upper()
        conn.execute("INSERT INTO bcap_app_map(id,bcap_id,app_id,bprocess_id,support_level,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.bcap_id,body.app_id,body.bprocess_id,body.support_level,body.note,now,now))
        return {"id":nid,"action":"created"}

@app.delete("/api/eba/coverage/{mid}")
def eba_delete_coverage(mid:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM bcap_app_map WHERE id=?",(mid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM bcap_app_map WHERE id=?",(mid,))
    return {"deleted":mid}

@app.get("/api/eba/apps/{app_id}/business")
def eba_app_business(app_id:str, current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        ar=conn.execute("SELECT id,name FROM main.applications WHERE id=?",(app_id,)).fetchone()
        if not ar: raise HTTPException(404)
        rows=conn.execute("""SELECT c.id AS bcap_id,c.domain,c.name AS bcap_name,c.priority,
                             m.id AS map_id,m.support_level,p.name AS bprocess_name
                             FROM ead.bcap c
                             LEFT JOIN ead.bcap_app_map m ON c.id=m.bcap_id AND m.app_id=?
                             LEFT JOIN ead.bprocess p ON m.bprocess_id=p.id
                             ORDER BY c.domain,c.name""",(app_id,)).fetchall()
        total=len(rows)
        primary=sum(1 for r in rows if r["support_level"]=="Primary")
        supporting=sum(1 for r in rows if r["support_level"]=="Supporting")
        planned=sum(1 for r in rows if r["support_level"]=="Planned")
        gaps=sum(1 for r in rows if r["support_level"] in (None,"None"))
    return {"app_id":app_id,"app_name":ar["name"],"total_bcap":total,
            "primary":primary,"supporting":supporting,"planned":planned,"gaps":gaps,
            "coverage_pct":round((primary+supporting)/total*100,1) if total else 0,
            "items":[dict(r) for r in rows]}

@app.get("/api/eba/gaps")
def eba_gaps(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        no_process=conn.execute("SELECT c.id,c.domain,c.name,c.priority FROM bcap c WHERE NOT EXISTS (SELECT 1 FROM bprocess p WHERE p.bcap_id=c.id) ORDER BY c.priority DESC,c.domain").fetchall()
        no_coverage=conn.execute("SELECT c.id,c.domain,c.name,c.priority,COUNT(m.id) AS mapped_apps FROM bcap c JOIN bprocess p ON p.bcap_id=c.id LEFT JOIN bcap_app_map m ON m.bcap_id=c.id WHERE NOT EXISTS (SELECT 1 FROM bcap_app_map WHERE bcap_id=c.id) GROUP BY c.id ORDER BY c.priority DESC").fetchall()
    return {"no_process":[dict(r) for r in no_process],"no_coverage":[dict(r) for r in no_coverage],"total_gaps":len(no_process)+len(no_coverage)}

@app.get("/api/eba/summary")
def eba_summary(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        domains=conn.execute("""SELECT c.domain,COUNT(DISTINCT c.id) AS bcap_count,COUNT(DISTINCT p.id) AS process_count,
                               SUM(CASE WHEN m.support_level='Primary' THEN 1 ELSE 0 END) AS primary_count,
                               SUM(CASE WHEN m.support_level='Supporting' THEN 1 ELSE 0 END) AS supporting_count,
                               COUNT(DISTINCT m.id) AS mapped_count
                               FROM bcap c LEFT JOIN bprocess p ON p.bcap_id=c.id
                               LEFT JOIN bcap_app_map m ON m.bcap_id=c.id
                               GROUP BY c.domain ORDER BY c.domain""").fetchall()
        totals=conn.execute("SELECT COUNT(*) AS total_bcap,(SELECT COUNT(*) FROM bprocess) AS total_process FROM bcap").fetchone()
    return {"domains":[dict(r) for r in domains],"totals":dict(totals)}

# ────────────────────────────── EDA ────────────────────────────────────────────

@app.get("/api/eda/ddomain")
def eda_list_ddomain(domain: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql,p="SELECT * FROM ddomain WHERE 1=1",[]
        if domain: sql+=" AND domain=?"; p.append(domain)
        return [dict(r) for r in conn.execute(sql+" ORDER BY domain,name",p).fetchall()]

@app.post("/api/eda/ddomain", status_code=201)
def eda_create_ddomain(body:DDomainWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="DDOM-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("INSERT INTO ddomain(id,domain,name,owner,description,classification,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (nid,body.domain,body.name,body.owner,body.description,body.classification,body.status,now,now))
    return {"id":nid}

@app.put("/api/eda/ddomain/{did}")
def eda_update_ddomain(did:str,body:DDomainWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM ddomain WHERE id=?",(did,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE ddomain SET domain=?,name=?,owner=?,description=?,classification=?,status=?,updated_at=? WHERE id=?",
                     (body.domain,body.name,body.owner,body.description,body.classification,body.status,now,did))
    return {"id":did}

@app.delete("/api/eda/ddomain/{did}")
def eda_delete_ddomain(did:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM ddomain WHERE id=?",(did,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM ddomain_app_map WHERE ddomain_id=?",(did,))
        conn.execute("DELETE FROM dasset WHERE ddomain_id=?",(did,))
        conn.execute("DELETE FROM ddomain WHERE id=?",(did,))
    return {"deleted":did}

@app.get("/api/eda/dasset")
def eda_list_dasset(ddomain_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql="SELECT a.*,d.name AS ddomain_name,d.domain FROM dasset a JOIN ddomain d ON a.ddomain_id=d.id WHERE 1=1"; p=[]
        if ddomain_id: sql+=" AND a.ddomain_id=?"; p.append(ddomain_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY d.domain,d.name,a.name",p).fetchall()]

@app.post("/api/eda/dasset", status_code=201)
def eda_create_dasset(body:DAssetWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="DAST-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM ddomain WHERE id=?",(body.ddomain_id,)).fetchone(): raise HTTPException(400,"DDomain not found")
        conn.execute("INSERT INTO dasset(id,ddomain_id,name,type,platform,status,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (nid,body.ddomain_id,body.name,body.type,body.platform,body.status,body.description,now,now))
    return {"id":nid}

@app.put("/api/eda/dasset/{aid}")
def eda_update_dasset(aid:str,body:DAssetWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM dasset WHERE id=?",(aid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE dasset SET ddomain_id=?,name=?,type=?,platform=?,status=?,description=?,updated_at=? WHERE id=?",
                     (body.ddomain_id,body.name,body.type,body.platform,body.status,body.description,now,aid))
    return {"id":aid}

@app.delete("/api/eda/dasset/{aid}")
def eda_delete_dasset(aid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM dasset WHERE id=?",(aid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM dasset WHERE id=?",(aid,))
    return {"deleted":aid}

@app.get("/api/eda/coverage")
def eda_list_coverage(app_id: Optional[str]=None, ddomain_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        sql="""SELECT m.*,d.name AS ddomain_name,d.domain,d.classification,
                      a.name AS dasset_name,ap.name AS app_name
               FROM ead.ddomain_app_map m JOIN ead.ddomain d ON m.ddomain_id=d.id
               LEFT JOIN ead.dasset a ON m.dasset_id=a.id
               LEFT JOIN main.applications ap ON m.app_id=ap.id WHERE 1=1"""; ps=[]
        if app_id: sql+=" AND m.app_id=?"; ps.append(app_id)
        if ddomain_id: sql+=" AND m.ddomain_id=?"; ps.append(ddomain_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY d.domain,d.name",ps).fetchall()]

@app.post("/api/eda/coverage", status_code=201)
def eda_upsert_coverage(body:DomainMapWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        ex=conn.execute("SELECT id FROM ddomain_app_map WHERE ddomain_id=? AND app_id=?",(body.ddomain_id,body.app_id)).fetchone()
        if ex:
            conn.execute("UPDATE ddomain_app_map SET dasset_id=?,role=?,note=?,updated_at=? WHERE id=?",
                         (body.dasset_id,body.role,body.note,now,ex["id"]))
            return {"id":ex["id"],"action":"updated"}
        nid="DAM-"+uuid.uuid4().hex[:6].upper()
        conn.execute("INSERT INTO ddomain_app_map(id,ddomain_id,app_id,dasset_id,role,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.ddomain_id,body.app_id,body.dasset_id,body.role,body.note,now,now))
        return {"id":nid,"action":"created"}

@app.delete("/api/eda/coverage/{mid}")
def eda_delete_coverage(mid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM ddomain_app_map WHERE id=?",(mid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM ddomain_app_map WHERE id=?",(mid,))
    return {"deleted":mid}

@app.get("/api/eda/apps/{app_id}/data")
def eda_app_data(app_id:str,current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        ar=conn.execute("SELECT id,name FROM main.applications WHERE id=?",(app_id,)).fetchone()
        if not ar: raise HTTPException(404)
        rows=conn.execute("""SELECT d.id AS ddomain_id,d.domain,d.name AS ddomain_name,d.classification,
                             m.id AS map_id,m.role,a.name AS dasset_name
                             FROM ead.ddomain d
                             LEFT JOIN ead.ddomain_app_map m ON d.id=m.ddomain_id AND m.app_id=?
                             LEFT JOIN ead.dasset a ON m.dasset_id=a.id
                             ORDER BY d.domain,d.name""",(app_id,)).fetchall()
        total=len(rows)
        owner=sum(1 for r in rows if r["role"]=="Owner")
        producer=sum(1 for r in rows if r["role"]=="Producer")
        consumer=sum(1 for r in rows if r["role"]=="Consumer")
        planned=sum(1 for r in rows if r["role"]=="Planned")
        gaps=sum(1 for r in rows if r["role"] in (None,"None"))
    return {"app_id":app_id,"app_name":ar["name"],"total_ddomain":total,
            "owner":owner,"producer":producer,"consumer":consumer,"planned":planned,"gaps":gaps,
            "coverage_pct":round((owner+producer+consumer)/total*100,1) if total else 0,
            "items":[dict(r) for r in rows]}

@app.get("/api/eda/gaps")
def eda_gaps(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        no_asset=conn.execute("SELECT d.id,d.domain,d.name,d.classification FROM ddomain d WHERE NOT EXISTS (SELECT 1 FROM dasset a WHERE a.ddomain_id=d.id) ORDER BY d.domain").fetchall()
        no_coverage=conn.execute("SELECT d.id,d.domain,d.name,d.classification FROM ddomain d WHERE NOT EXISTS (SELECT 1 FROM ddomain_app_map m WHERE m.ddomain_id=d.id) ORDER BY d.domain").fetchall()
    return {"no_asset":[dict(r) for r in no_asset],"no_coverage":[dict(r) for r in no_coverage],"total_gaps":len(no_asset)+len(no_coverage)}

@app.get("/api/eda/summary")
def eda_summary(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        domains=conn.execute("""SELECT d.domain,COUNT(DISTINCT d.id) AS ddomain_count,COUNT(DISTINCT a.id) AS dasset_count,
                               SUM(CASE WHEN m.role='Owner' THEN 1 ELSE 0 END) AS owner_count,
                               SUM(CASE WHEN m.role='Consumer' THEN 1 ELSE 0 END) AS consumer_count,
                               COUNT(DISTINCT m.id) AS mapped_count
                               FROM ddomain d LEFT JOIN dasset a ON a.ddomain_id=d.id
                               LEFT JOIN ddomain_app_map m ON m.ddomain_id=d.id
                               GROUP BY d.domain ORDER BY d.domain""").fetchall()
        totals=conn.execute("SELECT COUNT(*) AS total_ddomain,(SELECT COUNT(*) FROM dasset) AS total_dasset FROM ddomain").fetchone()
    return {"domains":[dict(r) for r in domains],"totals":dict(totals)}

# ────────────────────────────── EAA ────────────────────────────────────────────

@app.get("/api/eaa/acap")
def eaa_list_acap(domain: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql,p="SELECT * FROM acap WHERE 1=1",[]
        if domain: sql+=" AND domain=?"; p.append(domain)
        return [dict(r) for r in conn.execute(sql+" ORDER BY domain,name",p).fetchall()]

@app.post("/api/eaa/acap", status_code=201)
def eaa_create_acap(body:ACapWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="ACAP-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("INSERT INTO acap(id,domain,name,type,description,priority,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (nid,body.domain,body.name,body.type,body.description,body.priority,body.status,now,now))
    return {"id":nid}

@app.put("/api/eaa/acap/{aid}")
def eaa_update_acap(aid:str,body:ACapWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM acap WHERE id=?",(aid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE acap SET domain=?,name=?,type=?,description=?,priority=?,status=?,updated_at=? WHERE id=?",
                     (body.domain,body.name,body.type,body.description,body.priority,body.status,now,aid))
    return {"id":aid}

@app.delete("/api/eaa/acap/{aid}")
def eaa_delete_acap(aid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM acap WHERE id=?",(aid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM acap_app_map WHERE acap_id=?",(aid,))
        conn.execute("DELETE FROM appsys WHERE acap_id=?",(aid,))
        conn.execute("DELETE FROM acap WHERE id=?",(aid,))
    return {"deleted":aid}

@app.get("/api/eaa/appsys")
def eaa_list_appsys(acap_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql="SELECT s.*,c.name AS acap_name,c.domain FROM appsys s JOIN acap c ON s.acap_id=c.id WHERE 1=1"; p=[]
        if acap_id: sql+=" AND s.acap_id=?"; p.append(acap_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY c.domain,c.name,s.name",p).fetchall()]

@app.post("/api/eaa/appsys", status_code=201)
def eaa_create_appsys(body:AppSysWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="ASYS-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM acap WHERE id=?",(body.acap_id,)).fetchone(): raise HTTPException(400,"ACap not found")
        conn.execute("INSERT INTO appsys(id,acap_id,name,vendor,status,lifecycle,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (nid,body.acap_id,body.name,body.vendor,body.status,body.lifecycle,body.description,now,now))
    return {"id":nid}

@app.put("/api/eaa/appsys/{sid}")
def eaa_update_appsys(sid:str,body:AppSysWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM appsys WHERE id=?",(sid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE appsys SET acap_id=?,name=?,vendor=?,status=?,lifecycle=?,description=?,updated_at=? WHERE id=?",
                     (body.acap_id,body.name,body.vendor,body.status,body.lifecycle,body.description,now,sid))
    return {"id":sid}

@app.delete("/api/eaa/appsys/{sid}")
def eaa_delete_appsys(sid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM appsys WHERE id=?",(sid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM appsys WHERE id=?",(sid,))
    return {"deleted":sid}

@app.get("/api/eaa/coverage")
def eaa_list_coverage(app_id: Optional[str]=None, acap_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        sql="""SELECT m.*,c.name AS acap_name,c.domain,c.priority,
                      s.name AS appsys_name,s.vendor,ap.name AS app_name
               FROM ead.acap_app_map m JOIN ead.acap c ON m.acap_id=c.id
               LEFT JOIN ead.appsys s ON m.appsys_id=s.id
               LEFT JOIN main.applications ap ON m.app_id=ap.id WHERE 1=1"""; ps=[]
        if app_id: sql+=" AND m.app_id=?"; ps.append(app_id)
        if acap_id: sql+=" AND m.acap_id=?"; ps.append(acap_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY c.domain,c.name",ps).fetchall()]

@app.post("/api/eaa/coverage", status_code=201)
def eaa_upsert_coverage(body:ACapMapWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        ex=conn.execute("SELECT id FROM acap_app_map WHERE acap_id=? AND app_id=?",(body.acap_id,body.app_id)).fetchone()
        if ex:
            conn.execute("UPDATE acap_app_map SET appsys_id=?,fit_level=?,note=?,updated_at=? WHERE id=?",
                         (body.appsys_id,body.fit_level,body.note,now,ex["id"]))
            return {"id":ex["id"],"action":"updated"}
        nid="AAM-"+uuid.uuid4().hex[:6].upper()
        conn.execute("INSERT INTO acap_app_map(id,acap_id,app_id,appsys_id,fit_level,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.acap_id,body.app_id,body.appsys_id,body.fit_level,body.note,now,now))
        return {"id":nid,"action":"created"}

@app.delete("/api/eaa/coverage/{mid}")
def eaa_delete_coverage(mid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM acap_app_map WHERE id=?",(mid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM acap_app_map WHERE id=?",(mid,))
    return {"deleted":mid}

@app.get("/api/eaa/apps/{app_id}/apparch")
def eaa_app_arch(app_id:str,current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        ar=conn.execute("SELECT id,name FROM main.applications WHERE id=?",(app_id,)).fetchone()
        if not ar: raise HTTPException(404)
        rows=conn.execute("""SELECT c.id AS acap_id,c.domain,c.name AS acap_name,c.priority,
                             m.id AS map_id,m.fit_level,s.name AS appsys_name,s.vendor
                             FROM ead.acap c
                             LEFT JOIN ead.acap_app_map m ON c.id=m.acap_id AND m.app_id=?
                             LEFT JOIN ead.appsys s ON m.appsys_id=s.id
                             ORDER BY c.domain,c.name""",(app_id,)).fetchall()
        total=len(rows)
        good=sum(1 for r in rows if r["fit_level"]=="Good Fit")
        partial=sum(1 for r in rows if r["fit_level"]=="Partial Fit")
        workaround=sum(1 for r in rows if r["fit_level"]=="Workaround")
        gaps=sum(1 for r in rows if r["fit_level"] in (None,"None","Gap"))
    return {"app_id":app_id,"app_name":ar["name"],"total_acap":total,
            "good_fit":good,"partial_fit":partial,"workaround":workaround,"gaps":gaps,
            "coverage_pct":round((good+partial)/total*100,1) if total else 0,
            "items":[dict(r) for r in rows]}

@app.get("/api/eaa/gaps")
def eaa_gaps(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        no_sys=conn.execute("SELECT c.id,c.domain,c.name,c.priority FROM acap c WHERE NOT EXISTS (SELECT 1 FROM appsys s WHERE s.acap_id=c.id AND s.status='Active') ORDER BY c.priority DESC,c.domain").fetchall()
        no_coverage=conn.execute("SELECT c.id,c.domain,c.name,c.priority FROM acap c WHERE NOT EXISTS (SELECT 1 FROM acap_app_map m WHERE m.acap_id=c.id) ORDER BY c.priority DESC").fetchall()
    return {"no_system":[dict(r) for r in no_sys],"no_coverage":[dict(r) for r in no_coverage],"total_gaps":len(no_sys)+len(no_coverage)}

@app.get("/api/eaa/summary")
def eaa_summary(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        domains=conn.execute("""SELECT c.domain,COUNT(DISTINCT c.id) AS acap_count,COUNT(DISTINCT s.id) AS sys_count,
                               SUM(CASE WHEN m.fit_level='Good Fit' THEN 1 ELSE 0 END) AS good_count,
                               SUM(CASE WHEN m.fit_level='Partial Fit' THEN 1 ELSE 0 END) AS partial_count,
                               COUNT(DISTINCT m.id) AS mapped_count
                               FROM acap c LEFT JOIN appsys s ON s.acap_id=c.id
                               LEFT JOIN acap_app_map m ON m.acap_id=c.id
                               GROUP BY c.domain ORDER BY c.domain""").fetchall()
        totals=conn.execute("SELECT COUNT(*) AS total_acap,(SELECT COUNT(*) FROM appsys WHERE status='Active') AS active_sys FROM acap").fetchone()
    return {"domains":[dict(r) for r in domains],"totals":dict(totals)}

# ────────────────────────────── ETA ────────────────────────────────────────────

@app.get("/api/eta/tstd")
def eta_list_tstd(domain: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql,p="SELECT * FROM tstd WHERE 1=1",[]
        if domain: sql+=" AND domain=?"; p.append(domain)
        return [dict(r) for r in conn.execute(sql+" ORDER BY domain,name",p).fetchall()]

@app.post("/api/eta/tstd", status_code=201)
def eta_create_tstd(body:TStdWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="TSTD-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("INSERT INTO tstd(id,domain,name,radar_status,description,lifecycle,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.domain,body.name,body.radar_status,body.description,body.lifecycle,now,now))
    return {"id":nid}

@app.put("/api/eta/tstd/{tid}")
def eta_update_tstd(tid:str,body:TStdWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tstd WHERE id=?",(tid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE tstd SET domain=?,name=?,radar_status=?,description=?,lifecycle=?,updated_at=? WHERE id=?",
                     (body.domain,body.name,body.radar_status,body.description,body.lifecycle,now,tid))
    return {"id":tid}

@app.delete("/api/eta/tstd/{tid}")
def eta_delete_tstd(tid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tstd WHERE id=?",(tid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tstd_app_map WHERE tstd_id=?",(tid,))
        conn.execute("DELETE FROM tprod WHERE tstd_id=?",(tid,))
        conn.execute("DELETE FROM tstd WHERE id=?",(tid,))
    return {"deleted":tid}

@app.get("/api/eta/tprod")
def eta_list_tprod(tstd_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql="SELECT p.*,t.name AS tstd_name,t.domain FROM tprod p JOIN tstd t ON p.tstd_id=t.id WHERE 1=1"; ps=[]
        if tstd_id: sql+=" AND p.tstd_id=?"; ps.append(tstd_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY t.domain,t.name,p.name",ps).fetchall()]

@app.post("/api/eta/tprod", status_code=201)
def eta_create_tprod(body:TProdWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat(); nid="TPRD-"+uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tstd WHERE id=?",(body.tstd_id,)).fetchone(): raise HTTPException(400,"TStd not found")
        conn.execute("INSERT INTO tprod(id,tstd_id,name,vendor,version,lifecycle,status,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (nid,body.tstd_id,body.name,body.vendor,body.version,body.lifecycle,body.status,body.description,now,now))
    return {"id":nid}

@app.put("/api/eta/tprod/{pid}")
def eta_update_tprod(pid:str,body:TProdWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tprod WHERE id=?",(pid,)).fetchone(): raise HTTPException(404)
        conn.execute("UPDATE tprod SET tstd_id=?,name=?,vendor=?,version=?,lifecycle=?,status=?,description=?,updated_at=? WHERE id=?",
                     (body.tstd_id,body.name,body.vendor,body.version,body.lifecycle,body.status,body.description,now,pid))
    return {"id":pid}

@app.delete("/api/eta/tprod/{pid}")
def eta_delete_tprod(pid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tprod WHERE id=?",(pid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tprod WHERE id=?",(pid,))
    return {"deleted":pid}

@app.get("/api/eta/coverage")
def eta_list_coverage(app_id: Optional[str]=None, tstd_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        sql="""SELECT m.*,t.name AS tstd_name,t.domain,t.radar_status,
                      p.name AS tprod_name,p.vendor,ap.name AS app_name
               FROM ead.tstd_app_map m JOIN ead.tstd t ON m.tstd_id=t.id
               LEFT JOIN ead.tprod p ON m.tprod_id=p.id
               LEFT JOIN main.applications ap ON m.app_id=ap.id WHERE 1=1"""; ps=[]
        if app_id: sql+=" AND m.app_id=?"; ps.append(app_id)
        if tstd_id: sql+=" AND m.tstd_id=?"; ps.append(tstd_id)
        return [dict(r) for r in conn.execute(sql+" ORDER BY t.domain,t.name",ps).fetchall()]

@app.post("/api/eta/coverage", status_code=201)
def eta_upsert_coverage(body:TStdMapWrite,current_user:dict=Depends(_require_writer)):
    now=datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        ex=conn.execute("SELECT id FROM tstd_app_map WHERE tstd_id=? AND app_id=?",(body.tstd_id,body.app_id)).fetchone()
        if ex:
            conn.execute("UPDATE tstd_app_map SET tprod_id=?,compliance=?,note=?,updated_at=? WHERE id=?",
                         (body.tprod_id,body.compliance,body.note,now,ex["id"]))
            return {"id":ex["id"],"action":"updated"}
        nid="TAM-"+uuid.uuid4().hex[:6].upper()
        conn.execute("INSERT INTO tstd_app_map(id,tstd_id,app_id,tprod_id,compliance,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (nid,body.tstd_id,body.app_id,body.tprod_id,body.compliance,body.note,now,now))
        return {"id":nid,"action":"created"}

@app.delete("/api/eta/coverage/{mid}")
def eta_delete_coverage(mid:str,current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tstd_app_map WHERE id=?",(mid,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tstd_app_map WHERE id=?",(mid,))
    return {"deleted":mid}

@app.get("/api/eta/apps/{app_id}/tech")
def eta_app_tech(app_id:str,current_user:dict=Depends(_require_auth)):
    with get_connected_db() as conn:
        ar=conn.execute("SELECT id,name FROM main.applications WHERE id=?",(app_id,)).fetchone()
        if not ar: raise HTTPException(404)
        rows=conn.execute("""SELECT t.id AS tstd_id,t.domain,t.name AS tstd_name,t.radar_status,
                             m.id AS map_id,m.compliance,p.name AS tprod_name,p.vendor
                             FROM ead.tstd t
                             LEFT JOIN ead.tstd_app_map m ON t.id=m.tstd_id AND m.app_id=?
                             LEFT JOIN ead.tprod p ON m.tprod_id=p.id
                             ORDER BY t.domain,t.name""",(app_id,)).fetchall()
        total=len(rows)
        compliant=sum(1 for r in rows if r["compliance"]=="Compliant")
        partial=sum(1 for r in rows if r["compliance"]=="Partial")
        non_compliant=sum(1 for r in rows if r["compliance"]=="Non-Compliant")
        exempt=sum(1 for r in rows if r["compliance"]=="Exempt")
        gaps=sum(1 for r in rows if r["compliance"] in (None,"None"))
    return {"app_id":app_id,"app_name":ar["name"],"total_tstd":total,
            "compliant":compliant,"partial":partial,"non_compliant":non_compliant,
            "exempt":exempt,"gaps":gaps,
            "coverage_pct":round((compliant+partial)/total*100,1) if total else 0,
            "items":[dict(r) for r in rows]}

@app.get("/api/eta/gaps")
def eta_gaps(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        no_prod=conn.execute("SELECT t.id,t.domain,t.name,t.radar_status FROM tstd t WHERE NOT EXISTS (SELECT 1 FROM tprod p WHERE p.tstd_id=t.id AND p.status='Active') ORDER BY t.domain").fetchall()
        no_coverage=conn.execute("SELECT t.id,t.domain,t.name,t.radar_status FROM tstd t WHERE NOT EXISTS (SELECT 1 FROM tstd_app_map m WHERE m.tstd_id=t.id) ORDER BY t.domain").fetchall()
    return {"no_product":[dict(r) for r in no_prod],"no_coverage":[dict(r) for r in no_coverage],"total_gaps":len(no_prod)+len(no_coverage)}

@app.get("/api/eta/summary")
def eta_summary(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        domains=conn.execute("""SELECT t.domain,COUNT(DISTINCT t.id) AS tstd_count,COUNT(DISTINCT p.id) AS prod_count,
                               SUM(CASE WHEN m.compliance='Compliant' THEN 1 ELSE 0 END) AS compliant_count,
                               SUM(CASE WHEN m.compliance='Partial' THEN 1 ELSE 0 END) AS partial_count,
                               COUNT(DISTINCT m.id) AS mapped_count
                               FROM tstd t LEFT JOIN tprod p ON p.tstd_id=t.id
                               LEFT JOIN tstd_app_map m ON m.tstd_id=t.id
                               GROUP BY t.domain ORDER BY t.domain""").fetchall()
        totals=conn.execute("SELECT COUNT(*) AS total_tstd,(SELECT COUNT(*) FROM tprod WHERE status='Active') AS active_prod FROM tstd").fetchone()
    return {"domains":[dict(r) for r in domains],"totals":dict(totals)}

# ────────────────────── TECH CATALOG (B32.43) ───────────────────────────────────

@app.get("/api/tech/catalog")
def tech_list_catalog(category: Optional[str]=None, tier: Optional[str]=None,
                      standard_status: Optional[str]=None, q: Optional[str]=None,
                      current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql = """SELECT c.*,
                 (SELECT COUNT(*) FROM tech_versions v WHERE v.tech_id=c.id) AS version_count,
                 (SELECT COUNT(*) FROM tech_usage u WHERE u.tech_id=c.id) AS usage_count,
                 (SELECT COUNT(*) FROM tech_vulnerabilities t WHERE t.tech_id=c.id AND t.status='Open') AS open_cve_count,
                 (SELECT version_label FROM tech_versions v2 WHERE v2.tech_id=c.id AND v2.is_latest=1 LIMIT 1) AS latest_version
                 FROM tech_catalog c WHERE 1=1"""
        p = []
        if category: sql += " AND c.category=?"; p.append(category)
        if tier: sql += " AND c.tier=?"; p.append(tier)
        if standard_status: sql += " AND c.standard_status=?"; p.append(standard_status)
        if q: sql += " AND (c.name LIKE ? OR c.vendor LIKE ?)"; p += [f"%{q}%", f"%{q}%"]
        return [dict(r) for r in conn.execute(sql + " ORDER BY c.category,c.name", p).fetchall()]

@app.post("/api/tech/catalog", status_code=201)
def tech_create_catalog(body:TechCatalogWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    nid = "TC-" + uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("""INSERT INTO tech_catalog(id,name,vendor,category,sub_category,tier,standard_status,
                        website_url,tags,description,created_by,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (nid, body.name, body.vendor, body.category, body.sub_category, body.tier,
                      body.standard_status, body.website_url, body.tags, body.description,
                      current_user.get('sub', current_user.get('username', '')), now, now))
    return {"id": nid}

@app.get("/api/tech/catalog/{tech_id}")
def tech_get_catalog(tech_id:str, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        row = conn.execute("SELECT * FROM tech_catalog WHERE id=?", (tech_id,)).fetchone()
        if not row: raise HTTPException(404)
        r = dict(row)
        r["versions"] = [dict(v) for v in conn.execute("SELECT * FROM tech_versions WHERE tech_id=? ORDER BY is_latest DESC,release_date DESC", (tech_id,)).fetchall()]
        r["usage"] = [dict(u) for u in conn.execute("SELECT * FROM tech_usage WHERE tech_id=? ORDER BY environment,app_id", (tech_id,)).fetchall()]
        r["vulnerabilities"] = [dict(v) for v in conn.execute("SELECT * FROM tech_vulnerabilities WHERE tech_id=? ORDER BY cvss_score DESC", (tech_id,)).fetchall()]
        r["radar"] = [dict(v) for v in conn.execute("SELECT * FROM tech_radar WHERE tech_id=? ORDER BY radar_date DESC", (tech_id,)).fetchall()]
    return r

@app.put("/api/tech/catalog/{tech_id}")
def tech_update_catalog(tech_id:str, body:TechCatalogWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (tech_id,)).fetchone(): raise HTTPException(404)
        conn.execute("""UPDATE tech_catalog SET name=?,vendor=?,category=?,sub_category=?,tier=?,standard_status=?,
                        website_url=?,tags=?,description=?,updated_at=? WHERE id=?""",
                     (body.name, body.vendor, body.category, body.sub_category, body.tier,
                      body.standard_status, body.website_url, body.tags, body.description, now, tech_id))
    return {"id": tech_id}

@app.delete("/api/tech/catalog/{tech_id}")
def tech_delete_catalog(tech_id:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (tech_id,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tech_radar WHERE tech_id=?", (tech_id,))
        conn.execute("DELETE FROM tech_vulnerabilities WHERE tech_id=?", (tech_id,))
        conn.execute("DELETE FROM tech_usage WHERE tech_id=?", (tech_id,))
        conn.execute("DELETE FROM tech_versions WHERE tech_id=?", (tech_id,))
        conn.execute("DELETE FROM tech_catalog WHERE id=?", (tech_id,))
    return {"deleted": tech_id}

# ── Tech Versions ──────────────────────────────────────────────────────────────

@app.get("/api/tech/catalog/{tech_id}/versions")
def tech_list_versions(tech_id:str, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (tech_id,)).fetchone(): raise HTTPException(404)
        return [dict(r) for r in conn.execute("SELECT * FROM tech_versions WHERE tech_id=? ORDER BY is_latest DESC,release_date DESC", (tech_id,)).fetchall()]

@app.post("/api/tech/catalog/{tech_id}/versions", status_code=201)
def tech_add_version(tech_id:str, body:TechVersionWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    nid = "TV-" + uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (tech_id,)).fetchone(): raise HTTPException(404)
        if body.is_latest:
            conn.execute("UPDATE tech_versions SET is_latest=0 WHERE tech_id=?", (tech_id,))
        conn.execute("""INSERT INTO tech_versions(id,tech_id,version_label,major,minor,patch,build,
                        release_type,release_date,eol_date,ext_support_end,lifecycle_phase,
                        release_notes_url,is_latest,is_lts,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (nid, tech_id, body.version_label, body.major, body.minor, body.patch,
                      body.build, body.release_type, body.release_date, body.eol_date,
                      body.ext_support_end, body.lifecycle_phase, body.release_notes_url,
                      body.is_latest, body.is_lts, now))
    return {"id": nid}

@app.put("/api/tech/versions/{ver_id}")
def tech_update_version(ver_id:str, body:TechVersionWrite, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        row = conn.execute("SELECT tech_id FROM tech_versions WHERE id=?", (ver_id,)).fetchone()
        if not row: raise HTTPException(404)
        tech_id = row["tech_id"]
        if body.is_latest:
            conn.execute("UPDATE tech_versions SET is_latest=0 WHERE tech_id=?", (tech_id,))
        conn.execute("""UPDATE tech_versions SET version_label=?,major=?,minor=?,patch=?,build=?,
                        release_type=?,release_date=?,eol_date=?,ext_support_end=?,lifecycle_phase=?,
                        release_notes_url=?,is_latest=?,is_lts=? WHERE id=?""",
                     (body.version_label, body.major, body.minor, body.patch, body.build,
                      body.release_type, body.release_date, body.eol_date, body.ext_support_end,
                      body.lifecycle_phase, body.release_notes_url, body.is_latest, body.is_lts, ver_id))
    return {"id": ver_id}

@app.delete("/api/tech/versions/{ver_id}")
def tech_delete_version(ver_id:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_versions WHERE id=?", (ver_id,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tech_versions WHERE id=?", (ver_id,))
    return {"deleted": ver_id}

# ── Tech Servers ──────────────────────────────────────────────────────────────

@app.get("/api/tech/servers")
def tech_list_servers(environment: Optional[str]=None, status: Optional[str]=None,
                      q: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql = "SELECT * FROM tech_servers WHERE 1=1"; p = []
        if environment: sql += " AND environment=?"; p.append(environment)
        if status: sql += " AND status=?"; p.append(status)
        if q: sql += " AND (hostname LIKE ? OR ip_address LIKE ?)"; p += [f"%{q}%", f"%{q}%"]
        rows = [dict(r) for r in conn.execute(sql + " ORDER BY environment,hostname", p).fetchall()]
        # attach installed tech count
        for row in rows:
            row["tech_count"] = conn.execute("SELECT COUNT(*) FROM tech_usage WHERE server_id=?", (row["id"],)).fetchone()[0]
        return rows

@app.post("/api/tech/servers", status_code=201)
def tech_create_server(body:TechServerWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    nid = "SRV-" + uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        conn.execute("""INSERT INTO tech_servers(id,hostname,ip_address,environment,server_type,location,
                        os_name,os_version,cpu_core,ram_gb,managed_by,status,note,created_by,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (nid, body.hostname, body.ip_address, body.environment, body.server_type,
                      body.location, body.os_name, body.os_version, body.cpu_core, body.ram_gb,
                      body.managed_by, body.status, body.note,
                      current_user.get('sub', current_user.get('username', '')), now, now))
    return {"id": nid}

@app.put("/api/tech/servers/{srv_id}")
def tech_update_server(srv_id:str, body:TechServerWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_servers WHERE id=?", (srv_id,)).fetchone(): raise HTTPException(404)
        conn.execute("""UPDATE tech_servers SET hostname=?,ip_address=?,environment=?,server_type=?,location=?,
                        os_name=?,os_version=?,cpu_core=?,ram_gb=?,managed_by=?,status=?,note=?,updated_at=? WHERE id=?""",
                     (body.hostname, body.ip_address, body.environment, body.server_type, body.location,
                      body.os_name, body.os_version, body.cpu_core, body.ram_gb, body.managed_by,
                      body.status, body.note, now, srv_id))
    return {"id": srv_id}

# ── Tech Usage ────────────────────────────────────────────────────────────────

@app.get("/api/tech/usage")
def tech_list_usage(tech_id: Optional[str]=None, app_id: Optional[str]=None,
                    server_id: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql = """SELECT u.*, c.name AS tech_name, c.category AS tech_category,
                 v.version_label AS version_label_ref
                 FROM tech_usage u JOIN tech_catalog c ON u.tech_id=c.id
                 LEFT JOIN tech_versions v ON u.version_id=v.id WHERE 1=1"""
        p = []
        if tech_id: sql += " AND u.tech_id=?"; p.append(tech_id)
        if app_id: sql += " AND u.app_id=?"; p.append(app_id)
        if server_id: sql += " AND u.server_id=?"; p.append(server_id)
        return [dict(r) for r in conn.execute(sql + " ORDER BY u.environment,u.app_id", p).fetchall()]

@app.post("/api/tech/usage", status_code=201)
def tech_add_usage(body:TechUsageWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    nid = "TU-" + uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (body.tech_id,)).fetchone(): raise HTTPException(400, "Tech not found")
        conn.execute("""INSERT INTO tech_usage(id,tech_id,version_id,usage_target_type,app_id,server_id,
                        environment,usage_type,installed_version,install_date,upgrade_plan,note,created_by,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (nid, body.tech_id, body.version_id, body.usage_target_type, body.app_id,
                      body.server_id, body.environment, body.usage_type, body.installed_version,
                      body.install_date, body.upgrade_plan, body.note,
                      current_user.get('sub', current_user.get('username', '')), now, now))
    return {"id": nid}

@app.put("/api/tech/usage/{usage_id}")
def tech_update_usage(usage_id:str, body:TechUsageWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_usage WHERE id=?", (usage_id,)).fetchone(): raise HTTPException(404)
        conn.execute("""UPDATE tech_usage SET tech_id=?,version_id=?,usage_target_type=?,app_id=?,server_id=?,
                        environment=?,usage_type=?,installed_version=?,install_date=?,upgrade_plan=?,note=?,updated_at=?
                        WHERE id=?""",
                     (body.tech_id, body.version_id, body.usage_target_type, body.app_id, body.server_id,
                      body.environment, body.usage_type, body.installed_version, body.install_date,
                      body.upgrade_plan, body.note, now, usage_id))
    return {"id": usage_id}

@app.delete("/api/tech/usage/{usage_id}")
def tech_delete_usage(usage_id:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_usage WHERE id=?", (usage_id,)).fetchone(): raise HTTPException(404)
        conn.execute("DELETE FROM tech_usage WHERE id=?", (usage_id,))
    return {"deleted": usage_id}

# ── CVE / Vulnerabilities ─────────────────────────────────────────────────────

@app.get("/api/tech/vulnerabilities")
def tech_list_vulns(tech_id: Optional[str]=None, severity: Optional[str]=None,
                    status: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql = """SELECT t.*, c.name AS tech_name FROM tech_vulnerabilities t
                 JOIN tech_catalog c ON t.tech_id=c.id WHERE 1=1"""
        p = []
        if tech_id: sql += " AND t.tech_id=?"; p.append(tech_id)
        if severity: sql += " AND t.severity=?"; p.append(severity)
        if status: sql += " AND t.status=?"; p.append(status)
        return [dict(r) for r in conn.execute(sql + " ORDER BY CASE t.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, t.cvss_score DESC", p).fetchall()]

@app.post("/api/tech/catalog/{tech_id}/fetch-cve", status_code=202)
def tech_fetch_cve(tech_id:str, current_user:dict=Depends(_require_writer)):
    with get_ea_domains_db() as conn:
        row = conn.execute("SELECT id, name FROM tech_catalog WHERE id=?", (tech_id,)).fetchone()
        if not row: raise HTTPException(404)
        tech_name = row["name"]
    # Run in background thread so endpoint returns immediately
    threading.Thread(target=_fetch_nvd_cves_for_tech, args=(tech_id, tech_name), daemon=True).start()
    return {"status": "accepted", "tech_id": tech_id, "tech_name": tech_name, "message": "CVE fetch started in background"}

@app.put("/api/tech/vulnerabilities/{vuln_id}")
def tech_update_vuln(vuln_id:str, body:TechVulnUpdateWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_vulnerabilities WHERE id=?", (vuln_id,)).fetchone(): raise HTTPException(404)
        updates = []; vals = []
        if body.status is not None: updates.append("status=?"); vals.append(body.status)
        if body.remediation is not None: updates.append("remediation=?"); vals.append(body.remediation)
        if body.remediation_date is not None: updates.append("remediation_date=?"); vals.append(body.remediation_date)
        if body.assigned_to is not None: updates.append("assigned_to=?"); vals.append(body.assigned_to)
        if body.severity is not None: updates.append("severity=?"); vals.append(body.severity)
        if updates:
            updates.append("updated_at=?"); vals.append(now); vals.append(vuln_id)
            conn.execute(f"UPDATE tech_vulnerabilities SET {','.join(updates)} WHERE id=?", vals)
    return {"id": vuln_id}

# ── Tech Radar ────────────────────────────────────────────────────────────────

@app.get("/api/tech/radar")
def tech_list_radar(quarter: Optional[str]=None, ring: Optional[str]=None,
                    quadrant: Optional[str]=None, current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        sql = """SELECT r.*, c.name AS tech_name, c.category, c.tier, c.standard_status,
                 (SELECT COUNT(*) FROM tech_usage u WHERE u.tech_id=c.id) AS usage_count,
                 (SELECT version_label FROM tech_versions v WHERE v.tech_id=c.id AND v.is_latest=1 LIMIT 1) AS latest_version
                 FROM tech_radar r JOIN tech_catalog c ON r.tech_id=c.id WHERE 1=1"""
        p = []
        if quarter: sql += " AND r.radar_date=?"; p.append(quarter)
        if ring: sql += " AND r.ring=?"; p.append(ring)
        if quadrant: sql += " AND r.quadrant=?"; p.append(quadrant)
        # If no quarter filter, return only the latest entry per tech
        if not quarter:
            sql = f"""SELECT r.*, c.name AS tech_name, c.category, c.tier, c.standard_status,
                      (SELECT COUNT(*) FROM tech_usage u WHERE u.tech_id=c.id) AS usage_count,
                      (SELECT version_label FROM tech_versions v WHERE v.tech_id=c.id AND v.is_latest=1 LIMIT 1) AS latest_version
                      FROM tech_radar r JOIN tech_catalog c ON r.tech_id=c.id
                      WHERE r.id=(SELECT id FROM tech_radar WHERE tech_id=r.tech_id ORDER BY radar_date DESC LIMIT 1)"""
            if ring: sql += " AND r.ring=?"; p.append(ring)
            if quadrant: sql += " AND r.quadrant=?"; p.append(quadrant)
        return [dict(r) for r in conn.execute(sql + " ORDER BY r.radar_date DESC, r.ring, c.name", p).fetchall()]

@app.post("/api/tech/radar", status_code=201)
def tech_add_radar(body:TechRadarWrite, current_user:dict=Depends(_require_writer)):
    now = datetime.utcnow().isoformat()
    nid = "TR-" + uuid.uuid4().hex[:6].upper()
    with get_ea_domains_db() as conn:
        if not conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (body.tech_id,)).fetchone(): raise HTTPException(400, "Tech not found")
        decided_by = body.decided_by or current_user.get('sub', current_user.get('username', ''))
        conn.execute("""INSERT INTO tech_radar(id,tech_id,radar_date,ring,quadrant,rationale,decided_by,prev_ring,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                     (nid, body.tech_id, body.radar_date, body.ring, body.quadrant, body.rationale, decided_by, body.prev_ring, now))
    return {"id": nid}

# ── Tech Dashboard ────────────────────────────────────────────────────────────

@app.get("/api/tech/dashboard")
def tech_dashboard(current_user:dict=Depends(_require_auth)):
    with get_ea_domains_db() as conn:
        total_tech = conn.execute("SELECT COUNT(*) FROM tech_catalog").fetchone()[0]
        total_servers = conn.execute("SELECT COUNT(*) FROM tech_servers WHERE status='Active'").fetchone()[0]
        eol_count = conn.execute("SELECT COUNT(*) FROM tech_versions WHERE lifecycle_phase='EOL' AND is_latest=1").fetchone()[0]
        cve_critical = conn.execute("SELECT COUNT(*) FROM tech_vulnerabilities WHERE severity='Critical' AND status='Open'").fetchone()[0]
        cve_high = conn.execute("SELECT COUNT(*) FROM tech_vulnerabilities WHERE severity='High' AND status='Open'").fetchone()[0]
        cve_medium = conn.execute("SELECT COUNT(*) FROM tech_vulnerabilities WHERE severity='Medium' AND status='Open'").fetchone()[0]
        cve_low = conn.execute("SELECT COUNT(*) FROM tech_vulnerabilities WHERE severity='Low' AND status='Open'").fetchone()[0]
        cve_total = conn.execute("SELECT COUNT(*) FROM tech_vulnerabilities WHERE status='Open'").fetchone()[0]
        # by category
        by_category = [dict(r) for r in conn.execute("SELECT category, COUNT(*) AS cnt FROM tech_catalog GROUP BY category ORDER BY cnt DESC").fetchall()]
        # by tier
        by_tier = [dict(r) for r in conn.execute("SELECT tier, COUNT(*) AS cnt FROM tech_catalog GROUP BY tier ORDER BY tier").fetchall()]
        # by status
        by_status = [dict(r) for r in conn.execute("SELECT standard_status, COUNT(*) AS cnt FROM tech_catalog GROUP BY standard_status").fetchall()]
        # CVE by tech (top 10)
        top_cve_tech = [dict(r) for r in conn.execute("""SELECT c.name, COUNT(t.id) AS open_cve
                         FROM tech_vulnerabilities t JOIN tech_catalog c ON t.tech_id=c.id
                         WHERE t.status='Open' GROUP BY t.tech_id ORDER BY open_cve DESC LIMIT 10""").fetchall()]
        # radar summary
        radar_rings = [dict(r) for r in conn.execute("""SELECT r.ring, COUNT(*) AS cnt FROM tech_radar r
                        WHERE r.id=(SELECT id FROM tech_radar WHERE tech_id=r.tech_id ORDER BY radar_date DESC LIMIT 1)
                        GROUP BY r.ring""").fetchall()]
        # latest quarters
        quarters = [r[0] for r in conn.execute("SELECT DISTINCT radar_date FROM tech_radar ORDER BY radar_date DESC LIMIT 8").fetchall()]
    return {"total_tech": total_tech, "total_servers": total_servers, "eol_count": eol_count,
            "cve": {"critical": cve_critical, "high": cve_high, "medium": cve_medium, "low": cve_low, "total": cve_total},
            "by_category": by_category, "by_tier": by_tier, "by_status": by_status,
            "top_cve_tech": top_cve_tech, "radar_rings": radar_rings, "available_quarters": quarters}

# ─── 360° Cross-Domain EA View per App ─────────────────────────────────────────

@app.get("/api/ea/apps/{app_id}/360")
def ea_app_360(app_id:str, current_user:dict=Depends(_require_auth)):
    """360° EA Domain coverage for one application — all 5 domains."""
    with get_connected_db() as conn:
        ar=conn.execute("SELECT id,name FROM main.applications WHERE id=?",(app_id,)).fetchone()
        if not ar: raise HTTPException(404, f"App {app_id} not found")

        # ESA
        esa_rows=conn.execute("""SELECT c.coverage_level FROM esa.abb_app_coverage c WHERE c.app_id=?""",(app_id,)).fetchall()
        esa_total=conn.execute("SELECT COUNT(*) FROM esa.abb").fetchone()[0]
        esa_covered=sum(1 for r in esa_rows if r[0] in ("Covered","Full","Partial"))
        esa_pct=round(esa_covered/esa_total*100,1) if esa_total else 0

        # EBA
        eba_rows=conn.execute("SELECT m.support_level FROM ead.bcap_app_map m WHERE m.app_id=?",(app_id,)).fetchall()
        eba_total=conn.execute("SELECT COUNT(*) FROM ead.bcap").fetchone()[0]
        eba_covered=sum(1 for r in eba_rows if r[0] in ("Primary","Supporting"))
        eba_pct=round(eba_covered/eba_total*100,1) if eba_total else 0

        # EDA
        eda_rows=conn.execute("SELECT m.role FROM ead.ddomain_app_map m WHERE m.app_id=?",(app_id,)).fetchall()
        eda_total=conn.execute("SELECT COUNT(*) FROM ead.ddomain").fetchone()[0]
        eda_covered=sum(1 for r in eda_rows if r[0] in ("Owner","Producer","Consumer"))
        eda_pct=round(eda_covered/eda_total*100,1) if eda_total else 0

        # EAA
        eaa_rows=conn.execute("SELECT m.fit_level FROM ead.acap_app_map m WHERE m.app_id=?",(app_id,)).fetchall()
        eaa_total=conn.execute("SELECT COUNT(*) FROM ead.acap").fetchone()[0]
        eaa_covered=sum(1 for r in eaa_rows if r[0] in ("Good Fit","Partial Fit"))
        eaa_pct=round(eaa_covered/eaa_total*100,1) if eaa_total else 0

        # ETA
        eta_rows=conn.execute("SELECT m.compliance FROM ead.tstd_app_map m WHERE m.app_id=?",(app_id,)).fetchall()
        eta_total=conn.execute("SELECT COUNT(*) FROM ead.tstd").fetchone()[0]
        eta_covered=sum(1 for r in eta_rows if r[0] in ("Compliant","Partial"))
        eta_pct=round(eta_covered/eta_total*100,1) if eta_total else 0

        overall=round((esa_pct+eba_pct+eda_pct+eaa_pct+eta_pct)/5,1)

    return {
        "app_id":app_id, "app_name":ar["name"],
        "overall_pct": overall,
        "domains":[
            {"key":"esa","label":"Security Architecture","icon":"🛡","pct":esa_pct,"covered":esa_covered,"total":esa_total},
            {"key":"eba","label":"Business Architecture","icon":"📋","pct":eba_pct,"covered":eba_covered,"total":eba_total},
            {"key":"eda","label":"Data Architecture","icon":"🗄️","pct":eda_pct,"covered":eda_covered,"total":eda_total},
            {"key":"eaa","label":"Application Architecture","icon":"📱","pct":eaa_pct,"covered":eaa_covered,"total":eaa_total},
            {"key":"eta","label":"Technology Architecture","icon":"⚙️","pct":eta_pct,"covered":eta_covered,"total":eta_total},
        ]
    }

# ═══════════════════════════════════════════════════════════════════════════════
# ARB LITE — Architecture Review Board
# ═══════════════════════════════════════════════════════════════════════════════

def _arb_auto_review_level(impact: dict) -> str:
    """Auto-classify review level from impact profile."""
    formal_triggers = [
        impact.get('has_pii'),
        impact.get('internet_facing'),
        impact.get('new_vendor'),
        impact.get('expected_exception'),
        impact.get('security_impact') in ('High', 'Critical'),
        impact.get('new_integration') and impact.get('integration_impact') in ('High', 'Critical'),
    ]
    if any(formal_triggers):
        return 'Formal Review'
    medium_triggers = [
        impact.get('new_integration'),
        impact.get('new_technology'),
        impact.get('business_impact') not in ('None', '', None),
        impact.get('data_impact') not in ('None', '', None),
        impact.get('application_impact') not in ('None', '', None),
        impact.get('technology_impact') not in ('None', '', None),
        impact.get('compliance_impact') not in ('None', '', None),
    ]
    medium_count = sum(1 for t in medium_triggers if t)
    if medium_count == 0:
        return 'Auto-pass'
    if medium_count <= 2:
        return 'Desk Review'
    return 'Formal Review'

def _arb_generate_recommendations(conn, arb_id: str, impact: dict):
    """Generate artifact + ABB/SBB recommendations based on impact rules."""
    conn.execute("DELETE FROM arb_recommendations WHERE arb_request_id=?", (arb_id,))
    recs = []
    now = datetime.now().strftime("%Y-%m-%d")
    # Artifact recommendations
    if impact.get('new_integration'):
        recs.append((arb_id,'artifact','','Interface List','New integration requires interface documentation',1,'Pending'))
    if impact.get('security_impact') not in ('None','',None) or impact.get('has_pii'):
        recs.append((arb_id,'artifact','','Security Design Summary','Security/PII impact requires security consideration document',1,'Pending'))
    if impact.get('data_impact') not in ('None','',None) or impact.get('has_pii'):
        recs.append((arb_id,'artifact','','Data Flow Diagram','Data impact requires data flow documentation',1,'Pending'))
    if impact.get('new_technology'):
        recs.append((arb_id,'artifact','','Technical Design Summary','New technology requires technical design documentation',1,'Pending'))
    if impact.get('internet_facing'):
        recs.append((arb_id,'artifact','','Context Diagram','Internet-facing system requires context diagram',1,'Pending'))
    # ESA ABB recommendations
    try:
        conn.execute(f"ATTACH DATABASE '{ESA_DB_PATH}' AS esa_rec")
        if impact.get('internet_facing'):
            rows = conn.execute("SELECT id, name FROM esa_rec.abb WHERE domain IN ('Network Security','Application Security') LIMIT 4").fetchall()
            for r in rows:
                recs.append((arb_id,'abb',r[0],r[1],'Internet-facing system requires network/application security controls',0,'Pending'))
        if impact.get('has_pii'):
            rows = conn.execute("SELECT id, name FROM esa_rec.abb WHERE domain IN ('Data Security','Identity & Access Management') LIMIT 4").fetchall()
            for r in rows:
                recs.append((arb_id,'abb',r[0],r[1],'PII data requires data protection and access control',0,'Pending'))
        if impact.get('new_integration'):
            rows = conn.execute("SELECT id, name FROM esa_rec.abb WHERE domain IN ('Application Security') LIMIT 3").fetchall()
            for r in rows:
                recs.append((arb_id,'abb',r[0],r[1],'New integration requires secure interface controls',0,'Pending'))
        if impact.get('security_impact') in ('High','Critical'):
            rows = conn.execute("SELECT id, name FROM esa_rec.abb WHERE domain IN ('Identity & Access Management','Monitoring & Logging','Vulnerability Management') LIMIT 5").fetchall()
            for r in rows:
                recs.append((arb_id,'abb',r[0],r[1],'High security impact requires comprehensive security building blocks',0,'Pending'))
        conn.execute("DETACH DATABASE esa_rec")
    except Exception:
        try: conn.execute("DETACH DATABASE esa_rec")
        except: pass
    conn.executemany(
        "INSERT INTO arb_recommendations(arb_request_id,rec_type,ref_code,ref_name,reason_text,is_mandatory,status) VALUES(?,?,?,?,?,?,?)",
        recs
    )

def _arb_next_code(conn) -> str:
    year = datetime.now().year
    row = conn.execute("SELECT MAX(CAST(SUBSTR(request_code,-4) AS INTEGER)) FROM arb_requests WHERE request_code LIKE ?", (f"ARB-{year}-%",)).fetchone()
    seq = (row[0] or 0) + 1
    return f"ARB-{year}-{seq:04d}"

def _arb_log(user: str, action: str, target_id: str, detail: str = ""):
    try:
        with get_audit_db() as conn:
            conn.execute(
                "INSERT INTO audit_log(timestamp,user,action,target_type,target_id,detail,ip) VALUES(?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), user, action, 'arb_request', target_id, detail, '')
            )
    except Exception:
        pass

# ── ARB Requests ────────────────────────────────────────────────────────────────
@app.get("/api/arb/requests")
def arb_list_requests(
    status: Optional[str] = None,
    request_type: Optional[str] = None,
    review_level: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50, offset: int = 0,
    current_user: dict = Depends(_require_auth)
):
    with get_db() as conn:
        where, params = ["1=1"], []
        if status:       where.append("r.status=?");        params.append(status)
        if request_type: where.append("r.request_type=?");  params.append(request_type)
        if review_level: where.append("r.review_level=?");  params.append(review_level)
        if q:
            where.append("(r.title LIKE ? OR r.request_code LIKE ? OR r.business_owner LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        sql = f"""
            SELECT r.*,
                GROUP_CONCAT(DISTINCT ra.application_id) as app_ids,
                (SELECT decision_type FROM arb_decisions d WHERE d.arb_request_id=r.id) as decision_type
            FROM arb_requests r
            LEFT JOIN arb_request_applications ra ON ra.arb_request_id=r.id
            WHERE {' AND '.join(where)}
            GROUP BY r.id ORDER BY r.created_at DESC LIMIT ? OFFSET ?
        """
        rows = [dict(r) for r in conn.execute(sql, params + [limit, offset]).fetchall()]
        total = conn.execute(f"SELECT COUNT(*) FROM arb_requests r WHERE {' AND '.join(where)}", params).fetchone()[0]
        return {"items": rows, "total": total}

@app.post("/api/arb/requests", status_code=201)
def arb_create_request(body: ArbRequestWrite, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        arb_id = f"arb-{int(datetime.now().timestamp()*1000)}"
        code = _arb_next_code(conn)
        conn.execute("""
            INSERT INTO arb_requests(id,request_code,title,request_type,review_level,status,
                business_objective,change_summary,business_owner,requester_user,target_date,
                project_id,roadmap_id,created_by,created_at,updated_at,submitted_at,closed_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (arb_id, code, body.title or 'Untitled',
              body.request_type or 'New Project',
              body.review_level or 'Desk Review',
              'Draft',
              body.business_objective or '', body.change_summary or '',
              body.business_owner or '', body.requester_user or current_user.get('sub', current_user.get('username', '')),
              body.target_date or '', body.project_id or '', body.roadmap_id or '',
              current_user.get('sub', current_user.get('username', '')), now, now, '', ''))
        # Impact profile
        imp = body.impact or {}
        conn.execute("""
            INSERT OR REPLACE INTO arb_impact_profile(arb_request_id,business_impact,data_impact,
                application_impact,technology_impact,security_impact,integration_impact,compliance_impact,
                has_pii,internet_facing,new_integration,new_vendor,new_technology,expected_exception,
                context_diagram,data_flow,interface_list,security_consideration,solution_summary)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (arb_id,
              imp.get('business_impact','None'), imp.get('data_impact','None'),
              imp.get('application_impact','None'), imp.get('technology_impact','None'),
              imp.get('security_impact','None'), imp.get('integration_impact','None'),
              imp.get('compliance_impact','None'),
              1 if imp.get('has_pii') else 0,
              1 if imp.get('internet_facing') else 0,
              1 if imp.get('new_integration') else 0,
              1 if imp.get('new_vendor') else 0,
              1 if imp.get('new_technology') else 0,
              1 if imp.get('expected_exception') else 0,
              1 if imp.get('context_diagram') else 0,
              1 if imp.get('data_flow') else 0,
              1 if imp.get('interface_list') else 0,
              1 if imp.get('security_consideration') else 0,
              1 if imp.get('solution_summary') else 0))
        # Application links
        if body.application_ids:
            for app_id in body.application_ids:
                conn.execute("INSERT INTO arb_request_applications(arb_request_id,application_id) VALUES(?,?)", (arb_id, app_id))
        # Auto review level
        auto_level = _arb_auto_review_level(imp)
        conn.execute("UPDATE arb_requests SET review_level=? WHERE id=?", (auto_level, arb_id))
        # Generate recommendations
        _arb_generate_recommendations(conn, arb_id, imp)
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'create_arb_request', arb_id, f"Created: {code} - {body.title}")
    return {"id": arb_id, "request_code": code, "review_level": auto_level}

@app.get("/api/arb/requests/{arb_id}")
def arb_get_request(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        r = conn.execute("SELECT * FROM arb_requests WHERE id=?", (arb_id,)).fetchone()
        if not r: raise HTTPException(404, "ARB request not found")
        data = dict(r)
        data['impact'] = dict(conn.execute("SELECT * FROM arb_impact_profile WHERE arb_request_id=?", (arb_id,)).fetchone() or {})
        data['applications'] = [dict(x) for x in conn.execute("SELECT application_id FROM arb_request_applications WHERE arb_request_id=?", (arb_id,)).fetchall()]
        data['reviewers'] = [dict(x) for x in conn.execute("SELECT * FROM arb_reviewers WHERE arb_request_id=?", (arb_id,)).fetchall()]
        data['comments'] = [dict(x) for x in conn.execute("SELECT * FROM arb_comments WHERE arb_request_id=? ORDER BY created_at DESC", (arb_id,)).fetchall()]
        data['findings'] = [dict(x) for x in conn.execute("SELECT * FROM arb_findings WHERE arb_request_id=? ORDER BY severity DESC, created_at DESC", (arb_id,)).fetchall()]
        data['decision'] = dict(conn.execute("SELECT * FROM arb_decisions WHERE arb_request_id=?", (arb_id,)).fetchone() or {})
        data['actions'] = [dict(x) for x in conn.execute("SELECT * FROM arb_actions WHERE arb_request_id=? ORDER BY created_at", (arb_id,)).fetchall()]
        data['recommendations'] = [dict(x) for x in conn.execute("SELECT * FROM arb_recommendations WHERE arb_request_id=? ORDER BY is_mandatory DESC, rec_type", (arb_id,)).fetchall()]
        return data

@app.put("/api/arb/requests/{arb_id}")
def arb_update_request(arb_id: str, body: ArbRequestWrite, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        r = conn.execute("SELECT * FROM arb_requests WHERE id=?", (arb_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
        if dict(r)['status'] in ('Closed','Cancelled') and 'admin' not in current_user.get('roles',[]):
            raise HTTPException(403, "Cannot edit closed/cancelled request")
        fields = []
        params = []
        if body.title is not None:              fields.append("title=?");              params.append(body.title)
        if body.request_type is not None:       fields.append("request_type=?");       params.append(body.request_type)
        if body.review_level is not None:       fields.append("review_level=?");       params.append(body.review_level)
        if body.business_objective is not None: fields.append("business_objective=?"); params.append(body.business_objective)
        if body.change_summary is not None:     fields.append("change_summary=?");     params.append(body.change_summary)
        if body.business_owner is not None:     fields.append("business_owner=?");     params.append(body.business_owner)
        if body.requester_user is not None:     fields.append("requester_user=?");     params.append(body.requester_user)
        if body.target_date is not None:        fields.append("target_date=?");        params.append(body.target_date)
        if body.project_id is not None:         fields.append("project_id=?");         params.append(body.project_id)
        if body.roadmap_id is not None:         fields.append("roadmap_id=?");         params.append(body.roadmap_id)
        fields.append("updated_at=?"); params.append(now)
        conn.execute(f"UPDATE arb_requests SET {', '.join(fields)} WHERE id=?", params + [arb_id])
        # Update impact
        if body.impact is not None:
            imp = body.impact
            conn.execute("""
                INSERT OR REPLACE INTO arb_impact_profile(arb_request_id,business_impact,data_impact,
                    application_impact,technology_impact,security_impact,integration_impact,compliance_impact,
                    has_pii,internet_facing,new_integration,new_vendor,new_technology,expected_exception,
                    context_diagram,data_flow,interface_list,security_consideration,solution_summary)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (arb_id,
                  imp.get('business_impact','None'), imp.get('data_impact','None'),
                  imp.get('application_impact','None'), imp.get('technology_impact','None'),
                  imp.get('security_impact','None'), imp.get('integration_impact','None'),
                  imp.get('compliance_impact','None'),
                  1 if imp.get('has_pii') else 0, 1 if imp.get('internet_facing') else 0,
                  1 if imp.get('new_integration') else 0, 1 if imp.get('new_vendor') else 0,
                  1 if imp.get('new_technology') else 0, 1 if imp.get('expected_exception') else 0,
                  1 if imp.get('context_diagram') else 0, 1 if imp.get('data_flow') else 0,
                  1 if imp.get('interface_list') else 0, 1 if imp.get('security_consideration') else 0,
                  1 if imp.get('solution_summary') else 0))
            auto_level = _arb_auto_review_level(imp)
            conn.execute("UPDATE arb_requests SET review_level=? WHERE id=?", (auto_level, arb_id))
            _arb_generate_recommendations(conn, arb_id, imp)
        # Update apps
        if body.application_ids is not None:
            conn.execute("DELETE FROM arb_request_applications WHERE arb_request_id=?", (arb_id,))
            for app_id in body.application_ids:
                conn.execute("INSERT INTO arb_request_applications(arb_request_id,application_id) VALUES(?,?)", (arb_id, app_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'update_arb_request', arb_id, "Updated")
    return {"ok": True}

@app.post("/api/arb/requests/{arb_id}/submit")
def arb_submit_request(arb_id: str, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute("UPDATE arb_requests SET status='Submitted', submitted_at=?, updated_at=? WHERE id=?", (now, now, arb_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'submit_arb_request', arb_id, "Submitted for review")
    return {"ok": True}

@app.post("/api/arb/requests/{arb_id}/status")
def arb_change_status(arb_id: str, body: dict, current_user: dict = Depends(_require_writer)):
    now = datetime.now().isoformat()
    new_status = body.get('status','')
    with get_db() as conn:
        extra = {}
        if new_status == 'Closed':   extra['closed_at'] = now
        sets = "status=?, updated_at=?"
        params = [new_status, now]
        for k, v in extra.items():
            sets += f", {k}=?"
            params.append(v)
        conn.execute(f"UPDATE arb_requests SET {sets} WHERE id=?", params + [arb_id])
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'change_arb_status', arb_id, f"Status → {new_status}")
    return {"ok": True}

@app.delete("/api/arb/requests/{arb_id}")
def arb_delete_request(arb_id: str, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        for tbl in ['arb_recommendations','arb_actions','arb_decisions','arb_findings',
                    'arb_comments','arb_reviewers','arb_impact_profile','arb_request_applications']:
            conn.execute(f"DELETE FROM {tbl} WHERE arb_request_id=?", (arb_id,))
        conn.execute("DELETE FROM arb_requests WHERE id=?", (arb_id,))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'delete_arb_request', arb_id, "Deleted")
    return {"ok": True}

# ── ARB Reviewers ───────────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/reviewers")
def arb_list_reviewers(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM arb_reviewers WHERE arb_request_id=?", (arb_id,)).fetchall()]

@app.post("/api/arb/requests/{arb_id}/reviewers", status_code=201)
def arb_add_reviewer(arb_id: str, body: ArbReviewerWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute("INSERT INTO arb_reviewers(arb_request_id,reviewer_user,reviewer_role,assigned_by,assigned_at) VALUES(?,?,?,?,?)",
                     (arb_id, body.reviewer_user, body.reviewer_role, current_user.get('sub', current_user.get('username', '')), now))
        conn.execute("UPDATE arb_requests SET status='In Review', updated_at=? WHERE id=? AND status='Submitted'", (now, arb_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'assign_reviewer', arb_id, f"Assigned: {body.reviewer_user}")
    return {"ok": True}

@app.delete("/api/arb/requests/{arb_id}/reviewers/{reviewer_id}")
def arb_remove_reviewer(arb_id: str, reviewer_id: int, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        conn.execute("DELETE FROM arb_reviewers WHERE id=? AND arb_request_id=?", (reviewer_id, arb_id))
    return {"ok": True}

# ── ARB Comments ────────────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/comments")
def arb_list_comments(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM arb_comments WHERE arb_request_id=? ORDER BY created_at DESC", (arb_id,)).fetchall()]

@app.post("/api/arb/requests/{arb_id}/comments", status_code=201)
def arb_add_comment(arb_id: str, body: ArbCommentWrite, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute("INSERT INTO arb_comments(arb_request_id,reviewer_user,domain,comment_type,comment_text,severity,created_at) VALUES(?,?,?,?,?,?,?)",
                     (arb_id, current_user.get('sub', current_user.get('username', '')), body.domain, body.comment_type, body.comment_text, body.severity, now))
        conn.execute("UPDATE arb_requests SET updated_at=? WHERE id=?", (now, arb_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'add_arb_comment', arb_id, f"Domain: {body.domain}")
    return {"ok": True}

# ── ARB Findings ────────────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/findings")
def arb_list_findings(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM arb_findings WHERE arb_request_id=? ORDER BY severity DESC, created_at", (arb_id,)).fetchall()]

@app.post("/api/arb/requests/{arb_id}/findings", status_code=201)
def arb_add_finding(arb_id: str, body: ArbFindingWrite, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    finding_id = f"FND-{int(datetime.now().timestamp()*1000)}"
    with get_db() as conn:
        conn.execute("""INSERT INTO arb_findings(id,arb_request_id,category,domain,severity,description,recommended_action,owner,due_date,status,created_by,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (finding_id, arb_id, body.category, body.domain, body.severity,
                      body.description, body.recommended_action, body.owner, body.due_date, 'Open',
                      current_user.get('sub', current_user.get('username', '')), now))
        conn.execute("UPDATE arb_requests SET updated_at=? WHERE id=?", (now, arb_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'add_arb_finding', arb_id, f"Finding [{body.severity}]: {body.description[:60]}")
    return {"id": finding_id, "ok": True}

@app.put("/api/arb/findings/{finding_id}")
def arb_update_finding(finding_id: str, body: ArbFindingUpdate, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        fields, params = [], []
        if body.severity is not None:           fields.append("severity=?");            params.append(body.severity)
        if body.description is not None:        fields.append("description=?");         params.append(body.description)
        if body.recommended_action is not None: fields.append("recommended_action=?");  params.append(body.recommended_action)
        if body.owner is not None:              fields.append("owner=?");               params.append(body.owner)
        if body.due_date is not None:           fields.append("due_date=?");            params.append(body.due_date)
        if body.status is not None:             fields.append("status=?");              params.append(body.status)
        if fields:
            conn.execute(f"UPDATE arb_findings SET {', '.join(fields)} WHERE id=?", params + [finding_id])
    return {"ok": True}

# ── ARB Decisions ────────────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/decision")
def arb_get_decision(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        r = conn.execute("SELECT * FROM arb_decisions WHERE arb_request_id=?", (arb_id,)).fetchone()
        return dict(r) if r else {}

@app.post("/api/arb/requests/{arb_id}/decision", status_code=201)
def arb_set_decision(arb_id: str, body: ArbDecisionWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute("""INSERT OR REPLACE INTO arb_decisions(arb_request_id,decision_type,decision_summary,rationale,key_risks,required_next_steps,decided_by,decided_at)
                     VALUES(?,?,?,?,?,?,?,?)""",
                     (arb_id, body.decision_type, body.decision_summary, body.rationale,
                      body.key_risks, body.required_next_steps, current_user.get('sub', current_user.get('username', '')), now))
        conn.execute("UPDATE arb_requests SET status='Decision Issued', updated_at=? WHERE id=?", (now, arb_id))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'issue_arb_decision', arb_id, f"Decision: {body.decision_type}")
    return {"ok": True}

# ── ARB Actions ─────────────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/actions")
def arb_list_actions(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        today = datetime.now().strftime("%Y-%m-%d")
        rows = [dict(r) for r in conn.execute("SELECT * FROM arb_actions WHERE arb_request_id=? ORDER BY created_at", (arb_id,)).fetchall()]
        for row in rows:
            if row['status'] not in ('Closed',) and row['due_date'] and row['due_date'] < today:
                row['status'] = 'Overdue'
        return rows

@app.post("/api/arb/requests/{arb_id}/actions", status_code=201)
def arb_add_action(arb_id: str, body: ArbActionWrite, current_user: dict = Depends(_require_writer)):
    now = datetime.now().isoformat()
    action_id = f"ACT-{int(datetime.now().timestamp()*1000)}"
    with get_db() as conn:
        conn.execute("""INSERT INTO arb_actions(id,arb_request_id,finding_id,action_description,action_type,owner,due_date,required_evidence,status,closure_note,closed_at,created_by,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (action_id, arb_id, body.finding_id or '', body.action_description,
                      body.action_type, body.owner, body.due_date, body.required_evidence,
                      'Open', '', '', current_user.get('sub', current_user.get('username', '')), now))
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'add_arb_action', arb_id, f"Action: {body.action_description[:60]}")
    return {"id": action_id, "ok": True}

@app.put("/api/arb/actions/{action_id}")
def arb_update_action(action_id: str, body: ArbActionUpdate, current_user: dict = Depends(_require_auth)):
    now = datetime.now().isoformat()
    with get_db() as conn:
        fields, params = [], []
        if body.action_description is not None: fields.append("action_description=?"); params.append(body.action_description)
        if body.action_type is not None:        fields.append("action_type=?");        params.append(body.action_type)
        if body.owner is not None:              fields.append("owner=?");              params.append(body.owner)
        if body.due_date is not None:           fields.append("due_date=?");           params.append(body.due_date)
        if body.required_evidence is not None:  fields.append("required_evidence=?");  params.append(body.required_evidence)
        if body.status is not None:
            fields.append("status=?"); params.append(body.status)
            if body.status == 'Closed':
                fields.append("closed_at=?"); params.append(now)
        if body.closure_note is not None:       fields.append("closure_note=?");       params.append(body.closure_note)
        if fields:
            conn.execute(f"UPDATE arb_actions SET {', '.join(fields)} WHERE id=?", params + [action_id])
    _arb_log(current_user.get('sub', current_user.get('username', '')), 'update_arb_action', action_id, f"Status: {body.status}")
    return {"ok": True}

# ── ARB Recommendations ─────────────────────────────────────────────────────────
@app.get("/api/arb/requests/{arb_id}/recommendations")
def arb_list_recommendations(arb_id: str, current_user: dict = Depends(_require_auth)):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM arb_recommendations WHERE arb_request_id=? ORDER BY is_mandatory DESC, rec_type", (arb_id,)).fetchall()]

@app.post("/api/arb/requests/{arb_id}/generate-recommendations")
def arb_regenerate_recommendations(arb_id: str, current_user: dict = Depends(_require_writer)):
    with get_db() as conn:
        imp_row = conn.execute("SELECT * FROM arb_impact_profile WHERE arb_request_id=?", (arb_id,)).fetchone()
        if not imp_row: raise HTTPException(404, "Impact profile not found")
        _arb_generate_recommendations(conn, arb_id, dict(imp_row))
    return {"ok": True}

# ── ARB Dashboard ────────────────────────────────────────────────────────────────
@app.get("/api/arb/dashboard")
def arb_dashboard(current_user: dict = Depends(_require_auth)):
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        by_status = dict(conn.execute("SELECT status, COUNT(*) FROM arb_requests GROUP BY status").fetchall())
        by_type   = dict(conn.execute("SELECT request_type, COUNT(*) FROM arb_requests GROUP BY request_type").fetchall())
        by_level  = dict(conn.execute("SELECT review_level, COUNT(*) FROM arb_requests GROUP BY review_level").fetchall())
        by_decision = dict(conn.execute("SELECT decision_type, COUNT(*) FROM arb_decisions GROUP BY decision_type").fetchall())
        open_actions    = conn.execute("SELECT COUNT(*) FROM arb_actions WHERE status='Open'").fetchone()[0]
        overdue_actions = conn.execute("SELECT COUNT(*) FROM arb_actions WHERE status NOT IN ('Closed') AND due_date!='' AND due_date<?", (today,)).fetchone()[0]
        recent = [dict(r) for r in conn.execute(
            "SELECT id,request_code,title,request_type,review_level,status,created_by,created_at FROM arb_requests ORDER BY created_at DESC LIMIT 10"
        ).fetchall()]
        by_month = [dict(r) for r in conn.execute(
            "SELECT SUBSTR(created_at,1,7) as month, COUNT(*) as count FROM arb_requests GROUP BY month ORDER BY month DESC LIMIT 12"
        ).fetchall()]
        return {
            "by_status": by_status, "by_type": by_type, "by_level": by_level,
            "by_decision": by_decision,
            "open_actions": open_actions, "overdue_actions": overdue_actions,
            "recent_requests": recent, "by_month": by_month,
            "total": sum(by_status.values())
        }

# ── ARB CSV Export ───────────────────────────────────────────────────────────────
@app.get("/api/arb/export/csv")
def arb_export_csv(current_user: dict = Depends(_require_auth)):
    import csv, io
    with get_db() as conn:
        rows = conn.execute("""
            SELECT r.request_code, r.title, r.request_type, r.review_level, r.status,
                   r.business_owner, r.requester_user, r.target_date, r.created_at,
                   d.decision_type
            FROM arb_requests r
            LEFT JOIN arb_decisions d ON d.arb_request_id=r.id
            ORDER BY r.created_at DESC
        """).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Request Code','Title','Type','Review Level','Status','Business Owner','Requester','Target Date','Created','Decision'])
    for row in rows:
        writer.writerow(list(row))
    from fastapi.responses import Response
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=arb_requests.csv"})

# ─── STATIC + CATCH-ALL ────────────────────────────────────────────────────────
if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

@app.get("/{full_path:path}", include_in_schema=False)
def catch_all(full_path: str = ""):
    # FIX #8: Block direct access to sensitive config / database files
    _BLOCKED_FILES = {
        "users.config.json", "mpx-studio.config.json",
        "appport.db", "vendor.db", "appport_audit.db",
    }
    if any(full_path.endswith(f) for f in _BLOCKED_FILES):
        raise HTTPException(404)
    if full_path.startswith("api/"): raise HTTPException(404)
    idx = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(idx) if os.path.exists(idx) else JSONResponse(
        {"service": f"MPX AppPort EA Portfolio {APP_VERSION}", "docs": "/docs"})

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
    """Assign deterministic compliance values based on each app's attributes.
    ใช้ fixed seed=42 → reproducible ทุก run — เพิ่ม standard ใหม่ใน COMPLIANCE_STANDARDS (index.html)
    แล้วเพิ่ม rule ตรงนี้เพื่อ auto-assign seed data"""
    import random
    rng = random.Random(42)

    CLOUD_KW    = {"kubernetes","azure","aws","gcp","snowflake","heroku","terraform","kafka","cloud","istio","helm","docker","s3","lambda","fargate","bigquery"}
    EVENT_KW    = {"kafka","rabbitmq","activemq","nats","eventbridge","pubsub","sqs","sns","mq","celery","redis streams"}
    AI_KW       = {"tensorflow","pytorch","scikit","llm","gpt","openai","huggingface","langchain","ml","ai","vertex","sagemaker","mlflow","onnx","transformers"}
    OT_KW       = {"scada","plc","ics","modbus","opc","dnp3","profibus","dcs","fieldbus","bacnet"}
    WEB_KW      = {"react","angular","vue","next","nuxt","jquery","html","css","javascript","typescript","svelte","blazor"}
    PAYMENT_KW  = {"payment","visa","mastercard","stripe","omise","promptpay","2c2p","paymentsense"}
    BANKING_KW  = {"bank","banking","swift","sepa","clearing","settlement","iso20022","core bank","ledger","treasury","fx","nostro"}
    TELCO_KW    = {"telco","telecom","billing","cdr","diameter","ss7","voip","4g","5g","ims","bss","oss"}
    HEALTH_KW   = {"hl7","fhir","his","ehr","emr","hospital","clinic","patient","dicom","lab","pharmacy"}
    IDENTITY_KW = {"iam","sso","ldap","oauth","saml","oidc","identity","auth","pki","certificate","keycloak","okta","ping"}
    DATA_KW     = {"warehouse","lake","catalog","mdm","etl","pipeline","olap","bi","dbt","airflow","spark","flink","databricks","superset","metabase"}

    for app in apps:
        stack  = (app.get("stack","") or "").lower()
        name   = (app.get("name","") or "").lower()
        domain = (app.get("domain","") or "").lower()
        ea_cat = (app.get("ea_category","") or "").lower()
        ea_grp = (app.get("ea_group","") or "").lower()
        crit   = app.get("criticality","")
        svc    = app.get("service_hour","")
        integ  = int(app.get("integration", 0) or 0)
        strat  = int(app.get("strategic", 0) or 0)
        atype  = app.get("type","")

        is_mc      = crit == "Mission Critical"
        is_high    = crit in ("Mission Critical","High")
        is_cloud   = any(k in stack for k in CLOUD_KW)
        is_event   = any(k in stack for k in EVENT_KW)
        is_ai      = any(k in stack for k in AI_KW) or any(x in name for x in ("ai","ml","llm","genai","nlp"))
        is_ot      = any(k in stack for k in OT_KW)
        is_web     = any(k in stack for k in WEB_KW)
        is_payment = any(k in name or k in domain for k in PAYMENT_KW)
        is_banking = any(k in name or k in domain for k in BANKING_KW) or domain in ("finance","banking","treasury")
        is_telco   = any(k in name or k in domain for k in TELCO_KW)
        is_health  = any(k in name or k in domain for k in HEALTH_KW)
        is_identity= any(k in name or k in domain for k in IDENTITY_KW)
        is_data    = any(k in name or k in domain for k in DATA_KW) or domain in ("analytics","data","bi","reporting")
        is_inhouse = atype in ("Inhouse",)
        is_saas    = atype in ("Package","SaaS") and is_cloud
        has_pii    = bool(app.get("pi_spi"))
        has_dr     = bool(app.get("dr"))
        is_24x7    = svc == "24x7"
        hi_integ   = integ > 8
        vhi_integ  = integ > 15
        is_strategic = strat > 70
        is_core    = "core" in ea_grp or "core" in name
        is_finance = domain in ("finance","accounting","treasury")
        is_cx      = domain in ("crm","customer","portal","digital","ecommerce","marketing","retail")

        e = set()

        # ── EA Governance ──────────────────────────────────────────────────────
        if is_strategic or is_mc or is_core:   e.update(["TOGAF 10th Ed.","ArchiMate 3.2"])
        if is_mc or is_finance or "gov" in ea_cat: e.add("COBIT 2019")
        if is_mc:                               e.add("ISO/IEC 38500")
        if "platform" in name or "infra" in name or "it" in domain: e.add("IT4IT")

        # ── Process & Decision ─────────────────────────────────────────────────
        if hi_integ or "process" in name or "workflow" in name or is_finance: e.add("BPMN 2.x")
        if is_finance or "rule" in name or "decision" in name or "bpm" in name: e.add("DMN 1.5")

        # ── Industry Reference ─────────────────────────────────────────────────
        if is_telco:                            e.add("TM Forum ODA")
        if is_banking or is_finance:            e.add("BIAN Service Landscape")

        # ── Data Management ────────────────────────────────────────────────────
        if is_data or "data" in name:           e.update(["DAMA-DMBOK","EDM Council DCAM"])
        if is_data or "mdm" in name or "master" in name: e.add("ISO 8000")
        if is_data or "catalog" in name or "metadata" in name: e.add("ISO/IEC 11179")

        # ── Privacy ────────────────────────────────────────────────────────────
        if has_pii:                             e.update(["ISO/IEC 29100","GDPR / Thailand PDPA"])

        # ── Software Engineering ───────────────────────────────────────────────
        if is_inhouse:                          e.update(["ISO/IEC/IEEE 12207","ISO/IEC/IEEE 29119"])
        if is_inhouse or is_high:               e.add("ISO/IEC 25010")

        # ── API & Integration ──────────────────────────────────────────────────
        if is_event:                            e.add("AsyncAPI")
        if hi_integ or vhi_integ:              e.add("OpenAPI 3.x")
        if is_cx or is_web or "portal" in name: e.add("WCAG 2.2")

        # ── IT Service Management ──────────────────────────────────────────────
        if is_high or is_24x7:                  e.add("ITIL 4")
        if is_mc and is_24x7:                  e.add("ISO/IEC 20000-1")

        # ── Resilience & Risk ──────────────────────────────────────────────────
        if is_mc:                               e.add("ISO 22301")
        if is_high or is_finance:              e.add("ISO 31000")
        if is_cloud and is_high:               e.update(["ISO/IEC 27017","CSA CCM"])
        if is_cloud and has_pii:               e.add("ISO/IEC 27018")
        if is_saas or is_cloud:               e.add("SOC 2")
        if is_mc and is_24x7:                  e.add("SRE practices")

        # ── Cybersecurity ──────────────────────────────────────────────────────
        if has_pii or is_high:                 e.add("ISO/IEC 27001")
        if is_mc:                               e.update(["ISO/IEC 27002","Zero-Trust"])
        if is_finance or is_banking or is_mc:  e.add("NIST CSF 2.0")
        if is_mc and (is_finance or has_pii):  e.add("NIST SP 800-53 Rev.5")
        if is_high:                            e.add("CIS Controls v8")
        if is_inhouse and (is_web or hi_integ): e.add("OWASP ASVS")
        if is_inhouse or is_web:               e.add("OWASP Top 10")
        if is_mc and (is_finance or is_banking): e.add("SABSA")
        if is_ot:                              e.update(["IEC/ISA 62443"])

        # ── AI & Emerging Tech ─────────────────────────────────────────────────
        if is_ai:                              e.update(["OWASP Top 10 for LLM","NIST AI RMF","ISO/IEC 42001","EU AI Act"])

        # ── Financial & Regulatory ─────────────────────────────────────────────
        if is_banking or is_finance:           e.add("ISO 20022")
        if is_identity:                        e.add("eIDAS 2.0")
        if is_payment:                         e.add("PCI DSS")
        if is_finance or is_banking:           e.add("DORA / NIS2")
        if is_health:                          e.add("HIPAA Security Rule")

        # ── Internal Policies ──────────────────────────────────────────────────
        if has_dr:                             e.add("DR Policy")
        if hi_integ:                           e.add("API Standards")
        if is_cloud:                           e.add("Cloud-First")

        eligible = sorted(e)
        if eligible:
            # Coverage ratio: MC=65-90%, High=45-70%, others=25-55%
            lo, hi = (0.65, 0.90) if is_mc else (0.45, 0.70) if is_high else (0.25, 0.55)
            n = rng.randint(max(1, int(len(eligible)*lo)), max(1, int(len(eligible)*hi)))
            n = min(n, len(eligible))
            app["compliance"] = json.dumps(sorted(rng.sample(eligible, n)))
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
    init_esa_db()
    init_ea_domains_db()
    init_db()
    # Start NVD CVE daily refresh background thread
    threading.Thread(target=_nvd_daily_refresh, daemon=True).start()

# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print(f"\n{'='*55}")
    print(f"  {APP_NAME} EA Portfolio {APP_VERSION}")
    print(f"{'='*55}")
    print(f"  Config   : {_CONFIG_PATH}")
    print(f"  Frontend : http://localhost:{PORT}/")
    print(f"  API Docs : http://localhost:{PORT}/docs")
    print(f"  Database : {os.path.abspath(DB_PATH)}")
    print(f"  Audit DB : {os.path.abspath(AUDIT_DB_PATH)}")
    print(f"{'='*55}\n")
    # Railway: reload=False in production; use $PORT from environment
    reload_mode = os.environ.get("APP_ENV", "development") == "development"
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=reload_mode, reload_excludes=["*.db"])
