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
import json, os, sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError:
    print("=" * 60)
    print("ERROR: FastAPI not installed.")
    print("Run: pip install fastapi uvicorn")
    print("=" * 60)
    raise SystemExit(1)

# ─── CONFIG — อ่านจาก appport.config.json ────────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "appport.config.json")

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
        print(f"ℹ️  appport.config.json not found — using defaults")
    return defaults

CFG          = _load_config()
APP_VERSION  = CFG["version"]
APP_NAME     = CFG.get("app_name", "MPX AppPort")
APP_SUBTITLE = CFG.get("subtitle", "EA PORTFOLIO")

_BASE      = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(_BASE, "appport.db")
PORT       = 8000
STATIC_DIR = os.path.join(_BASE, "static")

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
def r_version():
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
def get_config():
    """Return full appport.config.json (re-read each time so hot-editable)."""
    return _load_config()

@app.get("/api/config/mpx2/badges")
def get_mpx2_badges():
    """Return MPX2 badge positions from config."""
    cfg = _load_config()
    return {"badges": cfg.get("mpx2", {}).get("badges", [])}

@app.get("/api/stats")
def r_stats():
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
           search: Optional[str]=None, show_decomm: bool=False):
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
def r_get(app_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    if not row: raise HTTPException(404, f"App {app_id} not found")
    return row_to_dict(row)

@app.post("/api/apps", status_code=201)
def r_create(body: AppWrite):
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
    return {"id": aid, "message": "Created"}

@app.put("/api/apps/{app_id}")
def r_update(app_id: str, body: AppWrite):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        # BUG-02: ป้องกันการแก้ไข app ที่ถูก decommission แล้ว
        if row["decommissioned"]: raise HTTPException(400, "Cannot update a decommissioned application")
        c = dict(row)
        # BUG-13: body.dict() deprecated ใน Pydantic v2 → ใช้ model_dump() พร้อม fallback
        _dump = getattr(body, "model_dump", None) or getattr(body, "dict")
        for k, v in _dump().items():
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
    return {"id": app_id, "message": "Updated"}

@app.post("/api/apps/{app_id}/decommission")
def r_decommission(app_id: str, body: DecommBody):
    with get_db() as conn:
        row = conn.execute("SELECT id, decommissioned FROM applications WHERE id=?", (app_id,)).fetchone()
        if not row: raise HTTPException(404, f"App {app_id} not found")
        if row["decommissioned"]: raise HTTPException(400, "Already decommissioned")
        conn.execute("""UPDATE applications SET decommissioned=1, status='Decommissioned',
            decomm_date=?, decomm_reason=?, last_updated=? WHERE id=?""",
            (body.decomm_date, body.decomm_reason, datetime.now().strftime("%Y-%m-%d"), app_id))
    return {"id": app_id, "message": "Decommissioned"}

# ─── EXPORT ────────────────────────────────────────────────────────────────────
@app.get("/api/export")
def r_export(include_decomm: bool = False):
    """Export all apps as JSON — frontend converts to XLSX."""
    with get_db() as conn:
        sql = "SELECT * FROM applications"
        if not include_decomm:
            sql += " WHERE decommissioned=0"
        sql += " ORDER BY id"
        rows = conn.execute(sql).fetchall()
    return [row_to_dict(r) for r in rows]

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
def r_import(body: ImportBody):
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

    return {"added": added, "updated": updated, "errors": errors,
            "total": added + updated, "message": f"Import complete"}


@app.get("/api/ea/structure")
def r_ea_structure():
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

# ─── STATIC + CATCH-ALL ────────────────────────────────────────────────────────
if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

@app.get("/{full_path:path}", include_in_schema=False)
def catch_all(full_path: str = ""):
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

# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    init_db()
    print(f"\n{'='*55}")
    print(f"  {APP_NAME} EA Portfolio {APP_VERSION}")
    print(f"{'='*55}")
    print(f"  Config   : {_CONFIG_PATH}")
    print(f"  Frontend : http://localhost:{PORT}/")
    print(f"  API Docs : http://localhost:{PORT}/docs")
    print(f"  Database : {os.path.abspath(DB_PATH)}")
    print(f"{'='*55}\n")
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=True, reload_excludes=["*.db"])
