"""
Seed Server Inventory (tech_servers) + App Tech Map (tech_usage)
รัน:  python3 seed_infra.py
DB:   ea_domains.db (tech tables) + appport.db (applications)
"""
import sqlite3, uuid, random
from datetime import datetime, timedelta

EA_DB   = "ea_domains.db"
APP_DB  = "appport.db"

def uid(prefix):
    return f"{prefix}-" + uuid.uuid4().hex[:6].upper()

def days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d")

# ─────────────────────────────────────────────────────────────────
# SERVER INVENTORY DATA  (30 servers)
# ─────────────────────────────────────────────────────────────────
SERVERS = [
    # (hostname, ip, env, type, location, os_name, os_ver, cpu, ram, managed_by, status, note)
    # ── Production ─────────────────────────────────────────────────
    ("prd-app-001", "10.10.1.11", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS", 16, 64,  "Platform Team",  "Active",  "K8s worker node 1"),
    ("prd-app-002", "10.10.1.12", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS", 16, 64,  "Platform Team",  "Active",  "K8s worker node 2"),
    ("prd-app-003", "10.10.1.13", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS", 16, 64,  "Platform Team",  "Active",  "K8s worker node 3"),
    ("prd-db-001",  "10.10.2.11", "Production", "Physical", "DC-BKK-1", "RHEL",          "8.9",        32, 256, "DBA Team",       "Active",  "PostgreSQL Primary"),
    ("prd-db-002",  "10.10.2.12", "Production", "Physical", "DC-BKK-1", "RHEL",          "8.9",        32, 256, "DBA Team",       "Active",  "PostgreSQL Replica"),
    ("prd-db-003",  "10.10.2.13", "Production", "Physical", "DC-BKK-1", "RHEL",          "8.9",        32, 128, "DBA Team",       "Active",  "Oracle RAC Node 1"),
    ("prd-db-004",  "10.10.2.14", "Production", "Physical", "DC-BKK-1", "RHEL",          "8.9",        32, 128, "DBA Team",       "Active",  "Oracle RAC Node 2"),
    ("prd-web-001", "10.10.3.11", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "Platform Team",  "Active",  "Nginx Load Balancer 1"),
    ("prd-web-002", "10.10.3.12", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "Platform Team",  "Active",  "Nginx Load Balancer 2"),
    ("prd-msg-001", "10.10.4.11", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "20.04 LTS", 16, 64,  "Platform Team",  "Active",  "Kafka Broker 1"),
    ("prd-msg-002", "10.10.4.12", "Production", "VM",       "DC-BKK-1", "Ubuntu Server", "20.04 LTS", 16, 64,  "Platform Team",  "Active",  "Kafka Broker 2"),
    ("prd-cache-001","10.10.5.11","Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "Platform Team",  "Active",  "Redis Primary"),
    ("prd-cache-002","10.10.5.12","Production", "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "Platform Team",  "Active",  "Redis Replica"),
    # ── Cloud Production ───────────────────────────────────────────
    ("aws-eks-001",  "172.31.1.11","Production","Cloud",    "AWS-ap-southeast-1","Amazon Linux","2023",  8, 32,  "Cloud Team",     "Active",  "EKS Managed Node - ap-se-1a"),
    ("aws-eks-002",  "172.31.1.12","Production","Cloud",    "AWS-ap-southeast-1","Amazon Linux","2023",  8, 32,  "Cloud Team",     "Active",  "EKS Managed Node - ap-se-1b"),
    ("aws-rds-001",  "172.31.2.11","Production","Cloud",    "AWS-ap-southeast-1","Amazon RDS","PostgreSQL 16", 16, 128,"Cloud Team", "Active","RDS Multi-AZ Primary"),
    ("az-aks-001",   "10.240.1.11","Production","Cloud",    "Azure-SEA",         "Azure AKS",   "1.29",   8, 32,  "Cloud Team",     "Active",  "AKS Node Pool - system"),
    # ── UAT ────────────────────────────────────────────────────────
    ("uat-app-001",  "10.20.1.11", "UAT",       "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "DevOps Team",    "Active",  "UAT App Server 1"),
    ("uat-app-002",  "10.20.1.12", "UAT",       "VM",       "DC-BKK-1", "Ubuntu Server", "22.04 LTS",  8, 32,  "DevOps Team",    "Active",  "UAT App Server 2"),
    ("uat-db-001",   "10.20.2.11", "UAT",       "VM",       "DC-BKK-1", "RHEL",          "8.9",         8, 64,  "DBA Team",       "Active",  "UAT PostgreSQL"),
    ("uat-db-002",   "10.20.2.12", "UAT",       "VM",       "DC-BKK-1", "Windows Server","2022",        8, 64,  "DBA Team",       "Active",  "UAT MSSQL Server"),
    # ── Development ────────────────────────────────────────────────
    ("dev-k8s-001",  "10.30.1.11", "Dev",       "VM",       "DC-BKK-2", "Ubuntu Server", "22.04 LTS",  8, 32,  "DevOps Team",    "Active",  "Dev K8s Cluster Node 1"),
    ("dev-k8s-002",  "10.30.1.12", "Dev",       "VM",       "DC-BKK-2", "Ubuntu Server", "22.04 LTS",  8, 32,  "DevOps Team",    "Active",  "Dev K8s Cluster Node 2"),
    ("dev-db-001",   "10.30.2.11", "Dev",       "VM",       "DC-BKK-2", "Ubuntu Server", "22.04 LTS",  4, 16,  "DevOps Team",    "Active",  "Dev Shared DB"),
    # ── DR ─────────────────────────────────────────────────────────
    ("dr-app-001",   "10.50.1.11", "DR",        "Physical", "DC-NMA-1", "RHEL",          "8.9",        16, 64,  "Platform Team",  "Active",  "DR App Server 1"),
    ("dr-app-002",   "10.50.1.12", "DR",        "Physical", "DC-NMA-1", "RHEL",          "8.9",        16, 64,  "Platform Team",  "Active",  "DR App Server 2"),
    ("dr-db-001",    "10.50.2.11", "DR",        "Physical", "DC-NMA-1", "RHEL",          "8.9",        32, 128, "DBA Team",       "Active",  "DR PostgreSQL Standby"),
    # ── Legacy / Phase-out ─────────────────────────────────────────
    ("leg-as400-001","10.10.9.11", "Production","Physical", "DC-BKK-1", "IBM i",         "7.4",        8,  64,  "Legacy Team",    "Active",  "Core Banking AS/400 Main"),
    ("leg-sap-001",  "10.10.9.12", "Production","Physical", "DC-BKK-1", "SUSE Linux",    "12 SP5",     64, 512, "SAP Team",       "Active",  "SAP S/4HANA App Server"),
    ("leg-win-001",  "10.10.9.20", "Production","Physical", "DC-BKK-1", "Windows Server","2019",        8,  32,  "IT Ops",         "Active",  "Legacy Print & File Server"),
]

# ─────────────────────────────────────────────────────────────────
# APP → TECH MAP
# แต่ละ app ใช้ tech อะไรบ้าง
# (app_id, [(tech_name, installed_ver, env, usage_type)])
# ─────────────────────────────────────────────────────────────────
APP_TECH_MAP = {
    "APP-001": [  # SAP S/4HANA
        ("SAP HANA",        "2.0 SP7",    "Production", "Runtime"),
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("SUSE Linux",      "12 SP5",     "Production", "Infrastructure"),
        ("Nginx",           "1.24.0",     "Production", "Infrastructure"),
    ],
    "APP-002": [  # Salesforce CRM
        ("JavaScript",      "ES2022",     "Production", "Frontend"),
        ("Node.js",         "20.11.0",    "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
    ],
    "APP-003": [  # Core Banking AS/400
        ("IBM i",           "7.4",        "Production", "Infrastructure"),
        ("RPG",             "IV",         "Production", "Runtime"),
    ],
    "APP-004": [  # HR WorkDay
        ("React",           "18.2.0",     "Production", "Frontend"),
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-005": [  # AI Analytics Hub
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("FastAPI",         "0.110.0",    "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
        ("Apache Kafka",    "3.7.0",      "Production", "Infrastructure"),
    ],
    "APP-006": [  # Legacy ERP Oracle
        ("Oracle Database", "19c",        "Production", "Runtime"),
        ("Java",            "8.0.402",    "Production", "Runtime"),
        ("Apache Tomcat",   "9.0.86",     "Production", "Runtime"),
    ],
    "APP-007": [  # K8s Platform
        ("Kubernetes",      "1.29.2",     "Production", "Runtime"),
        ("Docker",          "25.0.3",     "Production", "Runtime"),
        ("Nginx",           "1.24.0",     "Production", "Infrastructure"),
        ("Istio",           "1.21.0",     "Production", "Infrastructure"),
    ],
    "APP-008": [  # Data Warehouse v2
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("Apache Airflow",  "2.8.3",      "Production", "Runtime"),
        ("ClickHouse",      "24.3.1",     "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-009": [  # Supply Chain SAP
        ("SAP HANA",        "2.0 SP7",    "Production", "Runtime"),
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("SUSE Linux",      "12 SP5",     "Production", "Infrastructure"),
    ],
    "APP-010": [  # Customer Portal
        ("React",           "18.2.0",     "Production", "Frontend"),
        ("TypeScript",      "5.4.2",      "Production", "Frontend"),
        ("Next.js",         "14.1.3",     "Production", "Runtime"),
        ("Node.js",         "20.11.0",    "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Nginx",           "1.24.0",     "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-012": [  # Azure DevOps
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
        ("Docker",          "25.0.3",     "Production", "Build-tool"),
        ("Python",          "3.11.8",     "Production", "Build-tool"),
    ],
    "APP-013": [  # Power BI Platform
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("Microsoft SQL Server","2022",   "Production", "Runtime"),
    ],
    "APP-015": [  # Treasury System
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("Spring Boot",     "3.2.3",      "Production", "Runtime"),
        ("Oracle Database", "19c",        "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
    ],
    "APP-016": [  # Identity Platform
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("FastAPI",         "0.110.0",    "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Nginx",           "1.24.0",     "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-017": [  # ITSM ServiceNow
        ("JavaScript",      "ES2022",     "Production", "Frontend"),
        ("Node.js",         "20.11.0",    "Production", "Runtime"),
        ("MySQL",           "8.0.36",     "Production", "Runtime"),
    ],
    "APP-018": [  # Batch Processing v2
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("Apache Kafka",    "3.7.0",      "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-019": [  # Document Mgmt
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("Spring Boot",     "3.2.3",      "Production", "Runtime"),
        ("MongoDB",         "7.0.6",      "Production", "Runtime"),
        ("Elasticsearch",   "8.13.0",     "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-020": [  # API Gateway
        ("Go",              "1.22.1",     "Production", "Runtime"),
        ("Nginx",           "1.24.0",     "Production", "Infrastructure"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-022": [  # e-Commerce Platform
        ("TypeScript",      "5.4.2",      "Production", "Frontend"),
        ("React",           "18.2.0",     "Production", "Frontend"),
        ("Next.js",         "14.1.3",     "Production", "Runtime"),
        ("Node.js",         "20.11.0",    "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Elasticsearch",   "8.13.0",     "Production", "Runtime"),
        ("Apache Kafka",    "3.7.0",      "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-023": [  # Risk Mgmt System
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("FastAPI",         "0.110.0",    "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
    ],
    "APP-024": [  # ML Feature Store
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("FastAPI",         "0.110.0",    "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
        ("Apache Kafka",    "3.7.0",      "Production", "Infrastructure"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-026": [  # Cloud MDM
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("Spring Boot",     "3.2.3",      "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-029": [  # ServiceMesh Istio
        ("Istio",           "1.21.0",     "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
        ("Go",              "1.22.1",     "Production", "Runtime"),
    ],
    "APP-030": [  # Procurement Ariba
        ("Java",            "11.0.22",    "Production", "Runtime"),
        ("Spring Boot",     "2.7.18",     "Production", "Runtime"),
        ("Oracle Database", "19c",        "Production", "Runtime"),
    ],
    "APP-031": [  # (generic fallback)
        ("Python",          "3.10.14",    "Production", "Runtime"),
        ("PostgreSQL",      "14.11",      "Production", "Runtime"),
        ("Kubernetes",      "1.28.7",     "Production", "Infrastructure"),
    ],
    "APP-032": [
        ("Java",            "11.0.22",    "Production", "Runtime"),
        ("Spring Boot",     "2.7.18",     "Production", "Runtime"),
        ("MySQL",           "8.0.36",     "Production", "Runtime"),
    ],
    "APP-033": [
        ("TypeScript",      "5.4.2",      "Production", "Frontend"),
        ("Angular",         "17.3.0",     "Production", "Frontend"),
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
    ],
    "APP-034": [
        ("Go",              "1.22.1",     "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
        ("Redis",           "7.2.4",      "Production", "Infrastructure"),
    ],
    "APP-035": [
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("Django",          "5.0.3",      "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-036": [
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("Apache Kafka",    "3.7.0",      "Production", "Runtime"),
        ("MongoDB",         "7.0.6",      "Production", "Runtime"),
    ],
    "APP-037": [
        ("TypeScript",      "5.4.2",      "Production", "Frontend"),
        ("Vue.js",          "3.4.21",     "Production", "Frontend"),
        ("Node.js",         "20.11.0",    "Production", "Runtime"),
        ("MySQL",           "8.0.36",     "Production", "Runtime"),
    ],
    "APP-038": [
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("FastAPI",         "0.110.0",    "Production", "Runtime"),
        ("Elasticsearch",   "8.13.0",     "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
    "APP-039": [
        ("Java",            "17.0.9",     "Production", "Runtime"),
        ("Spring Boot",     "3.2.3",      "Production", "Runtime"),
        ("PostgreSQL",      "16.2",       "Production", "Runtime"),
    ],
    "APP-040": [
        ("Python",          "3.11.8",     "Production", "Runtime"),
        ("Apache Airflow",  "2.8.3",      "Production", "Runtime"),
        ("PostgreSQL",      "15.6",       "Production", "Runtime"),
        ("Kubernetes",      "1.29.2",     "Production", "Infrastructure"),
    ],
}

# ─────────────────────────────────────────────────────────────────
# SERVER → TECH MAP (software installed on each server)
# (server_hostname, [(tech_name, installed_ver, usage_type)])
# ─────────────────────────────────────────────────────────────────
SERVER_TECH_MAP = {
    "prd-app-001":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "prd-app-002":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "prd-app-003":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "prd-db-001":   [("PostgreSQL","16.2","Runtime"),   ("RHEL","8.9","Infrastructure")],
    "prd-db-002":   [("PostgreSQL","16.2","Runtime"),   ("RHEL","8.9","Infrastructure")],
    "prd-db-003":   [("Oracle Database","19c","Runtime"),("RHEL","8.9","Infrastructure")],
    "prd-db-004":   [("Oracle Database","19c","Runtime"),("RHEL","8.9","Infrastructure")],
    "prd-web-001":  [("Nginx","1.24.0","Runtime"),      ("Ubuntu Server","22.04","Infrastructure")],
    "prd-web-002":  [("Nginx","1.24.0","Runtime"),      ("Ubuntu Server","22.04","Infrastructure")],
    "prd-msg-001":  [("Apache Kafka","3.7.0","Runtime"), ("Ubuntu Server","20.04","Infrastructure")],
    "prd-msg-002":  [("Apache Kafka","3.7.0","Runtime"), ("Ubuntu Server","20.04","Infrastructure")],
    "prd-cache-001":[("Redis","7.2.4","Runtime"),        ("Ubuntu Server","22.04","Infrastructure")],
    "prd-cache-002":[("Redis","7.2.4","Runtime"),        ("Ubuntu Server","22.04","Infrastructure")],
    "aws-eks-001":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime")],
    "aws-eks-002":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime")],
    "aws-rds-001":  [("PostgreSQL","16.2","Runtime")],
    "az-aks-001":   [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime")],
    "uat-app-001":  [("Kubernetes","1.28.7","Runtime"), ("Docker","24.0.9","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "uat-app-002":  [("Kubernetes","1.28.7","Runtime"), ("Docker","24.0.9","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "uat-db-001":   [("PostgreSQL","15.6","Runtime"),   ("RHEL","8.9","Infrastructure")],
    "uat-db-002":   [("Microsoft SQL Server","2022","Runtime")],
    "dev-k8s-001":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "dev-k8s-002":  [("Kubernetes","1.29.2","Runtime"), ("Docker","25.0.3","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "dev-db-001":   [("PostgreSQL","16.2","Runtime"), ("MySQL","8.0.36","Runtime"), ("Ubuntu Server","22.04","Infrastructure")],
    "dr-app-001":   [("Kubernetes","1.28.7","Runtime"), ("RHEL","8.9","Infrastructure")],
    "dr-app-002":   [("Kubernetes","1.28.7","Runtime"), ("RHEL","8.9","Infrastructure")],
    "dr-db-001":    [("PostgreSQL","16.2","Runtime"),   ("RHEL","8.9","Infrastructure")],
    "leg-as400-001":[("IBM i","7.4","Runtime")],
    "leg-sap-001":  [("SAP HANA","2.0 SP7","Runtime"), ("Java","17.0.9","Runtime"), ("SUSE Linux","12 SP5","Infrastructure")],
    "leg-win-001":  [("Windows Server","2019","Infrastructure")],
}

# ─────────────────────────────────────────────────────────────────
def seed():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Connect to ea_domains.db ──────────────────────────────────
    ea = sqlite3.connect(EA_DB)
    ea.row_factory = sqlite3.Row
    ea.execute("PRAGMA journal_mode=WAL")

    # ── Load tech_catalog name→id map ─────────────────────────────
    rows = ea.execute("SELECT id, name FROM tech_catalog").fetchall()
    tech_map = {r["name"]: r["id"] for r in rows}
    print(f"Loaded {len(tech_map)} tech catalog entries")

    # ── Load versions: tech_id → latest version row ───────────────
    ver_rows = ea.execute("SELECT id, tech_id, version_label FROM tech_versions WHERE is_latest=1").fetchall()
    ver_map  = {r["tech_id"]: (r["id"], r["version_label"]) for r in ver_rows}
    print(f"Loaded {len(ver_map)} latest versions")

    # ══════════════════════════════════════════════════════════════
    # 1. SEED tech_servers
    # ══════════════════════════════════════════════════════════════
    print("\n── Seeding tech_servers ──")
    srv_id_map = {}  # hostname → id
    srv_count = 0
    for row in SERVERS:
        hostname, ip, env, stype, location, os_name, os_ver, cpu, ram, managed_by, status, note = row
        existing = ea.execute("SELECT id FROM tech_servers WHERE hostname=?", (hostname,)).fetchone()
        if existing:
            srv_id_map[hostname] = existing["id"]
            continue
        sid = uid("SRV")
        srv_id_map[hostname] = sid
        ea.execute("""INSERT INTO tech_servers
            (id,hostname,ip_address,environment,server_type,location,
             os_name,os_version,cpu_core,ram_gb,managed_by,status,note,
             created_by,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, hostname, ip, env, stype, location,
             os_name, os_ver, cpu, ram, managed_by, status, note,
             "seed", now, now))
        srv_count += 1

    ea.commit()
    print(f"  → {srv_count} servers inserted")

    # ══════════════════════════════════════════════════════════════
    # 2. SEED tech_usage — App → Tech
    # ══════════════════════════════════════════════════════════════
    print("\n── Seeding App Tech Map (tech_usage) ──")

    # Load apps from appport.db
    try:
        app_conn = sqlite3.connect(APP_DB)
        app_conn.row_factory = sqlite3.Row
        all_apps = app_conn.execute("SELECT id, name FROM applications").fetchall()
        app_id_set = {a["id"] for a in all_apps}
        print(f"  Loaded {len(app_id_set)} apps from {APP_DB}")
        app_conn.close()
    except Exception as e:
        print(f"  Warning: could not load apps ({e}) — using predefined list only")
        app_id_set = set(APP_TECH_MAP.keys())

    usage_count = 0
    for app_id, tech_list in APP_TECH_MAP.items():
        if app_id not in app_id_set:
            continue
        for tech_name, installed_ver, env, usage_type in tech_list:
            tid = tech_map.get(tech_name)
            if not tid:
                print(f"    SKIP: tech '{tech_name}' not in catalog")
                continue
            vid_info = ver_map.get(tid)
            vid = vid_info[0] if vid_info else None

            # check duplicate
            dup = ea.execute(
                "SELECT id FROM tech_usage WHERE tech_id=? AND app_id=? AND usage_type=? AND environment=?",
                (tid, app_id, usage_type, env)
            ).fetchone()
            if dup:
                continue

            ea.execute("""INSERT INTO tech_usage
                (id,tech_id,version_id,usage_target_type,app_id,server_id,
                 environment,usage_type,installed_version,created_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid("TU"), tid, vid, "App", app_id, None,
                 env, usage_type, installed_ver, "seed", now, now))
            usage_count += 1

    ea.commit()
    print(f"  → {usage_count} App→Tech usage records inserted")

    # ══════════════════════════════════════════════════════════════
    # 3. SEED tech_usage — Server → Tech
    # ══════════════════════════════════════════════════════════════
    print("\n── Seeding Server Tech Map (tech_usage) ──")
    srv_usage_count = 0
    for hostname, tech_list in SERVER_TECH_MAP.items():
        sid = srv_id_map.get(hostname)
        if not sid:
            continue
        # get server env
        srv_row = ea.execute("SELECT environment FROM tech_servers WHERE id=?", (sid,)).fetchone()
        srv_env = srv_row["environment"] if srv_row else "Production"

        for tech_name, installed_ver, usage_type in tech_list:
            tid = tech_map.get(tech_name)
            if not tid:
                continue
            vid_info = ver_map.get(tid)
            vid = vid_info[0] if vid_info else None

            dup = ea.execute(
                "SELECT id FROM tech_usage WHERE tech_id=? AND server_id=? AND usage_type=?",
                (tid, sid, usage_type)
            ).fetchone()
            if dup:
                continue

            ea.execute("""INSERT INTO tech_usage
                (id,tech_id,version_id,usage_target_type,app_id,server_id,
                 environment,usage_type,installed_version,created_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid("TU"), tid, vid, "Server", None, sid,
                 srv_env, usage_type, installed_ver, "seed", now, now))
            srv_usage_count += 1

    ea.commit()
    print(f"  → {srv_usage_count} Server→Tech usage records inserted")

    # ── Summary ───────────────────────────────────────────────────
    print("\n=== SEED INFRA COMPLETE ===")
    for tbl in ["tech_servers", "tech_usage"]:
        count = ea.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        print(f"  {tbl}: {count} rows")

    # breakdown tech_usage by target type
    for ttype in ["App", "Server"]:
        c = ea.execute("SELECT COUNT(*) FROM tech_usage WHERE usage_target_type=?", (ttype,)).fetchone()[0]
        print(f"    ↳ {ttype}: {c} records")

    ea.close()

if __name__ == "__main__":
    seed()
