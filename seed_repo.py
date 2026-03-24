"""
Seed EA Repository:
  - repo_standards  : 25 Architecture Standards
  - repo_links      : App→Capability, App→DataDomain, App→Tech,
                      App→ABB, Standard→App, ARBDecision→App
รัน: python3 seed_repo.py
"""
import sqlite3, uuid
from datetime import datetime

EA_DB  = "ea_domains.db"
APP_DB = "appport.db"
ESA_DB = "esa.db"

def uid(prefix): return f"{prefix}-" + uuid.uuid4().hex[:6].upper()
def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ═══════════════════════════════════════════════════════════════════════════════
# 1. ARCHITECTURE STANDARDS (25 entries)
# ═══════════════════════════════════════════════════════════════════════════════
STANDARDS = [
    # (code, category, title, description, rationale, guidance, status, version, owner)
    # ── Security ────────────────────────────────────────────────────────────────
    ("STD-SEC-001", "Security",
     "Zero Trust Architecture",
     "ทุก request ต้องผ่านการ authenticate และ authorize โดยไม่ไว้วางใจ network ภายในโดยปริยาย",
     "ลด attack surface จาก insider threat และ lateral movement",
     "ใช้ Identity-aware proxy, MFA, Least-privilege access, Micro-segmentation",
     "Active", "1.2", "CISO Office"),

    ("STD-SEC-002", "Security",
     "Data Encryption at Rest and in Transit",
     "ข้อมูล sensitive ต้องเข้ารหัสทั้งขณะเก็บ (AES-256) และขณะส่ง (TLS 1.3+)",
     "ป้องกันการรั่วไหลของข้อมูลเมื่อ medium ถูกเข้าถึงโดยไม่ได้รับอนุญาต",
     "ใช้ KMS สำหรับ key management, ห้ามใช้ TLS < 1.2 โดยเด็ดขาด",
     "Active", "1.0", "CISO Office"),

    ("STD-SEC-003", "Security",
     "Secret & Credential Management",
     "ห้ามฝัง secret, password, API key ใน source code หรือ config file",
     "ป้องกัน credential exposure ใน version control และ log files",
     "ใช้ HashiCorp Vault หรือ Kubernetes Secrets เท่านั้น, บังคับ secret rotation ทุก 90 วัน",
     "Active", "1.1", "Platform Team"),

    ("STD-SEC-004", "Security",
     "Vulnerability Management & Patching",
     "ทุก system ต้อง patch security vulnerability ภายใน SLA: Critical=24h, High=7d, Medium=30d",
     "ลดช่วงเวลาที่ระบบเปิดรับการโจมตีจาก known CVEs",
     "ใช้ automated scanning ทุก sprint, ต้อง sign-off จาก CISO ก่อน deploy ถ้ามี unpatched Critical",
     "Active", "1.0", "CISO Office"),

    # ── API & Integration ────────────────────────────────────────────────────────
    ("STD-API-001", "API",
     "RESTful API Design Standard",
     "API ใหม่ทุกตัวต้องออกแบบตาม REST principles พร้อม OpenAPI 3.0 spec",
     "สร้าง consistency ของ developer experience และลดเวลา integration",
     "ใช้ noun-based resource URL, HTTP verbs, versioning (/v1/), pagination, error format RFC7807",
     "Active", "2.0", "Platform Team"),

    ("STD-API-002", "API",
     "API Gateway Mandatory Routing",
     "ทุก external API call ต้องผ่าน API Gateway — ห้าม expose service โดยตรงสู่ internet",
     "Central point สำหรับ auth, rate-limit, logging, และ circuit breaker",
     "ใช้ Kong Gateway เป็น standard, กำหนด rate limit ตาม consumer tier",
     "Active", "1.0", "Platform Team"),

    ("STD-API-003", "API",
     "Async-First Event Architecture",
     "การ communicate ระหว่าง microservices ที่ไม่ต้องการ immediate response ให้ใช้ async messaging",
     "ลด coupling, เพิ่ม resilience, รองรับ high-throughput",
     "ใช้ Apache Kafka เป็น standard message broker, กำหนด schema ด้วย Avro/JSON Schema",
     "Active", "1.0", "Architecture Team"),

    # ── Data ────────────────────────────────────────────────────────────────────
    ("STD-DAT-001", "Data",
     "Data Classification & Handling Policy",
     "ข้อมูลทุกชุดต้องมี classification: Public / Internal / Confidential / Restricted",
     "กำหนดมาตรการป้องกันที่เหมาะสมกับความสำคัญของข้อมูล",
     "Restricted = encrypt + audit log + MFA, ห้ามเก็บใน local storage / personal device",
     "Active", "1.3", "Data Office"),

    ("STD-DAT-002", "Data",
     "Master Data Management Standard",
     "ข้อมูล master (Customer, Product, Employee) ต้องมี single source of truth และใช้ MDM system",
     "ป้องกัน data inconsistency ข้ามระบบและลด data reconciliation effort",
     "ห้าม duplicate master data ใน application DB, ต้อง subscribe จาก MDM API เท่านั้น",
     "Active", "1.0", "Data Office"),

    ("STD-DAT-003", "Data",
     "PII Data Minimization",
     "เก็บ PII เฉพาะที่จำเป็นตามวัตถุประสงค์ที่ระบุ, ลบเมื่อพ้นระยะเวลาที่กำหนด",
     "ปฏิบัติตาม PDPA และลด liability จากการรั่วไหลของข้อมูลส่วนบุคคล",
     "ทำ PII inventory ทุก 6 เดือน, บังคับ data retention policy, anonymize ใน non-prod",
     "Active", "1.0", "Data Office"),

    ("STD-DAT-004", "Data",
     "Data Quality Framework",
     "ข้อมูลที่ใช้ใน decision-making ต้องผ่าน quality gate: Completeness, Accuracy, Timeliness",
     "ข้อมูลไม่ดีนำไปสู่การตัดสินใจผิดพลาด — quality เป็น enabler ของ analytics",
     "กำหนด DQ metrics per domain, monitor ด้วย automated pipeline, escalate เมื่อต่ำกว่า threshold",
     "Active", "1.1", "Data Office"),

    # ── Platform & Infrastructure ────────────────────────────────────────────────
    ("STD-PLT-001", "Platform",
     "Container-First Deployment",
     "Application ใหม่ทุกตัวต้อง containerize ด้วย Docker และ deploy บน Kubernetes",
     "สร้าง consistency ของ deployment, เพิ่ม portability, รองรับ auto-scaling",
     "Base image ต้องผ่าน security scan, ห้ามใช้ root user ใน container, กำหนด resource limits",
     "Active", "2.0", "Platform Team"),

    ("STD-PLT-002", "Platform",
     "Infrastructure as Code (IaC)",
     "ทุก infrastructure provisioning ต้องทำผ่าน code (Terraform) — ห้าม manual provisioning",
     "สร้าง reproducibility, auditability, และลด configuration drift",
     "ใช้ Terraform + GitOps workflow, state ต้องเก็บใน remote backend (S3/GCS), peer review บังคับ",
     "Active", "1.0", "Platform Team"),

    ("STD-PLT-003", "Platform",
     "High Availability Design Requirement",
     "ระบบ Tier 1 ต้องออกแบบให้ HA ด้วย minimum 99.9% uptime SLA",
     "ป้องกัน single point of failure และรองรับ business continuity",
     "ต้อง multi-AZ, active-active หรือ active-passive failover, DR test ทุก 6 เดือน",
     "Active", "1.0", "Architecture Team"),

    ("STD-PLT-004", "Platform",
     "Observability Standard (Logs, Metrics, Traces)",
     "ทุก service ต้อง instrument ด้วย structured logging, metrics export, และ distributed tracing",
     "ลดเวลา MTTR, เพิ่ม visibility ของ system behavior",
     "Log format: JSON structured, Metrics: Prometheus, Tracing: OpenTelemetry, Retention: 90 วัน",
     "Active", "1.0", "Platform Team"),

    # ── Application ──────────────────────────────────────────────────────────────
    ("STD-APP-001", "Application",
     "Clean Architecture & Separation of Concerns",
     "Application ต้องแยก business logic, data access, และ presentation layer ชัดเจน",
     "เพิ่ม testability, maintainability, และลด technical debt",
     "ใช้ layered architecture หรือ hexagonal architecture, ห้าม business logic ใน UI layer",
     "Active", "1.0", "Architecture Team"),

    ("STD-APP-002", "Application",
     "API-First Development",
     "ออกแบบ API contract ก่อน implement — Frontend และ Backend develop parallel ได้",
     "ลด dependency และเพิ่ม development velocity",
     "ใช้ OpenAPI spec เป็น contract, mock server ระหว่าง development, contract test บังคับ",
     "Active", "1.0", "Architecture Team"),

    ("STD-APP-003", "Application",
     "Automated Testing Requirement",
     "ทุก service ต้องมี unit test coverage ≥ 80% และ integration test ก่อน merge to main",
     "ลด regression bug และเพิ่ม confidence ในการ deploy",
     "บังคับ CI gate: unit test + lint + security scan, E2E test สำหรับ critical user journey",
     "Active", "1.1", "Architecture Team"),

    ("STD-APP-004", "Application",
     "12-Factor Application Design",
     "Application ต้องปฏิบัติตาม 12-factor principles โดยเฉพาะ: Config via env, Stateless process",
     "เพิ่ม scalability, portability, และความง่ายในการ operate",
     "ห้าม hardcode config, ต้อง health check endpoint, graceful shutdown, horizontal scalable",
     "Active", "1.0", "Platform Team"),

    # ── Integration ──────────────────────────────────────────────────────────────
    ("STD-INT-001", "Integration",
     "Service Mesh for East-West Traffic",
     "การ communicate ระหว่าง microservices ใน cluster ต้องผ่าน service mesh (Istio)",
     "mTLS สำหรับ service-to-service, built-in observability, traffic management",
     "กำหนด DestinationRule และ VirtualService ทุก service, ใช้ circuit breaker pattern",
     "Active", "1.0", "Platform Team"),

    ("STD-INT-002", "Integration",
     "Legacy System Integration via Anti-Corruption Layer",
     "การ integrate กับ legacy system ต้องใช้ Anti-Corruption Layer (ACL) แยก domain model",
     "ป้องกัน legacy complexity ซึม penetrate เข้า new system",
     "ออกแบบ adapter/facade pattern, กำหนด contract ที่ new system owns, monitor legacy SLA",
     "Active", "1.0", "Architecture Team"),

    # ── Cloud ────────────────────────────────────────────────────────────────────
    ("STD-CLD-001", "Platform",
     "Cloud Cost Governance",
     "ทุก cloud resource ต้องมี tag: owner, project, environment, cost-center",
     "Enable cost attribution, anomaly detection, และ chargeback",
     "บังคับ tag policy ใน IAM, monthly cost review, auto-shutdown non-prod ช่วง weekend",
     "Active", "1.0", "Cloud Team"),

    ("STD-CLD-002", "Platform",
     "Cloud-Native Security Baseline",
     "ทุก cloud workload ต้องผ่าน CIS Benchmark และ Cloud Security Posture Management scan",
     "ป้องกัน misconfiguration ซึ่งเป็นสาเหตุหลักของ cloud breach",
     "ใช้ AWS Security Hub / Azure Security Center, remediate High+ findings ภายใน 7 วัน",
     "Active", "1.0", "CISO Office"),

    # ── Governance ───────────────────────────────────────────────────────────────
    ("STD-GOV-001", "Application",
     "Architecture Decision Record (ADR)",
     "ทุก significant architecture decision ต้องบันทึกเป็น ADR ใน repository",
     "สร้าง institutional memory, ป้องกันการตัดสินใจซ้ำ, และ onboard คนใหม่ได้เร็ว",
     "Format: Context / Decision / Consequences, เก็บใน /docs/adr/, review ใน ARB",
     "Active", "1.0", "Architecture Team"),

    ("STD-GOV-002", "Application",
     "Technology Lifecycle Management",
     "ทุก technology ต้องมี lifecycle plan: adoption → mainstream → deprecated → retired",
     "ป้องกัน tech debt สะสมจาก EOL technology ที่ไม่ได้ plan migration",
     "ทบทวน Tech Radar ทุก quarter, กำหนด migration plan ≥ 12 เดือนก่อน EOL",
     "Active", "1.0", "Architecture Team"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# 2. RELATIONSHIPS (repo_links)
# (src_type, src_id, dst_type, dst_id, link_type, strength, note)
# ═══════════════════════════════════════════════════════════════════════════════
APP_CAPABILITY_LINKS = [
    # APP-001 SAP S/4HANA → Finance + Supply Chain capabilities
    ("Application","APP-001","BusinessCapability","BCAP-007","Supports","Primary","SAP S/4HANA รองรับ Financial Planning"),
    ("Application","APP-001","BusinessCapability","BCAP-008","Supports","Primary","SAP S/4HANA รองรับ Revenue Management"),
    ("Application","APP-001","BusinessCapability","BCAP-009","Supports","Primary","SAP รองรับ Cost Management"),
    ("Application","APP-001","BusinessCapability","BCAP-010","Supports","Primary","SAP Financial Reporting"),
    ("Application","APP-001","BusinessCapability","BCAP-024","Supports","Primary","SAP รองรับ Procurement"),
    # APP-002 Salesforce CRM → Customer capabilities
    ("Application","APP-002","BusinessCapability","BCAP-001","Supports","Primary","Salesforce รองรับ Customer Acquisition"),
    ("Application","APP-002","BusinessCapability","BCAP-003","Supports","Primary","Salesforce CRM รองรับ Customer Service"),
    ("Application","APP-002","BusinessCapability","BCAP-006","Supports","Primary","Salesforce — CRM & Relationship core"),
    ("Application","APP-002","BusinessCapability","BCAP-005","Supports","Secondary","Salesforce Analytics"),
    # APP-004 HR WorkDay → HR capabilities
    ("Application","APP-004","BusinessCapability","BCAP-013","Supports","Primary","WorkDay รองรับ Talent Acquisition"),
    ("Application","APP-004","BusinessCapability","BCAP-014","Supports","Primary","WorkDay — Employee Lifecycle"),
    ("Application","APP-004","BusinessCapability","BCAP-015","Supports","Primary","WorkDay Performance Management"),
    # APP-005 AI Analytics Hub → Analytics
    ("Application","APP-005","BusinessCapability","BCAP-005","Supports","Primary","AI Analytics Hub — Customer Analytics"),
    ("Application","APP-005","BusinessCapability","BCAP-038","Supports","Primary","AI Analytics — Advanced Analytics"),
    # APP-010 Customer Portal → Customer capabilities
    ("Application","APP-010","BusinessCapability","BCAP-002","Supports","Primary","Customer Portal — Onboarding"),
    ("Application","APP-010","BusinessCapability","BCAP-003","Supports","Primary","Customer Portal — Customer Service"),
    ("Application","APP-010","BusinessCapability","BCAP-004","Supports","Secondary","Customer Portal ช่วย Retention"),
    # APP-015 Treasury System → Finance
    ("Application","APP-015","BusinessCapability","BCAP-011","Supports","Primary","Treasury System — Cash Management"),
    ("Application","APP-015","BusinessCapability","BCAP-010","Supports","Secondary","Treasury Financial Reporting"),
    # APP-017 ITSM ServiceNow → IT capabilities
    ("Application","APP-017","BusinessCapability","BCAP-036","Supports","Primary","ServiceNow — IT Service Management"),
    ("Application","APP-017","BusinessCapability","BCAP-003","Supports","Secondary","ServiceNow — Customer Service"),
    # APP-022 e-Commerce → Customer + Finance
    ("Application","APP-022","BusinessCapability","BCAP-001","Supports","Primary","e-Commerce — Customer Acquisition"),
    ("Application","APP-022","BusinessCapability","BCAP-008","Supports","Primary","e-Commerce — Revenue Management"),
    ("Application","APP-022","BusinessCapability","BCAP-004","Supports","Primary","e-Commerce — Retention"),
    # APP-023 Risk Mgmt System
    ("Application","APP-023","BusinessCapability","BCAP-032","Supports","Primary","Risk Mgmt — Risk & Compliance"),
    # APP-030 Procurement Ariba
    ("Application","APP-030","BusinessCapability","BCAP-024","Supports","Primary","Ariba — Procurement Management"),
    ("Application","APP-030","BusinessCapability","BCAP-025","Supports","Secondary","Ariba — Vendor Management"),
]

APP_DATADOMAIN_LINKS = [
    ("Application","APP-001","DataDomain","DDOM-008","Produces","Primary","SAP S/4HANA produces Financial Transactions"),
    ("Application","APP-001","DataDomain","DDOM-010","Produces","Primary","SAP produces Procurement Transactions"),
    ("Application","APP-001","DataDomain","DDOM-005","Consumes","Primary","SAP consumes Chart of Accounts"),
    ("Application","APP-002","DataDomain","DDOM-001","Consumes","Primary","Salesforce consumes Customer Master"),
    ("Application","APP-002","DataDomain","DDOM-007","Produces","Primary","Salesforce produces Sales & Order Data"),
    ("Application","APP-002","DataDomain","DDOM-013","Produces","Secondary","Salesforce produces Customer Intelligence"),
    ("Application","APP-004","DataDomain","DDOM-003","Produces","Primary","WorkDay produces Employee Master"),
    ("Application","APP-004","DataDomain","DDOM-009","Produces","Primary","WorkDay produces HR Transactions"),
    ("Application","APP-005","DataDomain","DDOM-013","Consumes","Primary","AI Analytics consumes Customer Intelligence"),
    ("Application","APP-005","DataDomain","DDOM-017","Produces","Primary","AI Analytics produces BI Mart"),
    ("Application","APP-008","DataDomain","DDOM-017","Produces","Primary","Data Warehouse produces BI Mart"),
    ("Application","APP-008","DataDomain","DDOM-014","Produces","Primary","Data Warehouse produces Financial Analytics"),
    ("Application","APP-008","DataDomain","DDOM-015","Produces","Primary","Data Warehouse produces Operational KPIs"),
    ("Application","APP-010","DataDomain","DDOM-001","Consumes","Primary","Customer Portal consumes Customer Master"),
    ("Application","APP-010","DataDomain","DDOM-012","Produces","Primary","Customer Portal produces Digital Activity"),
    ("Application","APP-013","DataDomain","DDOM-017","Consumes","Primary","Power BI consumes BI Mart"),
    ("Application","APP-013","DataDomain","DDOM-014","Consumes","Primary","Power BI consumes Financial Analytics"),
    ("Application","APP-015","DataDomain","DDOM-008","Consumes","Primary","Treasury consumes Financial Transactions"),
    ("Application","APP-015","DataDomain","DDOM-018","Consumes","Primary","Treasury consumes Currency Rates"),
    ("Application","APP-016","DataDomain","DDOM-001","Consumes","Primary","Identity Platform consumes Customer Master"),
    ("Application","APP-016","DataDomain","DDOM-003","Consumes","Primary","Identity Platform consumes Employee Master"),
    ("Application","APP-019","DataDomain","DDOM-023","Produces","Primary","Document Mgmt produces App Logs"),
    ("Application","APP-020","DataDomain","DDOM-026","Produces","Primary","API Gateway produces API & Integration Data"),
    ("Application","APP-022","DataDomain","DDOM-001","Consumes","Primary","e-Commerce consumes Customer Master"),
    ("Application","APP-022","DataDomain","DDOM-002","Consumes","Primary","e-Commerce consumes Product Master"),
    ("Application","APP-022","DataDomain","DDOM-007","Produces","Primary","e-Commerce produces Sales & Order Data"),
    ("Application","APP-023","DataDomain","DDOM-016","Produces","Primary","Risk Mgmt produces Risk & Fraud Analytics"),
    ("Application","APP-030","DataDomain","DDOM-004","Consumes","Primary","Procurement consumes Vendor & Partner Master"),
    ("Application","APP-030","DataDomain","DDOM-010","Produces","Primary","Procurement produces Procurement Transactions"),
]

APP_ABB_LINKS = [
    # Identity & Access
    ("Application","APP-016","ABB","ABB-001","Implements","Primary","Identity Platform implements IAM"),
    ("Application","APP-016","ABB","ABB-003","Implements","Primary","Identity Platform implements MFA"),
    ("Application","APP-016","ABB","ABB-004","Implements","Primary","Identity Platform implements SSO"),
    ("Application","APP-010","ABB","ABB-004","Consumes","Primary","Customer Portal consumes SSO"),
    ("Application","APP-002","ABB","ABB-004","Consumes","Primary","Salesforce consumes SSO"),
    ("Application","APP-004","ABB","ABB-004","Consumes","Primary","WorkDay consumes SSO"),
    # API Gateway
    ("Application","APP-020","ABB","ABB-016","Implements","Primary","API Gateway implements API Management ABB"),
    ("Application","APP-007","ABB","ABB-021","Implements","Primary","K8s Platform implements Container Orchestration"),
    # Security
    ("Application","APP-023","ABB","ABB-025","Implements","Primary","Risk Mgmt implements SIEM/Analytics"),
    ("Application","APP-005","ABB","ABB-025","Consumes","Secondary","AI Analytics Hub consumes Security Events"),
]

STANDARD_APP_LINKS = []  # will be populated dynamically

ARB_APP_LINKS = []  # will be populated from arb data

# ═══════════════════════════════════════════════════════════════════════════════
def seed():
    ts = now()

    # ── connect ──────────────────────────────────────────────────────────────
    ea  = sqlite3.connect(EA_DB);  ea.row_factory  = sqlite3.Row
    app = sqlite3.connect(APP_DB); app.row_factory = sqlite3.Row
    esa = sqlite3.connect(ESA_DB); esa.row_factory = sqlite3.Row

    # ── load lookup maps ─────────────────────────────────────────────────────
    bcap_ids = {r["id"] for r in ea.execute("SELECT id FROM bcap").fetchall()}
    ddom_ids = {r["id"] for r in ea.execute("SELECT id FROM ddomain").fetchall()}
    tech_ids = {r["name"]: r["id"] for r in ea.execute("SELECT id,name FROM tech_catalog").fetchall()}
    abb_ids  = {r["id"] for r in esa.execute("SELECT id FROM abb").fetchall()}
    app_ids  = {r["id"] for r in app.execute("SELECT id FROM applications").fetchall()}
    arb_reqs = app.execute("SELECT id, title FROM arb_requests WHERE status='Decision Issued'").fetchall()
    arb_apps = {}
    for req in arb_reqs:
        rows = app.execute("SELECT application_id FROM arb_request_applications WHERE arb_request_id=?", (req["id"],)).fetchall()
        arb_apps[req["id"]] = [r["application_id"] for r in rows]

    print(f"Loaded: {len(bcap_ids)} capabilities, {len(ddom_ids)} data domains, "
          f"{len(tech_ids)} tech, {len(abb_ids)} ABBs, {len(app_ids)} apps, {len(arb_reqs)} ARB decisions")

    # ════════════════════════════════════════════════════════════════════════
    # SEED repo_standards
    # ════════════════════════════════════════════════════════════════════════
    print("\n── Seeding repo_standards ──")
    std_id_map = {}  # code → id
    std_count = 0
    for code, cat, title, desc, rat, guide, status, ver, owner in STANDARDS:
        existing = ea.execute("SELECT id FROM repo_standards WHERE code=?", (code,)).fetchone()
        if existing:
            std_id_map[code] = existing["id"]
            continue
        sid = uid("STD")
        std_id_map[code] = sid
        ea.execute("""INSERT INTO repo_standards
            (id,code,category,title,description,rationale,guidance,status,version,owner,
             effective_date,review_date,tags,created_by,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, code, cat, title, desc, rat, guide, status, ver, owner,
             "2025-01-01", "2026-12-31", "[]", "seed", ts, ts))
        std_count += 1
    ea.commit()
    print(f"  → {std_count} standards inserted")

    # ════════════════════════════════════════════════════════════════════════
    # SEED repo_links
    # ════════════════════════════════════════════════════════════════════════
    print("\n── Seeding repo_links ──")
    link_count = 0

    def insert_link(src_type, src_id, dst_type, dst_id, link_type, strength, note):
        nonlocal link_count
        try:
            lid = uid("RL")
            ea.execute("""INSERT INTO repo_links
                (id,src_type,src_id,dst_type,dst_id,link_type,strength,note,created_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (lid, src_type, src_id, dst_type, dst_id, link_type, strength, note, "seed", ts, ts))
            link_count += 1
        except Exception as e:
            if "UNIQUE" not in str(e):
                print(f"    WARN: {e}")

    # App → BusinessCapability
    print("  App → BusinessCapability ...")
    for row in APP_CAPABILITY_LINKS:
        src_type, src_id, dst_type, dst_id, lt, strength, note = row
        if src_id not in app_ids: continue
        if dst_id not in bcap_ids: continue
        insert_link(src_type, src_id, dst_type, dst_id, lt, strength, note)

    # App → DataDomain
    print("  App → DataDomain ...")
    for row in APP_DATADOMAIN_LINKS:
        src_type, src_id, dst_type, dst_id, lt, strength, note = row
        if src_id not in app_ids: continue
        if dst_id not in ddom_ids: continue
        insert_link(src_type, src_id, dst_type, dst_id, lt, strength, note)

    # App → ABB
    print("  App → ABB ...")
    for row in APP_ABB_LINKS:
        src_type, src_id, dst_type, dst_id, lt, strength, note = row
        if src_id not in app_ids: continue
        if dst_id not in abb_ids: continue
        insert_link(src_type, src_id, dst_type, dst_id, lt, strength, note)

    # App → TechnologyProduct (from tech_usage in ea_domains.db)
    print("  App → TechnologyProduct (from tech_usage) ...")
    usage_rows = ea.execute("""
        SELECT DISTINCT tu.app_id, tu.tech_id
        FROM tech_usage tu
        WHERE tu.usage_target_type='App' AND tu.app_id IS NOT NULL AND tu.tech_id IS NOT NULL
    """).fetchall()
    for r in usage_rows:
        if r["app_id"] not in app_ids: continue
        insert_link("Application", r["app_id"], "TechnologyProduct", r["tech_id"],
                    "Implements", "Primary", "derived from tech_usage")

    # Standard → Application (Governs)
    print("  Standard → Application (Governs) ...")
    STD_APP_GOV = [
        ("STD-SEC-001", ["APP-010","APP-016","APP-020","APP-022","APP-005"]),
        ("STD-SEC-002", ["APP-001","APP-004","APP-015","APP-023","APP-010"]),
        ("STD-SEC-003", ["APP-007","APP-012","APP-005","APP-018","APP-016"]),
        ("STD-API-001", ["APP-010","APP-020","APP-016","APP-022","APP-005"]),
        ("STD-API-002", ["APP-010","APP-022","APP-016","APP-005","APP-018"]),
        ("STD-API-003", ["APP-018","APP-005","APP-008","APP-010","APP-022"]),
        ("STD-DAT-001", ["APP-001","APP-004","APP-008","APP-010","APP-022","APP-013"]),
        ("STD-DAT-002", ["APP-001","APP-004","APP-010","APP-022"]),
        ("STD-DAT-003", ["APP-010","APP-002","APP-004","APP-022"]),
        ("STD-PLT-001", ["APP-005","APP-007","APP-010","APP-016","APP-018","APP-020","APP-022"]),
        ("STD-PLT-002", ["APP-007","APP-012","APP-016","APP-020"]),
        ("STD-APP-003", ["APP-005","APP-010","APP-016","APP-018","APP-020","APP-022"]),
        ("STD-GOV-001", ["APP-005","APP-010","APP-016","APP-020","APP-022","APP-007"]),
        ("STD-GOV-002", ["APP-003","APP-006","APP-011","APP-014","APP-021","APP-025","APP-028"]),
        ("STD-SEC-004", ["APP-007","APP-016","APP-010","APP-020","APP-022"]),
    ]
    for code, app_list in STD_APP_GOV:
        std_id = std_id_map.get(code)
        if not std_id: continue
        for app_id in app_list:
            if app_id not in app_ids: continue
            insert_link("ArchitectureStandard", std_id, "Application", app_id,
                        "Governs", "Primary", f"{code} governs {app_id}")

    # ARB Decision → Application (Governs)
    print("  ARBDecision → Application ...")
    for req in arb_reqs:
        for app_id in arb_apps.get(req["id"], []):
            if app_id not in app_ids: continue
            insert_link("ARBDecision", req["id"], "Application", app_id,
                        "Governs", "Primary", f"ARB decision for {app_id}")

    ea.commit()
    print(f"  → {link_count} links inserted")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n=== SEED REPO COMPLETE ===")
    std_total  = ea.execute("SELECT COUNT(*) FROM repo_standards").fetchone()[0]
    link_total = ea.execute("SELECT COUNT(*) FROM repo_links").fetchone()[0]
    print(f"  repo_standards : {std_total} rows")
    print(f"  repo_links     : {link_total} rows")

    # breakdown by link type
    for row in ea.execute("SELECT src_type, dst_type, COUNT(*) as cnt FROM repo_links GROUP BY src_type,dst_type ORDER BY cnt DESC").fetchall():
        print(f"    ↳ {row['src_type']} → {row['dst_type']}: {row['cnt']}")

    ea.close(); app.close(); esa.close()

if __name__ == "__main__":
    seed()
