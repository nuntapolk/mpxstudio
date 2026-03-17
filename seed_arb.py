"""
seed_arb.py — Seed 50 ARB Lite requests linked to real app/project/roadmap data
Run: python3 seed_arb.py
"""

import sqlite3, time, uuid, random
from datetime import datetime, timedelta

DB_PATH = "appport.db"

# ─── Load real data ────────────────────────────────────────────────────────────
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

APPS    = conn.execute("SELECT id, name, domain, criticality, status, owner, biz_owner FROM applications").fetchall()
PROJS   = conn.execute("SELECT id, name, type, status, pm, sponsor FROM projects").fetchall()
ROADS   = conn.execute("SELECT id, app_id, title, lane, owner FROM roadmap_items").fetchall()

conn.close()

APP_MAP  = {a["id"]: dict(a) for a in APPS}
PROJ_MAP = {p["id"]: dict(p) for p in PROJS}
ROAD_MAP = {r["id"]: dict(r) for r in ROADS}

# ─── Helpers ───────────────────────────────────────────────────────────────────
REVIEWERS = [
    ("eaa",        "EAA"),
    ("eta",        "ETA"),
    ("eda",        "EDA"),
    ("eba",        "EBA"),
    ("esa",        "ESA"),
    ("ea_office",  "EA Office"),
    ("pmo",        "PMO"),
    ("arb_office", "ARB Secretariat"),
]

DOMAINS = ["Business","Data","Application","Technology","Security","Integration","Governance","General"]

FINDING_TEMPLATES = [
    ("Architecture", "Application",  "High",   "ขาด integration pattern มาตรฐาน",            "ให้ใช้ ESA Event-Driven Pattern"),
    ("Data",         "Data",         "Medium", "ไม่มี Data Lineage document",                 "จัดทำ Data Dictionary + Lineage"),
    ("Security",     "Security",     "Critical","PII ไม่ผ่าน PDPA encryption standard",       "Encrypt PII field ด้วย AES-256"),
    ("Technology",   "Technology",   "Medium", "Tech stack มี EOL ภายใน 12 เดือน",            "วางแผน Tech Refresh ก่อน EOL"),
    ("Architecture", "Integration",  "High",   "Missing API versioning strategy",             "กำหนด API Versioning policy"),
    ("Governance",   "General",      "Low",    "ไม่มี SLA definition ใน Service Agreement",   "เพิ่ม SLA clause ใน contract"),
    ("Architecture", "Application",  "Medium", "Single point of failure ใน critical path",   "เพิ่ม HA design"),
    ("Security",     "Security",     "High",   "ไม่มี WAF protection สำหรับ internet-facing", "Deploy WAF ก่อน go-live"),
    ("Data",         "Data",         "Medium", "ไม่มี Backup & Recovery test result",         "ทำ DR Drill และส่งผลทดสอบ"),
    ("Architecture", "Technology",   "Low",    "ขาด Architecture Decision Record (ADR)",      "จัดทำ ADR document"),
]

ACTION_TEMPLATES = [
    ("จัดทำ Architecture Decision Record",        "Condition",    "30 วัน"),
    ("ส่ง Data Flow Diagram ฉบับสมบูรณ์",          "Condition",    "14 วัน"),
    ("ทำ Security Penetration Test",               "Pre-requisite","45 วัน"),
    ("อัปเดต Interface Specification",             "Condition",    "21 วัน"),
    ("ยืนยัน SLA กับ vendor",                     "Follow-up",    "30 วัน"),
    ("จัดทำ DR Runbook และ test plan",             "Condition",    "60 วัน"),
    ("ส่ง PDPA Data Classification",              "Pre-requisite","14 วัน"),
    ("Update Technology Roadmap alignment",        "Follow-up",    "45 วัน"),
    ("จัดทำ Rollback Plan",                       "Pre-requisite","7 วัน"),
    ("ทำ Performance Benchmark test",             "Condition",    "30 วัน"),
]

COMMENT_TEMPLATES = [
    # (domain, comment_type, severity, comment_text)
    ("Business",     "Concern",    "Medium", "ควรมี Business Impact Assessment ที่ละเอียดกว่านี้"),
    ("Data",         "Question",   "Low",    "ขอ Data Dictionary สำหรับ entity หลักทั้งหมด"),
    ("Application",  "Suggestion", "Low",    "แนะนำให้ใช้ Microservices pattern แทน Monolith"),
    ("Technology",   "Concern",    "Medium", "Version ที่เลือกใกล้ EOL ภายใน 18 เดือน"),
    ("Security",     "Concern",    "High",   "ต้องผ่าน Security Assessment ก่อน go-live"),
    ("Integration",  "Question",   "Medium", "มี Error handling กรณี downstream service down หรือไม่?"),
    ("Governance",   "Suggestion", "Low",    "ควร align กับ Enterprise Architecture Principle #3"),
    ("General",      "Concern",    "Low",    "ขอ stakeholder sign-off จาก Business Owner"),
]

def rnd_date(base, min_days=7, max_days=90):
    return (base + timedelta(days=random.randint(min_days, max_days))).strftime("%Y-%m-%d")

def ago(days):
    return (datetime.now() - timedelta(days=days)).isoformat()

def future(days):
    return (datetime.now() + timedelta(days=days)).isoformat()

def arb_id_ts(offset_ms=0):
    return f"arb-{int(time.time()*1000) + offset_ms}"

# ─── 50 ARB Request Definitions ────────────────────────────────────────────────
# Each entry: (title, req_type, app_ids, project_id, roadmap_id, status, review_level, decision_type, created_daysago)
SEED_REQUESTS = [
    # ── Closed / Decision Issued (15) ──────────────────────────────────────────
    {
        "title": "Core Banking AS/400 Migration to Cloud Core",
        "request_type": "Migration",
        "apps": ["APP-003"],
        "project_id": "PRJ-001",
        "roadmap_id": "RM-0001",
        "biz_owner": "Wanchai S.",
        "requester": "pmo",
        "objective": "ย้าย Core Banking จาก AS/400 ไป Cloud-native เพื่อลด operational risk และ TCO",
        "summary": "Migration ระบบ Core Banking ที่อายุ 30+ ปี ไป modern cloud platform พร้อม parallel run 6 เดือน",
        "impact": {"business_impact":"Critical","data_impact":"High","application_impact":"Critical",
                   "technology_impact":"High","security_impact":"High","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Conditionally Approved", "Approved with mandatory security review", "High migration risk"),
        "created_daysago": 45,
        "reviewers": [("arb_office","ARB Secretariat"),("esa","ESA"),("eta","ETA")],
    },
    {
        "title": "SAP S/4HANA Finance Module Upgrade to 2023",
        "request_type": "Upgrade",
        "apps": ["APP-001"],
        "project_id": "PRJ-012",
        "roadmap_id": None,
        "biz_owner": "Somchai K.",
        "requester": "ea_office",
        "objective": "Upgrade SAP S/4HANA ให้ตรง Maintenance Stack และรองรับ IFRS17",
        "summary": "In-place upgrade SAP S/4HANA ECC→2023 FPS03 พร้อม custom code remediation 450 objects",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"High","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Architecture aligns with EAA standard", "Minimal risk"),
        "created_daysago": 60,
        "reviewers": [("eaa","EAA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Zero-Trust Security Platform Implementation",
        "request_type": "New Project",
        "apps": ["APP-016","APP-032","APP-065"],
        "project_id": "PRJ-008",
        "roadmap_id": None,
        "biz_owner": "Kanchana R.",
        "requester": "esa",
        "objective": "Implement Zero-Trust Network Access แทน VPN-based model เพื่อเพิ่ม security posture",
        "summary": "Deploy ZTNA platform ครอบคลุม identity, device trust, network segmentation และ continuous monitoring",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Critical","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":True,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Conditionally Approved", "Approved pending DR test completion", "Network disruption risk"),
        "created_daysago": 30,
        "reviewers": [("esa","ESA"),("eta","ETA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Customer Data Platform (CDP) Deployment",
        "request_type": "New Project",
        "apps": ["APP-043","APP-002"],
        "project_id": "PRJ-011",
        "roadmap_id": None,
        "biz_owner": "Worapon S.",
        "requester": "eba",
        "objective": "รวม Customer Data จากทุก touchpoint เป็น Single Customer View เพื่อ personalization",
        "summary": "Deploy CDP platform ดึงข้อมูลจาก CRM, e-Commerce, Contact Center มารวมใน unified profile",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"High","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Conditionally Approved", "Approved with PDPA compliance plan", "PII risk"),
        "created_daysago": 50,
        "reviewers": [("eda","EDA"),("esa","ESA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Legacy ERP Oracle Phase-out & Data Archive",
        "request_type": "Retirement",
        "apps": ["APP-006"],
        "project_id": "PRJ-009",
        "roadmap_id": None,
        "biz_owner": "Amorn C.",
        "requester": "ea_office",
        "objective": "Decommission Legacy ERP Oracle หลัง SAP S/4HANA cutover เสร็จสมบูรณ์",
        "summary": "Archive 15 ปีของข้อมูล Finance/Procurement ไป Data Vault และ shutdown Oracle EBS R12",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Medium","integration_impact":"Medium",
                   "compliance_impact":"High","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":True},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Retirement plan complete and validated", "Data retention verified"),
        "created_daysago": 90,
        "reviewers": [("eda","EDA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "e-Commerce Platform Payment Gateway Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-022","APP-087"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Varunya C.",
        "requester": "eaa",
        "objective": "Upgrade Payment Gateway เป็น PCI-DSS v4.0 compliant ก่อน deadline มีนาคม 2026",
        "summary": "Replace Cybersource integration ด้วย version ใหม่ที่รองรับ 3DS2 และ open banking",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"Medium","security_impact":"High","integration_impact":"High",
                   "compliance_impact":"Critical","has_pii":True,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Compliant with PCI-DSS v4.0 requirements", "No major risks"),
        "created_daysago": 35,
        "reviewers": [("esa","ESA"),("eaa","EAA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "MuleSoft API Gateway Consolidation",
        "request_type": "Modernization",
        "apps": ["APP-094","APP-082"],
        "project_id": "PRJ-015",
        "roadmap_id": "RM-0002",
        "biz_owner": "Nuttapon T.",
        "requester": "eaa",
        "objective": "Consolidate 3 API gateway instances เป็น single MuleSoft Anypoint Platform",
        "summary": "Migrate existing REST/SOAP APIs จาก IBM DataPower และ Axway ไป MuleSoft พร้อม API versioning",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"Critical",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Conditionally Approved", "Approved with rollback plan", "Migration complexity"),
        "created_daysago": 25,
        "reviewers": [("eta","ETA"),("eaa","EAA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "AI/ML Platform Buildout - Databricks Lakehouse",
        "request_type": "New Project",
        "apps": ["APP-096","APP-007"],
        "project_id": "PRJ-007",
        "roadmap_id": None,
        "biz_owner": "Thanakrit W.",
        "requester": "eda",
        "objective": "สร้าง Enterprise AI/ML Platform บน Databricks เพื่อรองรับ Analytics และ GenAI use cases",
        "summary": "Deploy Databricks Lakehouse architecture รวม Data Ingestion, Feature Store, MLflow model registry",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Strong business value, architecture approved", "Governance model needed"),
        "created_daysago": 40,
        "reviewers": [("eda","EDA"),("eta","ETA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "DevSecOps Pipeline - GitLab CI/CD",
        "request_type": "New Project",
        "apps": ["APP-098"],
        "project_id": "PRJ-010",
        "roadmap_id": None,
        "biz_owner": "Nuttapon T.",
        "requester": "eta",
        "objective": "Standardize CI/CD pipeline ทุก project บน GitLab DevSecOps พร้อม SAST/DAST integration",
        "summary": "Deploy GitLab Enterprise + SonarQube + Trivy สำหรับ automated security scanning ใน pipeline",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"High","integration_impact":"Medium",
                   "compliance_impact":"Medium","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Desk Review",
        "decision": ("Approved", "Approved, aligns with DevSecOps strategy", "None"),
        "created_daysago": 20,
        "reviewers": [("eta","ETA"),("esa","ESA")],
    },
    {
        "title": "PDPA Compliance Remediation - PII Data Masking",
        "request_type": "Compliance",
        "apps": ["APP-002","APP-043","APP-022"],
        "project_id": "PRJ-014",
        "roadmap_id": None,
        "biz_owner": "Thida K.",
        "requester": "esa",
        "objective": "Implement PII data masking และ consent management ให้ครบตาม PDPA requirement",
        "summary": "Deploy Informatica CDGC สำหรับ data classification + masking ใน non-prod environments",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"High","integration_impact":"Medium",
                   "compliance_impact":"Critical","has_pii":True,"internet_facing":False,
                   "new_integration":False,"new_vendor":True,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Mandatory compliance, fully approved", "No risks"),
        "created_daysago": 15,
        "reviewers": [("esa","ESA"),("eda","EDA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Genesys Cloud CX Contact Center Migration",
        "request_type": "Migration",
        "apps": ["APP-085","APP-077"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Narong P.",
        "requester": "eaa",
        "objective": "Migrate On-premise Contact Center ไป Genesys Cloud CX SaaS พร้อม Omnichannel",
        "summary": "Migrate 500 agent seats + IVR flows + Verint Speech Analytics integration",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":True,"internet_facing":True,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Conditionally Approved", "Approved with network redundancy plan", "SLA dependency"),
        "created_daysago": 28,
        "reviewers": [("eaa","EAA"),("eta","ETA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Supply Chain SAP TM + EWM Integration",
        "request_type": "Integration",
        "apps": ["APP-009","APP-063","APP-089"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "eba",
        "objective": "Integrate SAP TM Transport Management กับ SAP EWM Warehouse ผ่าน iDoc",
        "summary": "Real-time integration ระหว่าง Transport Planning และ Warehouse Execution ลด manual handoff",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Desk Review",
        "decision": ("Approved", "Standard SAP integration pattern, approved", "None"),
        "created_daysago": 22,
        "reviewers": [("eaa","EAA"),("eba","EBA")],
    },
    {
        "title": "SAS Risk Engine Model Refresh",
        "request_type": "Upgrade",
        "apps": ["APP-088"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Charoenporn V.",
        "requester": "eda",
        "objective": "Refresh Credit Risk Model ใน SAS ให้ตรงกับ Basel IV requirement",
        "summary": "Retrain SAS risk models ด้วย 3-year data, update scorecard, ผ่าน Model Validation Committee",
        "impact": {"business_impact":"Critical","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Critical","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Model validated and approved by Risk Committee", "None"),
        "created_daysago": 55,
        "reviewers": [("eda","EDA"),("eba","EBA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "MES Factory v1 Phase-out",
        "request_type": "Retirement",
        "apps": ["APP-014"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Patipan W.",
        "requester": "eta",
        "objective": "Decommission MES Factory v1 หลัง MES v2 cutover เสร็จสิ้น",
        "summary": "Shutdown MES Factory v1 พร้อม Archive 8 ปีของ Production data ไป Cold Storage",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Medium","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":True},
        "status": "Decision Issued",
        "review_level": "Desk Review",
        "decision": ("Approved", "Retirement validated, data archived", "None"),
        "created_daysago": 70,
        "reviewers": [("eta","ETA"),("eba","EBA")],
    },
    {
        "title": "Hashicorp Vault Secrets Management Rollout",
        "request_type": "New Project",
        "apps": ["APP-090","APP-016"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Kanchana R.",
        "requester": "esa",
        "objective": "Centralize secrets management ด้วย Hashicorp Vault แทน hardcoded credentials",
        "summary": "Deploy Vault Enterprise cluster, onboard 50+ apps, automate secret rotation",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Critical","integration_impact":"High",
                   "compliance_impact":"High","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Decision Issued",
        "review_level": "Formal Review",
        "decision": ("Approved", "Critical security initiative, approved", "Rollout sequencing required"),
        "created_daysago": 18,
        "reviewers": [("esa","ESA"),("eta","ETA"),("arb_office","ARB Secretariat")],
    },

    # ── In Review (10) ─────────────────────────────────────────────────────────
    {
        "title": "ERP Cloud Migration - SAP Rise",
        "request_type": "Migration",
        "apps": ["APP-001","APP-006"],
        "project_id": "PRJ-002",
        "roadmap_id": "RM-0002",
        "biz_owner": "Nattaya P.",
        "requester": "pmo",
        "objective": "Migrate SAP ECC และ Legacy ERP ไป SAP S/4HANA Cloud (RISE with SAP)",
        "summary": "Full cloud migration SAP Basis + custom Z-objects 300+ programs",
        "impact": {"business_impact":"Critical","data_impact":"High","application_impact":"Critical",
                   "technology_impact":"High","security_impact":"High","integration_impact":"Critical",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 10,
        "reviewers": [("eaa","EAA"),("eda","EDA"),("eba","EBA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "New Customer Digital Portal",
        "request_type": "New Project",
        "apps": ["APP-010","APP-060"],
        "project_id": "PRJ-004",
        "roadmap_id": None,
        "biz_owner": "Worapon S.",
        "requester": "eaa",
        "objective": "สร้าง Customer Self-Service Portal ใหม่ที่รองรับ Omnichannel บน React + Headless CMS",
        "summary": "New portal ทดแทน legacy Java portal ด้วย React SPA + Adobe Experience Manager Headless",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":True,"internet_facing":True,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 8,
        "reviewers": [("eaa","EAA"),("esa","ESA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Data Warehouse Modernization - Databricks Delta",
        "request_type": "Modernization",
        "apps": ["APP-008","APP-096"],
        "project_id": "PRJ-005",
        "roadmap_id": None,
        "biz_owner": "Charoenporn V.",
        "requester": "eda",
        "objective": "Modernize Data Warehouse จาก Teradata ไป Databricks Delta Lakehouse",
        "summary": "Migrate 200TB+ data, rebuild 500+ ETL pipelines บน Spark/dbt",
        "impact": {"business_impact":"High","data_impact":"Critical","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 7,
        "reviewers": [("eda","EDA"),("eta","ETA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Fraud Detection AI Model Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-048","APP-005"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Kanchana R.",
        "requester": "esa",
        "objective": "Upgrade Fraud Detection Model ด้วย Real-time ML inference แทน Batch rule-based",
        "summary": "Deploy new XGBoost + Graph Neural Network model บน Kafka streaming pipeline",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"High",
                   "technology_impact":"High","security_impact":"High","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 6,
        "reviewers": [("esa","ESA"),("eda","EDA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Network Infrastructure Refresh - SD-WAN",
        "request_type": "Upgrade",
        "apps": ["APP-082","APP-084"],
        "project_id": "PRJ-013",
        "roadmap_id": None,
        "biz_owner": "Wichai B.",
        "requester": "eta",
        "objective": "Replace MPLS WAN ด้วย Cisco SD-WAN ทุก 45 สาขา",
        "summary": "Deploy Cisco Viptela SD-WAN รองรับ SaaS traffic steering + zero-touch provisioning",
        "impact": {"business_impact":"High","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":True,
                   "new_integration":False,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 5,
        "reviewers": [("eta","ETA"),("esa","ESA")],
    },
    {
        "title": "Gen-AI Copilot for EA Documentation",
        "request_type": "New Project",
        "apps": ["APP-050"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Thanakrit W.",
        "requester": "ea_office",
        "objective": "Deploy Gen-AI Copilot ช่วย EA Team สร้าง Architecture Document อัตโนมัติ",
        "summary": "LLM-based assistant integrate กับ MPX AppPort ดึง context จาก application inventory",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"High","integration_impact":"Medium",
                   "compliance_impact":"Medium","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 4,
        "reviewers": [("eaa","EAA"),("esa","ESA")],
    },
    {
        "title": "SAP Ariba Procurement Cloud Integration",
        "request_type": "Integration",
        "apps": ["APP-056","APP-030"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "eba",
        "objective": "Integrate SAP Ariba Cloud กับ SAP S/4HANA Finance ผ่าน SAP Integration Suite",
        "summary": "P2P integration: PO, GR, Invoice ระหว่าง Ariba Network กับ SAP Finance module",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":False,"internet_facing":True,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 3,
        "reviewers": [("eaa","EAA"),("eba","EBA")],
    },
    {
        "title": "Pega BPM Claims Process Automation",
        "request_type": "Upgrade",
        "apps": ["APP-055","APP-073"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "eaa",
        "objective": "Automate Insurance Claims process บน Pega BPM ลด manual work 60%",
        "summary": "Implement Pega Claims Processing workflow + AI decisioning + Guidewire integration",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 3,
        "reviewers": [("eaa","EAA"),("eba","EBA"),("esa","ESA")],
    },
    {
        "title": "Veeva Vault QMS Validation",
        "request_type": "Compliance",
        "apps": ["APP-064","APP-093"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Patipan W.",
        "requester": "eaa",
        "objective": "Computer System Validation ของ Veeva Vault CTMS สำหรับ GCP audit readiness",
        "summary": "Full IQ/OQ/PQ validation package + UAT + traceability matrix สำหรับ FDA 21 CFR Part 11",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Medium","integration_impact":"Low",
                   "compliance_impact":"Critical","has_pii":True,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 2,
        "reviewers": [("esa","ESA"),("arb_office","ARB Secretariat")],
    },
    {
        "title": "Kafka Event Bus Major Version Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-082"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Nuttapon T.",
        "requester": "eta",
        "objective": "Upgrade Kafka 2.x ไป 3.7 LTS เพื่อรองรับ KRaft mode (ไม่ต้องการ ZooKeeper)",
        "summary": "Rolling upgrade Kafka cluster 9 brokers + Schema Registry + Connect workers",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "In Review",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 2,
        "reviewers": [("eta","ETA"),("eaa","EAA")],
    },

    # ── Submitted (8) ──────────────────────────────────────────────────────────
    {
        "title": "Legacy HR System Retirement",
        "request_type": "Retirement",
        "apps": ["APP-004"],
        "project_id": "PRJ-003",
        "roadmap_id": "RM-0003",
        "biz_owner": "Wanchai S.",
        "requester": "pmo",
        "objective": "Decommission Legacy HR PeopleSoft หลัง SAP SuccessFactors go-live",
        "summary": "Archive 12 ปีของ HR data พร้อม shutdown infrastructure และ revoke licenses",
        "impact": {"business_impact":"Medium","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Medium","integration_impact":"Medium",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":True},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 2,
        "reviewers": [],
    },
    {
        "title": "Digital Twin Platform for Manufacturing",
        "request_type": "New Project",
        "apps": ["APP-100","APP-035"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Thanakrit W.",
        "requester": "eba",
        "objective": "สร้าง Digital Twin ของ Production line เพื่อ predictive maintenance",
        "summary": "IoT sensor integration + Azure Digital Twins + Power BI real-time dashboard",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 1,
        "reviewers": [],
    },
    {
        "title": "Mendix Low-Code Platform Expansion",
        "request_type": "Upgrade",
        "apps": ["APP-079"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Worapon S.",
        "requester": "eaa",
        "objective": "ขยาย Mendix License เป็น Enterprise tier รองรับ 20 citizen-developer apps",
        "summary": "License upgrade + security hardening + governance framework สำหรับ Low-Code apps",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Medium","integration_impact":"Low",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 1,
        "reviewers": [],
    },
    {
        "title": "SAP GRC Access Control Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-071"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Nuntachai P.",
        "requester": "esa",
        "objective": "Upgrade SAP GRC 12.0 เป็น 12.0 SP40 พร้อม Fiori UI integration",
        "summary": "In-place patch upgrade พร้อม SoD Ruleset update 2026 สำหรับ external audit",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"High","integration_impact":"Low",
                   "compliance_impact":"High","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 1,
        "reviewers": [],
    },
    {
        "title": "RPA Platform Scale-up - UiPath",
        "request_type": "Upgrade",
        "apps": ["APP-040"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Patipan W.",
        "requester": "eba",
        "objective": "Scale UiPath deployment จาก 10 เป็น 50 robots รองรับ Finance automation",
        "summary": "Add Orchestrator capacity + Document Understanding + AI Center modules",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Medium","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 1,
        "reviewers": [],
    },
    {
        "title": "Elastic Search Cluster Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-092"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Charoenporn V.",
        "requester": "eta",
        "objective": "Upgrade Elasticsearch 7.x ไป 8.x พร้อม migrate Kibana dashboards",
        "summary": "Rolling upgrade + re-index migration + Kibana dashboard compatibility check",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "ITSM ServiceNow ITOM Integration",
        "request_type": "Integration",
        "apps": ["APP-017","APP-084"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Prasertsak D.",
        "requester": "eaa",
        "objective": "Integrate ServiceNow ITOM กับ Grafana Observability ผ่าน bi-directional sync",
        "summary": "Auto-create incidents ใน ServiceNow จาก Grafana alerts + CMDB auto-discovery",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Camunda BPM Credit Approval Workflow",
        "request_type": "New Project",
        "apps": ["APP-091","APP-015"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Nipon A.",
        "requester": "eba",
        "objective": "Implement Credit Approval workflow บน Camunda BPMN แทน manual email process",
        "summary": "BPMN process modeling สำหรับ SME credit workflow + Treasury integration",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"High","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Submitted",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },

    # ── Draft (17) ─────────────────────────────────────────────────────────────
    {
        "title": "WMS Manhattan Upgrade to Cloud Edition",
        "request_type": "Upgrade",
        "apps": ["APP-059"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "pmo_office",
        "objective": "Upgrade WMS Manhattan On-premise ไป Manhattan Active Omni Cloud",
        "summary": "SaaS migration พร้อม re-integration กับ SAP EWM และ transport system",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 1,
        "reviewers": [],
    },
    {
        "title": "Power BI Premium Capacity Migration",
        "request_type": "Upgrade",
        "apps": ["APP-013"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Orawan L.",
        "requester": "eda",
        "objective": "ย้าย Power BI จาก Pro licenses ไป Premium Per Capacity สำหรับ enterprise scale",
        "summary": "Capacity migration + Paginated Reports + Dataflows Gen2 + Large model storage",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Low",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"Low",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Auto-pass",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Informatica MDM Customer Domain Expansion",
        "request_type": "Upgrade",
        "apps": ["APP-066","APP-026"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Charoenporn V.",
        "requester": "eda",
        "objective": "ขยาย Informatica MDM เพิ่ม Product domain นอกจาก Customer domain ที่มีอยู่",
        "summary": "Add Product MDM hub พร้อม Golden Record reconciliation กับ SAP MDG",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Splunk SIEM Cloud Migration",
        "request_type": "Migration",
        "apps": ["APP-057","APP-032"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Nuntachai P.",
        "requester": "esa",
        "objective": "Migrate Splunk On-premise ไป Splunk Cloud Platform เพื่อลด infra overhead",
        "summary": "Lift-and-shift Splunk index + saved searches + alerts ไป Splunk Cloud",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"High",
                   "technology_impact":"High","security_impact":"Critical","integration_impact":"High",
                   "compliance_impact":"High","has_pii":False,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "SAP Fiori Launchpad Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-097"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Somchai K.",
        "requester": "eaa",
        "objective": "Upgrade SAP Fiori Launchpad ให้รองรับ HTML5 Cloud apps บน BTP",
        "summary": "Configure SAP BTP Launchpad Service + migrate custom Fiori tiles 80+ apps",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"High",
                   "technology_impact":"Medium","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Demand Planning Kinaxis Migration",
        "request_type": "Migration",
        "apps": ["APP-047"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "eba",
        "objective": "Replace legacy Demand Planning ด้วย Kinaxis RapidResponse Cloud",
        "summary": "SCP-to-Kinaxis migration พร้อม S&OP process redesign และ SAP integration",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"High",
                   "technology_impact":"High","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "PingFederate IAM Upgrade to PingOne",
        "request_type": "Migration",
        "apps": ["APP-065","APP-016"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Nuntachai P.",
        "requester": "esa",
        "objective": "Migrate PingFederate On-premise IAM ไป PingOne Cloud CIAM",
        "summary": "SSO federation migration + OAuth2/OIDC re-configuration สำหรับ 80+ integrated apps",
        "impact": {"business_impact":"Critical","data_impact":"Medium","application_impact":"Critical",
                   "technology_impact":"High","security_impact":"Critical","integration_impact":"Critical",
                   "compliance_impact":"High","has_pii":True,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Adobe Experience Manager Upgrade 6.5→Cloud",
        "request_type": "Migration",
        "apps": ["APP-060"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Worapon S.",
        "requester": "eaa",
        "objective": "Migrate AEM 6.5 On-premise ไป AEM as a Cloud Service",
        "summary": "Content migration + custom component refactor + CI/CD pipeline สำหรับ Cloud Native AEM",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Procurement Ariba Network Expansion",
        "request_type": "Upgrade",
        "apps": ["APP-030"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Sirichai B.",
        "requester": "eba",
        "objective": "Expand SAP Ariba Network onboarding ให้ครอบคลุม Tier-2 suppliers 200+ ราย",
        "summary": "Supplier enablement program + EDI-to-Ariba migration + Guided Buying activation",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":True,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Compliance GRC Archer Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-036","APP-099"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Prasertsak D.",
        "requester": "esa",
        "objective": "Upgrade RSA Archer GRC 6.x ไป 6.13 พร้อม Consolidated Risk Management use case",
        "summary": "In-place upgrade + new IT Risk Management questionnaire + SOX control mapping",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"High","integration_impact":"Low",
                   "compliance_impact":"High","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "IoT Data Platform SCADA Integration",
        "request_type": "Integration",
        "apps": ["APP-035"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Phanuwat S.",
        "requester": "eta",
        "objective": "Integrate SCADA system กับ IoT Data Platform ผ่าน MQTT protocol",
        "summary": "Real-time sensor data ingestion จาก 500+ PLCs ผ่าน Edge gateway ไป Azure IoT Hub",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"Medium",
                   "technology_impact":"High","security_impact":"High","integration_impact":"High",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Document Management System Cloud Migration",
        "request_type": "Migration",
        "apps": ["APP-019"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Apinya T.",
        "requester": "eaa",
        "objective": "Migrate On-premise DMS ไป SharePoint Online + Microsoft 365",
        "summary": "Content migration 5TB + metadata mapping + workflows redesign บน Power Automate",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"Medium","integration_impact":"Medium",
                   "compliance_impact":"Medium","has_pii":True,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "PLM Windchill Cloud Migration",
        "request_type": "Migration",
        "apps": ["APP-041"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Patipan W.",
        "requester": "eta",
        "objective": "Migrate PTC Windchill PLM ไป Windchill+ SaaS",
        "summary": "PLM data migration + CAD integrations + ThingWorx IoT connectivity",
        "impact": {"business_impact":"High","data_impact":"High","application_impact":"High",
                   "technology_impact":"High","security_impact":"Medium","integration_impact":"High",
                   "compliance_impact":"Medium","has_pii":False,"internet_facing":False,
                   "new_integration":True,"new_vendor":False,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Tax Engine Upgrade - Thomson Reuters ONESOURCE",
        "request_type": "Upgrade",
        "apps": ["APP-044"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Amorn C.",
        "requester": "eba",
        "objective": "Upgrade Tax Engine ให้ตรงกับ e-Tax Invoice 2026 requirement",
        "summary": "Version upgrade + RD e-Tax API re-integration + VAT calculation logic update",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"High",
                   "compliance_impact":"Critical","has_pii":False,"internet_facing":True,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Middleware Platform Update - IBM MQ to RabbitMQ",
        "request_type": "Migration",
        "apps": ["APP-082"],
        "project_id": "PRJ-006",
        "roadmap_id": None,
        "biz_owner": "Chai W.",
        "requester": "eta",
        "objective": "Migrate IBM MQ messaging ไป RabbitMQ/CloudAMQP เพื่อลด license cost",
        "summary": "Queue-by-queue migration พร้อม consumer group re-configuration สำหรับ 30+ subscribers",
        "impact": {"business_impact":"High","data_impact":"Medium","application_impact":"High",
                   "technology_impact":"High","security_impact":"Low","integration_impact":"Critical",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":True,"new_technology":True,"expected_exception":False},
        "status": "Draft",
        "review_level": "Formal Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Catalog PIM Akeneo Upgrade",
        "request_type": "Upgrade",
        "apps": ["APP-042"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Varunya C.",
        "requester": "eaa",
        "objective": "Upgrade Akeneo PIM Community ไป Enterprise Edition พร้อม Asset Manager",
        "summary": "License upgrade + data model migration + e-Commerce connector update",
        "impact": {"business_impact":"Medium","data_impact":"Medium","application_impact":"Medium",
                   "technology_impact":"Low","security_impact":"Low","integration_impact":"Medium",
                   "compliance_impact":"Low","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Desk Review",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
    {
        "title": "Batch Processing v2 Performance Optimization",
        "request_type": "Upgrade",
        "apps": ["APP-018"],
        "project_id": None,
        "roadmap_id": None,
        "biz_owner": "Phanuwat S.",
        "requester": "eta",
        "objective": "ลด Batch Processing runtime จาก 6 ชั่วโมงเป็น < 2 ชั่วโมงด้วย parallel processing",
        "summary": "Refactor batch jobs ไป Spring Batch parallel steps + DB query optimization",
        "impact": {"business_impact":"Medium","data_impact":"Low","application_impact":"Medium",
                   "technology_impact":"Medium","security_impact":"None","integration_impact":"Low",
                   "compliance_impact":"None","has_pii":False,"internet_facing":False,
                   "new_integration":False,"new_vendor":False,"new_technology":False,"expected_exception":False},
        "status": "Draft",
        "review_level": "Auto-pass",
        "decision": None,
        "created_daysago": 0,
        "reviewers": [],
    },
]


# ─── Insert into DB ────────────────────────────────────────────────────────────
print(f"\n🌱  Seeding {len(SEED_REQUESTS)} ARB requests into {DB_PATH}...\n")

conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()

# Check arb tables exist
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'arb_%'").fetchall()]
if not tables:
    print("❌  ARB tables not found — start the server once first to create tables, then re-run.")
    conn.close()
    exit(1)
print(f"  Found ARB tables: {', '.join(tables)}\n")

# Clear existing seed data
for t in ["arb_recommendations","arb_actions","arb_decisions","arb_findings",
          "arb_comments","arb_reviewers","arb_impact_profile","arb_request_applications","arb_requests"]:
    cur.execute(f"DELETE FROM {t}")
conn.commit()
print("  🗑  Cleared existing ARB data\n")

# Sequence counter
counter_row = cur.execute("SELECT value FROM config WHERE key='arb_seq'").fetchone()
cur.execute("DELETE FROM config WHERE key='arb_seq'")

now = datetime.now()

for i, req in enumerate(SEED_REQUESTS):
    offset_ms = i * 1000
    arb_id = f"arb-{1773700000000 + i*7777}"

    # Calculate dates
    created_dt = now - timedelta(days=req["created_daysago"])
    created_iso = created_dt.isoformat()
    submitted_iso = ""
    closed_iso = ""
    if req["status"] not in ("Draft",):
        submitted_iso = (created_dt + timedelta(days=1)).isoformat()
    if req["status"] == "Decision Issued":
        closed_iso = (created_dt + timedelta(days=random.randint(5,20))).isoformat()

    code = f"ARB-2026-{i+1:04d}"

    # ── arb_requests ──────────────────────────────────────────────────────────
    cur.execute("""
        INSERT INTO arb_requests(id,request_code,title,request_type,review_level,status,
            business_objective,change_summary,business_owner,requester_user,
            target_date,project_id,roadmap_id,created_by,created_at,updated_at,submitted_at,closed_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (arb_id, code, req["title"], req["request_type"], req["review_level"], req["status"],
          req.get("objective",""), req.get("summary",""),
          req.get("biz_owner",""), req.get("requester","admin"),
          rnd_date(now, 30, 120),
          req.get("project_id") or "", req.get("roadmap_id") or "",
          req.get("requester","admin"), created_iso, created_iso, submitted_iso, closed_iso))

    # ── arb_request_applications ─────────────────────────────────────────────
    for app_id in req.get("apps", []):
        cur.execute("INSERT OR IGNORE INTO arb_request_applications(arb_request_id,application_id) VALUES(?,?)",
                    (arb_id, app_id))

    # ── arb_impact_profile ────────────────────────────────────────────────────
    imp = req.get("impact", {})
    cur.execute("""
        INSERT OR REPLACE INTO arb_impact_profile(
            arb_request_id,business_impact,data_impact,application_impact,technology_impact,
            security_impact,integration_impact,compliance_impact,
            has_pii,internet_facing,new_integration,new_vendor,new_technology,expected_exception,
            context_diagram,data_flow,interface_list,security_consideration,solution_summary)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (arb_id,
          imp.get("business_impact","None"), imp.get("data_impact","None"),
          imp.get("application_impact","None"), imp.get("technology_impact","None"),
          imp.get("security_impact","None"), imp.get("integration_impact","None"),
          imp.get("compliance_impact","None"),
          1 if imp.get("has_pii") else 0, 1 if imp.get("internet_facing") else 0,
          1 if imp.get("new_integration") else 0, 1 if imp.get("new_vendor") else 0,
          1 if imp.get("new_technology") else 0, 1 if imp.get("expected_exception") else 0,
          "","","","",""))

    # ── arb_reviewers ─────────────────────────────────────────────────────────
    assign_dt = created_dt + timedelta(days=1)
    for rev_user, rev_role in req.get("reviewers", []):
        cur.execute("""INSERT INTO arb_reviewers(arb_request_id,reviewer_user,reviewer_role,assigned_by,assigned_at)
                       VALUES(?,?,?,?,?)""",
                    (arb_id, rev_user, rev_role, "arb_office", assign_dt.isoformat()))

    # ── arb_comments (2 per In Review / Decision Issued) ─────────────────────
    if req["status"] in ("In Review","Decision Issued"):
        for j in range(2):
            tmpl = COMMENT_TEMPLATES[(i + j) % len(COMMENT_TEMPLATES)]
            rev = req["reviewers"][j % len(req["reviewers"])][0] if req["reviewers"] else "arb_office"
            cur.execute("""INSERT INTO arb_comments(arb_request_id,reviewer_user,domain,comment_type,comment_text,severity,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (arb_id, rev, tmpl[0], tmpl[1], tmpl[3], tmpl[2],
                         (created_dt + timedelta(days=2+j)).isoformat()))

    # ── arb_findings (for Decision Issued) ───────────────────────────────────
    finding_ids = []
    if req["status"] == "Decision Issued":
        num_findings = random.randint(1, 3)
        for j in range(num_findings):
            fid = f"FND-{1773700000000 + i*7777 + j*111}"
            tmpl = FINDING_TEMPLATES[(i + j) % len(FINDING_TEMPLATES)]
            cur.execute("""INSERT INTO arb_findings(
                           id,arb_request_id,category,domain,severity,description,
                           recommended_action,owner,due_date,status,created_by,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (fid, arb_id, tmpl[0], tmpl[1], tmpl[2], tmpl[3], tmpl[4],
                         req.get("requester","ea_office"),
                         rnd_date(now, 30, 90),
                         "Closed" if req["status"] == "Decision Issued" else "Open",
                         "arb_office",
                         (created_dt + timedelta(days=3)).isoformat()))
            finding_ids.append(fid)

    # ── arb_decisions ─────────────────────────────────────────────────────────
    if req["status"] == "Decision Issued" and req.get("decision"):
        dec_type, dec_summary, risks = req["decision"]
        cur.execute("""INSERT INTO arb_decisions(
                       arb_request_id,decision_type,decision_summary,rationale,
                       key_risks,required_next_steps,decided_by,decided_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (arb_id, dec_type, dec_summary,
                     f"Architecture review completed — {dec_summary}",
                     risks, "ดำเนินการตาม conditions ที่กำหนด",
                     "arb_office", closed_iso))
        # decision_type stored in arb_decisions only

    # ── arb_actions ───────────────────────────────────────────────────────────
    if req["status"] in ("In Review","Decision Issued"):
        num_actions = random.randint(1, 3)
        for j in range(num_actions):
            aid = f"ACT-{1773700000000 + i*7777 + j*222}"
            tmpl = ACTION_TEMPLATES[(i + j) % len(ACTION_TEMPLATES)]
            status = "Closed" if req["status"] == "Decision Issued" and random.random() > 0.4 else "Open"
            due = rnd_date(now, 14, 60)
            cur.execute("""INSERT INTO arb_actions(
                           id,arb_request_id,finding_id,action_description,action_type,
                           owner,due_date,required_evidence,status,closure_note,closed_at,created_by,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (aid, arb_id,
                         finding_ids[j % len(finding_ids)] if finding_ids else "",
                         tmpl[0], tmpl[1],
                         req.get("requester","ea_office"), due,
                         "Document ที่เกี่ยวข้อง",
                         status,
                         "Completed and verified" if status == "Closed" else "",
                         closed_iso if status == "Closed" else "",
                         "arb_office",
                         (created_dt + timedelta(days=4)).isoformat()))

    # ── arb_recommendations ───────────────────────────────────────────────────
    recs = []
    if imp.get("data_impact") in ("High","Critical"):
        recs.append(("artifact","","Data Flow Diagram","Data impact requires data flow documentation",1))
        recs.append(("artifact","","Data Dictionary","Mandatory for High data impact",1))
    if imp.get("security_impact") in ("High","Critical") or imp.get("has_pii"):
        recs.append(("artifact","","Security Assessment Report","Security/PII risk requires formal assessment",1))
        recs.append(("abb","ESA-SEC-001","Security ABB Reference","Apply Security Architecture Building Block",0))
    if imp.get("integration_impact") in ("High","Critical") or imp.get("new_integration"):
        recs.append(("artifact","","Interface Specification","Integration requires interface documentation",1))
        recs.append(("abb","ESA-INT-001","Integration ABB Reference","Apply Integration Pattern from ESA",0))
    if imp.get("new_technology"):
        recs.append(("artifact","","Technology Assessment","New technology requires formal evaluation",1))
    if imp.get("internet_facing"):
        recs.append(("artifact","","Internet Risk Assessment","Internet-facing requires risk documentation",1))
    if imp.get("expected_exception"):
        recs.append(("artifact","","Exception Approval Form","Expected exception requires formal approval",1))
    if imp.get("compliance_impact") in ("High","Critical"):
        recs.append(("artifact","","Compliance Checklist","High compliance impact requires checklist",1))
    if not recs:
        recs.append(("artifact","","Architecture Overview Document","Standard documentation required",0))

    for ref_type, ref_code, ref_name, reason, mandatory in recs:
        cur.execute("""INSERT INTO arb_recommendations(
                       arb_request_id,rec_type,ref_code,ref_name,reason_text,is_mandatory,status)
                       VALUES(?,?,?,?,?,?,?)""",
                    (arb_id, ref_type, ref_code, ref_name, reason, mandatory,
                     "Completed" if req["status"] == "Decision Issued" else "Pending"))

    conn.commit()
    status_icon = {"Decision Issued":"✅","In Review":"🔍","Submitted":"📤","Draft":"📝"}.get(req["status"],"  ")
    print(f"  {status_icon} [{i+1:02d}] {code} | {req['review_level']:15} | {req['status']:17} | {req['title'][:50]}")

# Update arb_seq counter
cur.execute("INSERT INTO config VALUES('arb_seq', ?)", (str(len(SEED_REQUESTS)),))
conn.commit()
conn.close()

print(f"""
═══════════════════════════════════════════════════════
  ✅  Seeded {len(SEED_REQUESTS)} ARB Requests successfully!
───────────────────────────────────────────────────────
  Decision Issued : {sum(1 for r in SEED_REQUESTS if r['status']=='Decision Issued'):2d}
  In Review       : {sum(1 for r in SEED_REQUESTS if r['status']=='In Review'):2d}
  Submitted       : {sum(1 for r in SEED_REQUESTS if r['status']=='Submitted'):2d}
  Draft           : {sum(1 for r in SEED_REQUESTS if r['status']=='Draft'):2d}
───────────────────────────────────────────────────────
  Formal Review   : {sum(1 for r in SEED_REQUESTS if r['review_level']=='Formal Review'):2d}
  Desk Review     : {sum(1 for r in SEED_REQUESTS if r['review_level']=='Desk Review'):2d}
  Auto-pass       : {sum(1 for r in SEED_REQUESTS if r['review_level']=='Auto-pass'):2d}
═══════════════════════════════════════════════════════
""")
