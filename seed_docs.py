#!/usr/bin/env python3
"""
seed_docs.py — Seed EA Document Library with 22 example documents
Covers: Policy(5), Procedure(3), Guideline(3), ADD(5), ADR(4), Template(2)
"""
import sqlite3, uuid, datetime, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
EA_DB = os.path.join(BASE, "ea_domains.db")
APP_DB = os.path.join(BASE, "appport.db")
NOW = datetime.datetime.utcnow().isoformat()
TODAY = datetime.date.today().isoformat()

# ── helpers ──────────────────────────────────────────────────────────────────
def conn_ea():
    c = sqlite3.connect(EA_DB)
    c.row_factory = sqlite3.Row
    return c

def doc(doc_code, doc_type, title, domain, category, status, version,
        owner, confidentiality, effective_date, review_date, summary, content,
        approved_by=""):
    return {
        "id": str(uuid.uuid4()),
        "doc_code": doc_code,
        "doc_type": doc_type,
        "title": title,
        "version": version,
        "status": status,
        "domain": domain,
        "category": category,
        "scope": "",
        "summary": summary,
        "content": content,
        "confidentiality": confidentiality,
        "owner": owner,
        "approved_by": approved_by,
        "effective_date": effective_date,
        "review_date": review_date,
        "expiry_date": "",
        "tags": "[]",
        "created_by": "ea.admin",
        "created_at": NOW,
        "updated_at": NOW,
    }

# ── POLICY DOCUMENTS ─────────────────────────────────────────────────────────
DOCS = [

doc("EA-POL-GOV-001","Policy",
    "Enterprise Architecture Governance Policy",
    "Cross-domain","Governance","Approved","1.0",
    "ea.lead","Internal","2025-01-01","2026-01-01",
    "นโยบายกำกับดูแลสถาปัตยกรรมองค์กร ครอบคลุมการตัดสินใจ การ review และการบังคับใช้มาตรฐาน EA ทั้งหมด",
    approved_by="cio@company.com",
    content="""# Enterprise Architecture Governance Policy
**Code:** EA-POL-GOV-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.lead

## 1. Purpose & Objectives
นโยบายนี้กำหนดกรอบการกำกับดูแล Enterprise Architecture (EA) เพื่อ:
- ให้มั่นใจว่าการตัดสินใจด้าน IT สอดคล้องกับกลยุทธ์องค์กร
- กำหนดบทบาทและความรับผิดชอบของ EA Team และ Stakeholders
- สร้างกระบวนการ review และอนุมัติการเปลี่ยนแปลงสถาปัตยกรรม

## 2. Scope
นโยบายนี้ใช้กับ:
- โครงการ IT ทุกโครงการที่มีมูลค่า > 500,000 THB
- การเปลี่ยนแปลงระบบ Core/Critical ทุกรายการ
- การนำเทคโนโลยีใหม่เข้าสู่องค์กร
- Vendor ภายนอกที่ดำเนินงานด้าน IT ในนามขององค์กร

## 3. Policy Statements
1. **ARB Mandatory Review** — โครงการทุกประเภทที่อยู่ใน Scope ต้องผ่าน Architecture Review Board (ARB) ก่อนดำเนินการ
2. **Standards Compliance** — ระบบทุกระบบต้องปฏิบัติตาม Architecture Standards ที่กำหนดไว้ใน EA Repository
3. **Exception Process** — การยกเว้นมาตรฐานต้องขออนุมัติผ่าน Waiver Process ตาม STD-GOV-014
4. **Documentation Requirement** — ระบบ Critical/High ต้องมี Architecture Design Document (ADD) ที่ได้รับอนุมัติ
5. **Technology Lifecycle** — การนำเทคโนโลยีใหม่ต้องผ่าน Tech Radar Assessment ก่อนใช้งาน Production

## 4. Roles & Responsibilities
| Role | Responsibility |
|------|----------------|
| EA Lead | กำหนดทิศทาง EA, อนุมัติ Standards และ Waivers |
| ARB Chair | ดำเนิน ARB Review, ออก Decision |
| Application Owner | ปฏิบัติตาม Standards, ส่ง ARB Request |
| IT Project Manager | ประสาน ARB Review ตั้งแต่ต้น |
| CIO | อนุมัติ Exception ระดับ Strategic |

## 5. Related Standards
- STD-GOV-003: Architecture Review Board (ARB) Process
- STD-GOV-004: Enterprise Architecture Roadmap
- STD-GOV-005: IT Project Architecture Gate
- STD-GOV-014: Standard Waiver & Exception Process

## 6. Related Procedures
- EA-PRO-ARB-001: ARB Submission & Review Procedure
- EA-PRO-GOV-001: EA Standards Management Procedure

## 7. Exceptions & Waiver Process
การขอยกเว้นนโยบายต้องยื่นผ่าน ARB พร้อมเหตุผลและ Risk Mitigation Plan อ้างอิง STD-GOV-014

## 8. Compliance & Enforcement
การไม่ปฏิบัติตามนโยบายจะส่งผลให้โครงการถูก Hold จนกว่าจะได้รับการ remediate หรือ Waiver ที่ได้รับอนุมัติ

## 9. Review Schedule
ทบทวนทุก 12 เดือน หรือเมื่อมีการเปลี่ยนแปลงกลยุทธ์องค์กรที่มีนัยสำคัญ

## 10. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2025-01-01 | ea.lead | Initial release |
"""),

doc("EA-POL-SEC-001","Policy",
    "Information Security Architecture Policy",
    "ESA","Security","Approved","1.2",
    "ea.security","Confidential","2025-03-01","2026-03-01",
    "นโยบายความปลอดภัยสารสนเทศระดับ EA ครอบคลุม Zero Trust, Encryption, Identity, Endpoint และ Cloud Security",
    approved_by="ciso@company.com",
    content="""# Information Security Architecture Policy
**Code:** EA-POL-SEC-001 | **Version:** 1.2 | **Status:** Approved | **Owner:** ea.security

## 1. Purpose & Objectives
กำหนดหลักการสถาปัตยกรรมความปลอดภัยที่ระบบทุกระบบต้องปฏิบัติตาม เพื่อปกป้องข้อมูลและระบบขององค์กรจาก Cyber Threats

## 2. Scope
ระบบ IT ทุกระบบ ทั้ง On-Premise, Cloud และ Hybrid ที่ประมวลผลข้อมูลขององค์กร

## 3. Policy Statements
1. **Zero Trust** — ไม่มีการ Trust โดยอัตโนมัติ ทุก Request ต้องผ่านการ Authenticate และ Authorize (STD-SEC-001)
2. **Encryption** — ข้อมูลทุกประเภทต้องเข้ารหัสทั้ง At Rest และ In Transit (STD-SEC-002)
3. **IAM** — ทุกระบบต้องใช้ Centralized Identity Provider และ MFA (STD-SEC-005, STD-SEC-023)
4. **DevSecOps** — Security ต้องฝังอยู่ใน SDLC ตั้งแต่ Design Phase (STD-SEC-007, STD-SEC-012)
5. **Vulnerability Management** — ระบบ Critical ต้อง Scan ทุก 30 วัน, High ทุก 90 วัน (STD-SEC-004)
6. **PII Protection** — ข้อมูล PII ต้องผ่าน Data Minimization และ Masking ก่อนใช้งาน Non-Production

## 4. Roles & Responsibilities
| Role | Responsibility |
|------|----------------|
| CISO | กำกับ Security Policy โดยรวม |
| EA Security Architect | ออกแบบและ review Security Architecture |
| Application Owner | ปฏิบัติตาม Security Standards |
| Security Operations | Monitor และ Respond ต่อ Incident |

## 5. Related Standards
- STD-SEC-001 ถึง STD-SEC-025 — Security Standards ทั้งหมด
- STD-DAT-001: Data Classification & Handling Policy
- STD-DAT-003: PII Data Minimization

## 6. Compliance & Enforcement
ระบบที่ไม่ผ่าน Security Review จะไม่ได้รับอนุญาตให้ Deploy ใน Production

## 7. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2024-06-01 | ea.security | Initial release |
| 1.2 | 2025-03-01 | ea.security | เพิ่ม PII Protection และ Container Security |
"""),

doc("EA-POL-DAT-001","Policy",
    "Data Governance & Architecture Policy",
    "EDA","Data","Approved","1.0",
    "ea.data","Internal","2025-02-01","2026-02-01",
    "นโยบายกำกับดูแลข้อมูลองค์กร ครอบคลุมการจำแนกประเภท, Data Owner, คุณภาพข้อมูล และการปฏิบัติตาม PDPA",
    approved_by="cdo@company.com",
    content="""# Data Governance & Architecture Policy
**Code:** EA-POL-DAT-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.data

## 1. Purpose
กำหนดกรอบการกำกับดูแลข้อมูลเพื่อให้มั่นใจในคุณภาพ ความปลอดภัย และการใช้ข้อมูลอย่างเหมาะสม

## 2. Scope
ข้อมูลทุกประเภทที่องค์กรสร้าง เก็บ ประมวลผล หรือรับมา ทั้งใน Structured และ Unstructured Format

## 3. Policy Statements
1. **Data Classification** — ข้อมูลทุกชุดต้องได้รับการจำแนกประเภท (Public/Internal/Confidential/Restricted)
2. **Data Ownership** — ทุก Data Domain ต้องมี Data Owner ที่รับผิดชอบ
3. **Data Quality** — ข้อมูล Master Data ต้องมี Data Quality Score ≥ 85%
4. **PDPA Compliance** — ข้อมูลส่วนบุคคลต้องปฏิบัติตาม PDPA อย่างเคร่งครัด
5. **Data Lifecycle** — ต้องมี Retention Policy ชัดเจนสำหรับข้อมูลทุกประเภท

## 4. Related Standards
- STD-DAT-001: Data Classification & Handling Policy
- STD-DAT-003: PII Data Minimization
- STD-DAT-004: Data Quality Framework
- STD-DAT-005: Data Retention & Archival Policy

## 5. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2025-02-01 | ea.data | Initial release |
"""),

doc("EA-POL-CLD-001","Policy",
    "Cloud Adoption & Governance Policy",
    "ETA","Cloud","Approved","1.1",
    "ea.platform","Internal","2025-04-01","2026-04-01",
    "นโยบายการนำ Cloud มาใช้งานในองค์กร ครอบคลุม Cloud-First Principle, FinOps, Security Baseline และ Multi-Cloud Strategy",
    approved_by="cto@company.com",
    content="""# Cloud Adoption & Governance Policy
**Code:** EA-POL-CLD-001 | **Version:** 1.1 | **Status:** Approved | **Owner:** ea.platform

## 1. Purpose
กำหนดหลักการและกรอบการนำ Cloud Technology มาใช้งานอย่างมีประสิทธิภาพและปลอดภัย

## 2. Scope
โครงการ IT ทุกโครงการที่พิจารณาใช้ Cloud Services (IaaS, PaaS, SaaS)

## 3. Policy Statements
1. **Cloud-First** — โครงการใหม่ต้องพิจารณา Cloud ก่อน On-Premise
2. **Approved Providers** — ใช้ได้เฉพาะ Cloud Providers ที่ได้รับอนุมัติ (AWS, Azure, GCP)
3. **Landing Zone** — ต้องใช้ Cloud Landing Zone มาตรฐานขององค์กร (STD-CLD-004)
4. **FinOps** — ทุก Cloud Workload ต้องมี Cost Tagging และ Budget Alert (STD-CLD-001)
5. **Security Baseline** — ต้องผ่าน Cloud Security Baseline Assessment ก่อน Go-Live (STD-CLD-002)

## 4. Related Standards
- STD-CLD-001: Cloud Cost Governance
- STD-CLD-002: Cloud-Native Security Baseline
- STD-CLD-004: Cloud Landing Zone Standard
- STD-PLT-009: Cloud Native Architecture Principle

## 5. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2024-10-01 | ea.platform | Initial release |
| 1.1 | 2025-04-01 | ea.platform | เพิ่ม FinOps requirement |
"""),

doc("EA-POL-API-001","Policy",
    "API Governance Policy",
    "EAA","API","Approved","1.0",
    "ea.integration","Internal","2025-01-15","2026-01-15",
    "นโยบายกำกับดูแล API ขององค์กร ครอบคลุม API-First Design, Security, Versioning และ Lifecycle Management",
    approved_by="cto@company.com",
    content="""# API Governance Policy
**Code:** EA-POL-API-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.integration

## 1. Purpose
กำหนดมาตรฐานและหลักปฏิบัติสำหรับการออกแบบ พัฒนา และบริหาร API ขององค์กร

## 2. Scope
API ทุกประเภท (Internal/External/Partner) ที่พัฒนาโดยทีม IT

## 3. Policy Statements
1. **API-First Design** — ทุก Integration ต้องใช้ API เป็น Primary Interface (STD-APP-002)
2. **API Gateway** — External API ทุกตัวต้องผ่าน API Gateway (STD-API-002)
3. **API Security** — ต้องมี Authentication, Authorization และ Rate Limiting (STD-SEC-020, STD-API-005)
4. **Versioning** — ต้องใช้ Semantic Versioning และมี Deprecation Notice ≥ 6 เดือน (STD-API-004, STD-API-011)
5. **Documentation** — API ทุกตัวต้องมี OpenAPI Specification ใน Developer Portal (STD-API-006)

## 4. Related Standards
- STD-API-001 ถึง STD-API-015 — API Standards ทั้งหมด
- STD-SEC-020: API Security Standard

## 5. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2025-01-15 | ea.integration | Initial release |
"""),

# ── PROCEDURES ────────────────────────────────────────────────────────────────

doc("EA-PRO-ARB-001","Procedure",
    "ARB Submission & Review Procedure",
    "Cross-domain","Governance","Approved","2.0",
    "ea.lead","Internal","2025-01-01","2026-01-01",
    "ขั้นตอนการยื่น ARB Request ตั้งแต่การเตรียมเอกสาร การ Submit จนถึงการออก Decision และการติดตาม Action Items",
    approved_by="arb.chair@company.com",
    content="""# ARB Submission & Review Procedure
**Code:** EA-PRO-ARB-001 | **Version:** 2.0 | **Status:** Approved | **Owner:** ea.lead

## 1. Purpose
อธิบายขั้นตอนการยื่น ARB Request และกระบวนการ Review เพื่อให้ทุกโครงการได้รับการ Govern อย่างถูกต้อง

## 2. Scope
โครงการ IT ทุกโครงการที่อยู่ใน Scope ตาม EA-POL-GOV-001

## 3. Roles & Responsibilities
| Role | Responsibility |
|------|----------------|
| Requester | เตรียมเอกสารและยื่น Request |
| ARB Secretariat | ตรวจสอบ Completeness, มอบหมาย Reviewer |
| EA Reviewer | Review ใน Domain ที่รับผิดชอบ |
| ARB Chair | ออก Decision |

## 4. Prerequisites
- [ ] กำหนดสิ่งที่จะเปลี่ยนแปลง (Change Summary)
- [ ] ระบุ Business Objective ที่ชัดเจน
- [ ] ประเมิน Impact Profile (Business/Data/Security/Tech/Integration)
- [ ] เตรียม Context Diagram อย่างน้อย 1 รูป
- [ ] ระบุ Application(s) ที่เกี่ยวข้อง

## 5. Procedure Steps

### Step 1 — Initiate Request (Day 0)
1. เข้าสู่ระบบ MPX AppPort → ARB → ARB Requests
2. กด **+ New Request** และกรอกข้อมูลให้ครบถ้วน
3. แนบ Context Diagram และ Solution Summary
4. Save as **Draft**

### Step 2 — Submit for Review (Day 0-3)
1. ตรวจสอบ Completeness ของ Impact Profile
2. กด **Submit** → Status เปลี่ยนเป็น Submitted
3. ARB Secretariat จะ Assign Reviewer ภายใน 2 วันทำการ

### Step 3 — Review Period (Day 3-10)
1. Reviewer แต่ละ Domain ทำการ Review และ Comment ภายใน 5 วันทำการ
2. Requester ต้องตอบ Comment ภายใน 2 วันทำการ
3. Status เปลี่ยนเป็น **In Review**

### Step 4 — ARB Decision Meeting (Day 10-14)
1. ARB Chair เปิด Meeting เพื่อพิจารณา Request
2. ออก Decision: Approved / Conditionally Approved / Rejected / Deferred
3. บันทึก Key Risks และ Required Next Steps

### Step 5 — Post-Decision Actions
1. Requester ดำเนินการตาม Action Items ที่กำหนด
2. แจ้ง Closure เมื่อ Action Items เสร็จสิ้น

## 6. Inputs & Outputs
| Item | Type | Description |
|------|------|-------------|
| ARB Request Form | Input | ข้อมูลโครงการและ Impact Profile |
| Context Diagram | Input | สถาปัตยกรรมโดยรวม |
| ARB Decision | Output | ผลการตัดสินใจพร้อม Rationale |
| Action Items | Output | รายการที่ต้องดำเนินการต่อ |

## 7. Related Documents
- EA-POL-GOV-001: Enterprise Architecture Governance Policy
- STD-GOV-003: Architecture Review Board (ARB) Process

## 8. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2024-01-01 | ea.lead | Initial release |
| 2.0 | 2025-01-01 | ea.lead | เพิ่ม Digital Submission Process |
"""),

doc("EA-PRO-SEC-001","Procedure",
    "Security Architecture Review Procedure",
    "ESA","Security","Approved","1.0",
    "ea.security","Confidential","2025-02-01","2026-02-01",
    "ขั้นตอนการทำ Security Architecture Review สำหรับโครงการใหม่และการเปลี่ยนแปลงระบบ ครอบคลุม Threat Modeling และ Security Assessment",
    content="""# Security Architecture Review Procedure
**Code:** EA-PRO-SEC-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.security

## 1. Purpose
กำหนดกระบวนการ Review ด้านความปลอดภัยสำหรับโครงการ IT ทุกประเภท

## 2. Scope
โครงการที่มี Security Impact = High หรือ Critical ตาม ARB Impact Profile

## 3. Procedure Steps

### Step 1 — Threat Modeling
1. สร้าง Data Flow Diagram (DFD) ของระบบ
2. ระบุ Trust Boundaries และ Entry Points
3. ใช้ STRIDE Model วิเคราะห์ Threat ทุก Component

### Step 2 — Security Controls Review
1. ตรวจสอบ ABB Coverage: IAM, Network, Data, Application Security
2. Map กับ Security Standards ที่เกี่ยวข้อง (STD-SEC-xxx)
3. ระบุ Gaps และ Compensating Controls

### Step 3 — Compliance Check
1. ตรวจสอบ PDPA, ISO27001, PCI-DSS ตามที่ระบบต้องปฏิบัติตาม
2. ออก Security Architecture Sign-off หรือ Finding List

## 4. Related Documents
- EA-POL-SEC-001: Information Security Architecture Policy
- STD-SEC-007: Application Security (DevSecOps)
- STD-SEC-017: Security Architecture Review Requirement
"""),

doc("EA-PRO-STD-001","Procedure",
    "Architecture Standard Management Procedure",
    "Cross-domain","Governance","Approved","1.0",
    "ea.lead","Internal","2025-01-01","2026-01-01",
    "ขั้นตอนการสร้าง แก้ไข และ Deprecate Architecture Standards รวมถึงกระบวนการ Review และ Approval",
    content="""# Architecture Standard Management Procedure
**Code:** EA-PRO-STD-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.lead

## 1. Purpose
กำหนดกระบวนการบริหาร Architecture Standards ให้ทันสมัยและสอดคล้องกับ Technology Landscape

## 2. Procedure Steps

### Step 1 — Initiate Standard
1. ระบุ Gap หรือ Need สำหรับ Standard ใหม่
2. Draft Standard โดย EA Domain Lead ที่รับผิดชอบ

### Step 2 — Peer Review
1. วน Review ใน EA Team (2 สัปดาห์)
2. รับ Comment จาก Stakeholders

### Step 3 — ARB Endorsement
1. นำเสนอใน ARB Meeting เพื่อขอ Endorse
2. อัปเดตตาม Feedback ก่อน Publish

### Step 4 — Publish & Communicate
1. เพิ่มเข้า EA Repository → Standards
2. แจ้ง Application Owners และ Dev Teams

### Step 5 — Periodic Review
1. ทบทวน Standard ทุก 12 เดือน
2. Mark เป็น Deprecated เมื่อล้าสมัย

## 3. Related Documents
- EA-POL-GOV-001: EA Governance Policy
- STD-GOV-006: Technology Standardization Process
"""),

# ── GUIDELINES ────────────────────────────────────────────────────────────────

doc("EA-GDL-API-001","Guideline",
    "RESTful API Design Guideline",
    "EAA","API","Approved","1.0",
    "ea.integration","Internal","2025-02-01","2026-02-01",
    "แนวทางปฏิบัติสำหรับการออกแบบ RESTful API ให้มีความสม่ำเสมอ ใช้งานง่าย และปลอดภัย",
    content="""# RESTful API Design Guideline
**Code:** EA-GDL-API-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.integration

## 1. Introduction
Guideline นี้ขยายความ STD-API-001 เพื่อให้ทีมพัฒนามีแนวทางที่ชัดเจนในการออกแบบ REST API

## 2. Principles
- **Resource-Oriented** — ออกแบบรอบ Resource ไม่ใช่ Action
- **Consistent** — ใช้ Convention เดียวกันทั้ง API Landscape
- **Predictable** — Behavior ที่คาดเดาได้สำหรับ Consumer
- **Secure by Design** — Security ตั้งแต่ขั้นตอน Design

## 3. Recommended Practices

### 3.1 URL Design
- ใช้ Noun (Plural) สำหรับ Resource: `/api/v1/applications`, `/api/v1/users`
- ไม่ใช้ Verb ใน URL: ❌ `/api/getUser` → ✅ `GET /api/users/{id}`
- ใช้ Kebab-case สำหรับ Multi-word: `/api/arb-requests`
- Nested Resource ไม่เกิน 2 ระดับ: `/api/apps/{id}/services`

### 3.2 HTTP Methods
| Method | Usage | Idempotent |
|--------|-------|------------|
| GET | อ่านข้อมูล | ✅ |
| POST | สร้าง Resource ใหม่ | ❌ |
| PUT | แทนที่ Resource ทั้งหมด | ✅ |
| PATCH | อัปเดตบางส่วน | ✅ |
| DELETE | ลบ Resource | ✅ |

### 3.3 Response Format
```json
{
  "data": { ... },
  "meta": { "total": 100, "page": 1, "limit": 20 },
  "errors": []
}
```

### 3.4 Error Handling
```json
{
  "errors": [{
    "code": "VALIDATION_ERROR",
    "message": "field 'email' is required",
    "field": "email"
  }]
}
```

### 3.5 Versioning
- ใช้ URL Versioning: `/api/v1/`, `/api/v2/`
- Major version เมื่อมี Breaking Change เท่านั้น
- Minor/Patch ไม่ต้องเปลี่ยน Version

## 4. Anti-patterns (สิ่งที่ควรหลีกเลี่ยง)
- ❌ ใช้ GET สำหรับ Operation ที่เปลี่ยนแปลงข้อมูล
- ❌ Return HTTP 200 สำหรับ Error
- ❌ ใช้ Verb ใน URL (`/api/createUser`)
- ❌ Nested Resource เกิน 3 ระดับ
- ❌ ไม่มี Pagination สำหรับ Collection ที่ใหญ่

## 5. Related Standards
- STD-API-001: RESTful API Design Standard
- STD-API-004: API Versioning Strategy
- STD-API-008: API Error Handling Standard
"""),

doc("EA-GDL-CLD-001","Guideline",
    "Cloud Architecture Design Guideline",
    "ETA","Cloud","Approved","1.0",
    "ea.platform","Internal","2025-03-01","2026-03-01",
    "แนวทางการออกแบบสถาปัตยกรรม Cloud ตาม Well-Architected Framework ครอบคลุม Reliability, Security, Performance, Cost, Operational Excellence",
    content="""# Cloud Architecture Design Guideline
**Code:** EA-GDL-CLD-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.platform

## 1. Introduction
Guideline นี้ให้แนวทางการออกแบบ Cloud Architecture ตามหลัก Well-Architected Framework

## 2. Five Pillars Framework

### 2.1 Operational Excellence
- ใช้ Infrastructure as Code (IaC) สำหรับทุก Resource (STD-PLT-002)
- Implement Observability: Logs, Metrics, Traces (STD-PLT-004)
- มี Runbook สำหรับ Operational Procedures

### 2.2 Security
- ใช้ Least Privilege สำหรับ IAM Roles
- Enable CloudTrail/Audit Logs ทุก Account
- Encrypt ทุกอย่าง: ข้อมูล, Network Traffic, Secrets (STD-SEC-002, STD-SEC-003)

### 2.3 Reliability
- ออกแบบ Multi-AZ สำหรับ Critical Workloads
- มี Auto-scaling และ Load Balancing
- กำหนด RTO/RPO และทดสอบ DR อย่างน้อยปีละ 1 ครั้ง (STD-PLT-003)

### 2.4 Performance Efficiency
- เลือก Right-size Instance ตาม Workload Pattern
- ใช้ Caching Layer (CDN, In-Memory Cache) สำหรับ Read-heavy Workloads
- Monitor Performance SLO อย่างต่อเนื่อง (STD-PLT-010)

### 2.5 Cost Optimization
- Tag ทุก Resource ด้วย Project/Team/Environment (STD-CLD-001)
- ใช้ Reserved/Spot Instances สำหรับ Stable Workloads
- Review Cost Report ทุกเดือน

## 3. Anti-patterns
- ❌ Lift & Shift โดยไม่ Optimize สำหรับ Cloud
- ❌ ไม่มี Cost Budget Alert
- ❌ ใช้ Root Account สำหรับ Daily Operations
- ❌ Public S3 Bucket โดยไม่จำเป็น

## 4. Related Standards
- STD-PLT-001 ถึง STD-PLT-015
- STD-CLD-001, STD-CLD-002, STD-CLD-004
"""),

doc("EA-GDL-SEC-001","Guideline",
    "Secure Coding & DevSecOps Guideline",
    "ESA","Security","Approved","1.0",
    "ea.security","Internal","2025-04-01","2026-04-01",
    "แนวทาง Secure Coding และการฝัง Security ใน SDLC (DevSecOps) ครอบคลุม OWASP Top 10, SAST/DAST, Secret Management และ Container Security",
    content="""# Secure Coding & DevSecOps Guideline
**Code:** EA-GDL-SEC-001 | **Version:** 1.0 | **Status:** Approved | **Owner:** ea.security

## 1. Introduction
Guideline นี้ให้แนวทางการฝัง Security ในทุกขั้นตอนของ SDLC

## 2. OWASP Top 10 — Mitigation Practices

### A01: Broken Access Control
- ใช้ Role-Based Access Control (RBAC) อย่างเคร่งครัด
- ทดสอบ Horizontal และ Vertical Privilege Escalation

### A02: Cryptographic Failures
- ใช้ AES-256 สำหรับ At-Rest, TLS 1.3 สำหรับ In-Transit
- ห้ามใช้ MD5, SHA-1 สำหรับ Password Hashing

### A03: Injection
- ใช้ Parameterized Queries/Prepared Statements เสมอ
- Validate และ Sanitize ทุก Input

## 3. DevSecOps Pipeline

### Security Gates ใน CI/CD:
```
Code Commit
  → SAST (SonarQube/Checkmarx) [STD-APP-020]
  → SCA / Dependency Check (Snyk) [STD-APP-009]
  → Secret Scanning
  → Build & Unit Test
  → DAST (OWASP ZAP) [เฉพาะ Staging]
  → Container Scan (Aqua/Trivy) [STD-SEC-021]
  → Deploy
```

## 4. Secret Management
- ห้าม Hardcode Secret ใน Code หรือ Config File
- ใช้ Vault/AWS Secrets Manager/Azure Key Vault (STD-SEC-003)
- Rotate Secret ทุก 90 วัน สำหรับ Production

## 5. Related Standards
- STD-SEC-007: Application Security (DevSecOps)
- STD-SEC-012: Secure Software Development Lifecycle
- STD-APP-008: Input Validation & Output Encoding
"""),

# ── ARCHITECTURE DESIGN DOCUMENTS ─────────────────────────────────────────────

doc("APP-001-ADD-v1","ADD",
    "CRM System — Architecture Design Document v1.0",
    "Application","Application","Approved","1.0",
    "ea.team","Internal","2024-06-01","2025-06-01",
    "Architecture Design Document สำหรับ CRM System (APP-001) ครอบคลุม Logical Architecture, Integration, Security และ Technology Stack",
    content="""# CRM System — Architecture Design Document
**Code:** APP-001-ADD-v1 | **Application:** APP-001 CRM System | **Version:** 1.0

---

## 1. Executive Summary
CRM System เป็นระบบ Core Front-Office ที่รองรับกระบวนการ Customer Management ตั้งแต่ Lead Generation, Customer Onboarding จนถึง Customer Retention รองรับผู้ใช้งาน 800 คน และข้อมูลลูกค้ากว่า 2 ล้านราย

## 2. System Overview & Business Context
- **Business Purpose:** บริหารความสัมพันธ์ลูกค้าและ Sales Pipeline
- **Business Capabilities Supported:** BCAP-001, BCAP-002, BCAP-003, BCAP-006
- **Application Classification:** Core / Critical / Customer-facing

## 3. Architecture Goals & Constraints
### Quality Attributes
| Attribute | Requirement | Target |
|-----------|-------------|--------|
| Availability | 99.9% | 24x7 excluding maintenance |
| Response Time | < 300ms | p95 API Response |
| Scalability | 1,000 concurrent | Peak hours |
| Data Retention | 7 years | Regulatory requirement |

### Architecture Principles Applied
- STD-APP-001: Clean Architecture
- STD-APP-002: API-First Development
- STD-SEC-001: Zero Trust Architecture

## 4. Logical Architecture
```
[Web Browser / Mobile App]
       ↓ HTTPS / TLS 1.3
[API Gateway (Kong)] → Rate Limiting, Auth, Logging
       ↓
[CRM Application Services]
  ├── Customer Service
  ├── Sales Pipeline Service
  ├── Campaign Service
  └── Analytics Service
       ↓
[Data Layer]
  ├── PostgreSQL (Transactional)
  ├── Redis (Session/Cache)
  └── Elasticsearch (Search)
```

## 5. Data Architecture
- **Data Domains:** DDOM-001 (Customer Master), DDOM-007 (Sales Data)
- **PII Data:** YES — Name, Email, Phone, Address
- **Classification:** Confidential
- **Data Controls:** Encryption at Rest, Column-level Masking for Non-Prod

## 6. Integration Architecture
| System | Direction | Protocol | Description |
|--------|-----------|----------|-------------|
| ERP (APP-010) | Outbound | REST API | Sync Customer Data |
| Email Gateway | Outbound | SMTP/API | Campaign Emails |
| Analytics Platform | Outbound | Event Stream | Behavioral Data |
| IAM (SSO) | Inbound | SAML/OAuth2 | Authentication |

## 7. Security Architecture
- **Authentication:** SSO via Microsoft Entra ID (ABB-004)
- **Authorization:** RBAC — Sales/Manager/Admin
- **ABB Coverage:** ABB-001, ABB-004, ABB-019, ABB-025
- **Security Standards:** STD-SEC-001, STD-SEC-002, STD-SEC-005
- **Compliance:** PDPA, ISO27001

## 8. Technology Stack
| Category | Technology | Version | Standard Status |
|----------|-----------|---------|-----------------|
| Language | Java | 21 LTS | Approved |
| Framework | Spring Boot | 3.2 | Approved |
| Database | PostgreSQL | 16 | Approved |
| Cache | Redis | 7.2 | Approved |
| Container | Docker/Kubernetes | 1.29 | Approved |

## 9. Deployment Architecture
- **Environment:** Private Cloud (On-Premise Kubernetes)
- **DR Strategy:** Active-Passive, RTO=4hr, RPO=1hr
- **Backup:** Daily Full + Hourly Incremental

## 10. ARB Decision Reference
- ARB Request: ARB-2024-0001
- Decision: Conditionally Approved
- Key Conditions: ต้องมี PDPA DPO Sign-off ก่อน Go-Live

## 11. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | 2024-06-01 | ea.team | Initial release |
"""),

doc("APP-020-ADD-v1","ADD",
    "Data Warehouse Platform — Architecture Design Document v1.0",
    "Application","Data","Approved","1.0",
    "ea.data","Internal","2024-09-01","2025-09-01",
    "Architecture Design Document สำหรับ Data Warehouse Platform (APP-020) ครอบคลุม Modern Data Architecture, Data Lakehouse, ETL Pipeline และ BI Integration",
    content="""# Data Warehouse Platform — Architecture Design Document
**Code:** APP-020-ADD-v1 | **Application:** APP-020 Data Warehouse Platform | **Version:** 1.0

## 1. Executive Summary
Data Warehouse Platform เป็นแกนกลางของ Enterprise Data Strategy รองรับ Analytics และ BI ขององค์กร ใช้ Modern Data Lakehouse Architecture บน Cloud

## 2. Business Context
- **Business Capabilities:** BCAP-030 (Data & Analytics), BCAP-010 (Financial Reporting)
- **Data Domains:** DDOM-013, DDOM-014, DDOM-015, DDOM-016, DDOM-017
- **Users:** 200 Data Analysts, 50 Data Scientists, 500 Business Users (via BI)

## 3. Architecture — Modern Data Lakehouse

```
[Source Systems]                    [Consumers]
Apps, ERP, CRM                      BI Tools, Analytics, ML
       ↓                                     ↑
[Ingestion Layer]               [Serving Layer]
 Kafka / CDC                     Data Mart / DW
 Batch ETL                       Query Engine
       ↓                                     ↑
[Storage Layer — Data Lake]
 Raw Zone → Curated Zone → Gold Zone
 (Object Storage S3-compatible)
       ↓
[Processing Layer]
 Apache Spark (Batch)
 Apache Flink (Streaming)
```

## 4. Technology Stack
| Layer | Technology | Notes |
|-------|-----------|-------|
| Ingestion | Apache Kafka | Real-time streaming |
| Storage | MinIO / S3 | Object Storage |
| Processing | Apache Spark | Batch & ML |
| Table Format | Delta Lake / Iceberg | ACID on Lake |
| BI | Power BI | Corporate standard |

## 5. Data Governance Integration
- ใช้ Data Catalog (STD-DAT-014) สำหรับ Metadata Management
- Data Lineage Tracking ผ่าน Apache Atlas
- Data Quality Monitoring ทุก Pipeline

## 6. ARB Decision Reference
- ARB Request: ARB-2024-0015
- Decision: Approved
"""),

doc("APP-042-ADD-v1","ADD",
    "API Management Platform — Architecture Design Document v1.0",
    "Application","Integration","In Review","1.0",
    "ea.integration","Internal","2025-01-01","2026-01-01",
    "Architecture Design Document สำหรับ API Management Platform (APP-042) ครอบคลุม API Gateway, Developer Portal, API Lifecycle Management และ Security",
    content="""# API Management Platform — Architecture Design Document
**Code:** APP-042-ADD-v1 | **Application:** APP-042 | **Version:** 1.0 | **Status:** In Review

## 1. Executive Summary
API Management Platform เป็น Central Hub สำหรับ API ทั้งหมดขององค์กร รองรับทั้ง Internal, Partner และ Public APIs

## 2. Architecture Overview
```
[API Consumers]
External / Partner / Internal
       ↓
[API Gateway Cluster]
Kong Enterprise (Active-Active)
  ├── Authentication (OAuth2/API Key)
  ├── Rate Limiting
  ├── Request Routing
  ├── Logging & Analytics
  └── Caching
       ↓
[Backend Services]
Internal Microservices / Legacy Systems
```

## 3. Key Capabilities
- **API Gateway:** Kong Enterprise — Central Entry Point
- **Developer Portal:** Kong Dev Portal — API Discovery, Self-service Key
- **API Analytics:** Realtime Dashboard, SLO Monitoring
- **API Security:** OAuth2, mTLS, JWT Validation

## 4. Technology Stack
| Component | Technology | Standard Status |
|-----------|-----------|-----------------|
| API Gateway | Kong Enterprise | Approved |
| Service Mesh | Istio | Trial |
| Auth Server | Keycloak | Approved |

## 5. Integration Standards Applied
- STD-API-001: RESTful API Design
- STD-API-002: API Gateway Mandatory Routing
- STD-API-004: API Versioning Strategy
- STD-SEC-020: API Security Standard
"""),

doc("APP-061-ADD-v1","ADD",
    "CI/CD Pipeline Platform — Architecture Design Document v1.0",
    "Application","Platform","Approved","1.0",
    "ea.platform","Internal","2024-11-01","2025-11-01",
    "Architecture Design Document สำหรับ CI/CD Pipeline Platform (APP-061) ครอบคลุม GitOps, Build Pipeline, Container Registry และ Deployment Strategy",
    content="""# CI/CD Pipeline Platform — Architecture Design Document
**Code:** APP-061-ADD-v1 | **Application:** APP-061 | **Version:** 1.0

## 1. Executive Summary
CI/CD Pipeline Platform เป็นศูนย์กลาง DevOps ขององค์กร รองรับการ Build, Test และ Deploy อัตโนมัติสำหรับทุก Application

## 2. Pipeline Architecture
```
[Developer] → git push
       ↓
[GitLab CI/CD]
  ├── SAST (SonarQube)
  ├── SCA (Snyk)
  ├── Build & Unit Test
  ├── Container Build & Scan
  ├── Push to Registry (Harbor)
  └── Deploy to Kubernetes
       ↓
[Environments]
Dev → QA → Staging → Production
(GitOps via ArgoCD)
```

## 3. Technology Stack
| Component | Technology | Version |
|-----------|-----------|---------|
| SCM | GitLab | 16.x |
| CI | GitLab CI | - |
| Container Registry | Harbor | 2.x |
| CD/GitOps | ArgoCD | 2.x |
| K8s | Kubernetes | 1.29 |

## 4. Standards Applied
- STD-PLT-005: CI/CD Pipeline Standard
- STD-PLT-006: GitOps Deployment Model
- STD-SEC-007: Application Security (DevSecOps)
- STD-APP-003: Automated Testing Requirement
"""),

doc("APP-080-ADD-v1","ADD",
    "Identity & Access Management — Architecture Design Document v1.0",
    "Application","Security","Approved","2.0",
    "ea.security","Confidential","2025-01-01","2026-01-01",
    "Architecture Design Document สำหรับ IAM Platform (APP-080) ครอบคลุม SSO, MFA, PAM, Federation และ Zero Trust Identity",
    content="""# Identity & Access Management — Architecture Design Document
**Code:** APP-080-ADD-v1 | **Application:** APP-080 IAM Platform | **Version:** 2.0

## 1. Executive Summary
IAM Platform เป็น Foundation ของ Zero Trust Architecture ขององค์กร รองรับ Authentication และ Authorization สำหรับผู้ใช้งาน 5,000 คน และ 100+ Applications

## 2. IAM Architecture

```
[Users / Service Accounts]
       ↓
[Identity Provider — Microsoft Entra ID]
  ├── SSO / SAML / OAuth2 / OIDC
  ├── MFA (Microsoft Authenticator)
  └── Conditional Access Policies
       ↓
[Access Control Layer]
  ├── RBAC (Applications)
  ├── ABAC (Data Resources)
  └── PAM (CyberArk) — Privileged Accounts
       ↓
[Protected Resources]
Applications / Data / Infrastructure
```

## 3. ABB Coverage
| ABB | Capability | Solution |
|-----|-----------|---------|
| ABB-001 | Identity & Access Management | Microsoft Entra ID |
| ABB-002 | Privileged Access Management | CyberArk PAM |
| ABB-003 | Multi-Factor Authentication | Microsoft Authenticator |
| ABB-004 | Single Sign-On | Entra ID SSO |
| ABB-005 | Identity Federation | Entra ID B2B |

## 4. Standards Compliance
- STD-SEC-005: IAM Standard — ✅ Compliant
- STD-SEC-006: PAM — ✅ Compliant
- STD-SEC-001: Zero Trust — ✅ In Progress
- STD-SEC-023: MFA Policy — ✅ Compliant
"""),

# ── ARCHITECTURE DECISION RECORDS ─────────────────────────────────────────────

doc("APP-001-ADR-001","ADR",
    "ADR-001: Database Technology Selection for CRM System",
    "Application","Application","Accepted","1.0",
    "ea.team","Internal","2024-03-01","",
    "ตัดสินใจเลือก PostgreSQL เป็น Primary Database สำหรับ CRM System แทน Oracle เนื่องจาก Cost, Scalability และ Open Source Benefits",
    content="""# ADR-001: Database Technology Selection for CRM System
**Code:** APP-001-ADR-001 | **Date:** 2024-03-01 | **Status:** Accepted

## Context & Problem
CRM System ต้องการ Database ที่รองรับ:
- Transactional workload สูง (5,000 TPS)
- JSON/Semi-structured Data
- Full-text Search
- Cost ที่สมเหตุสมผล (Budget 5M THB/yr)

## Decision Drivers
- Total Cost of Ownership (TCO) ต้องไม่เกิน 5M THB/year
- ต้องรองรับ ACID Transaction
- ทีมมีความสามารถ (Skills) ในการดูแล
- Vendor Lock-in Risk ต้องต่ำ

## Considered Options
1. **Oracle Database 19c** — Enterprise, Feature-rich, Expensive
2. **PostgreSQL 16** — Open Source, Feature-rich, Cost-effective
3. **MySQL 8** — Open Source, Simple, Limited Features

## Decision Outcome
**Chosen Option: PostgreSQL 16**

เหตุผล:
- TCO ต่ำกว่า Oracle 80% (ประมาณ 800K vs 4M THB/yr)
- รองรับ JSON, Full-text Search, Partitioning อย่างครบถ้วน
- Active Community และ Long-term Support
- สอดคล้อง STD-INF-xxx (Technology Standard)

### Positive Consequences
- ✅ ประหยัดงบประมาณ ~3.2M THB/yr
- ✅ ลด Vendor Lock-in
- ✅ ทีม Dev มีประสบการณ์ PostgreSQL อยู่แล้ว

### Negative Consequences
- ⚠️ ต้องลงทุนใน DBA Training เพิ่มเติม
- ⚠️ บาง Oracle-specific Feature ต้องเขียน Workaround

## Links
- Related: STD-INF-xxx (Database Standard)
- Authorized by: ARB-2024-0001
"""),

doc("EA-ADR-SEC-001","ADR",
    "EA-ADR: Zero Trust Architecture Adoption Decision",
    "ESA","Security","Accepted","1.0",
    "ea.security","Confidential","2024-06-01","",
    "ตัดสินใจนำ Zero Trust Architecture มาใช้เป็น Security Model หลักขององค์กร แทน Perimeter-based Security",
    content="""# EA-ADR: Zero Trust Architecture Adoption Decision
**Code:** EA-ADR-SEC-001 | **Date:** 2024-06-01 | **Status:** Accepted | **Domain:** ESA

## Context & Problem
กลยุทธ์ขยาย Cloud Workload และ Remote Work ทำให้ Perimeter-based Security ไม่เพียงพอ:
- ผู้ใช้งาน Remote เพิ่มขึ้น 300%
- Cloud Resources อยู่นอก Traditional Network Perimeter
- Lateral Movement Attacks เป็นความเสี่ยงสำคัญ

## Decision Drivers
- Reduce Attack Surface จาก Lateral Movement
- รองรับ Cloud-first และ Remote Work Strategy
- ปฏิบัติตาม Regulatory Requirements (ISO27001, NIST)

## Considered Options
1. **Enhance Perimeter Defense** — เพิ่ม Firewall, VPN
2. **Zero Trust Architecture** — "Never Trust, Always Verify"
3. **Hybrid Approach** — Perimeter + Micro-segmentation

## Decision Outcome
**Chosen Option: Zero Trust Architecture (ZTA)**

ขั้นตอน Adoption:
- Phase 1: Identity (IAM + MFA) — 2024 Q3
- Phase 2: Device (EDR + MDM) — 2024 Q4
- Phase 3: Network (ZTNA) — 2025 Q1
- Phase 4: Application (Zero Trust App Access) — 2025 Q2

### Positive Consequences
- ✅ ลด Attack Surface อย่างมีนัยสำคัญ
- ✅ รองรับ Cloud และ Remote Work ได้ดีขึ้น

### Negative Consequences
- ⚠️ ต้องลงทุน Tools และ Training (30M THB)
- ⚠️ User Experience อาจกระทบในช่วงแรก

## Links
- Enforces: STD-SEC-001: Zero Trust Architecture
- Related: EA-POL-SEC-001
"""),

doc("APP-020-ADR-001","ADR",
    "ADR-001: Data Lakehouse Architecture vs Traditional Data Warehouse",
    "Application","Data","Accepted","1.0",
    "ea.data","Internal","2024-07-01","",
    "ตัดสินใจใช้ Modern Data Lakehouse Architecture (Delta Lake) แทน Traditional Data Warehouse (Snowflake/Redshift) สำหรับ Enterprise Data Platform",
    content="""# ADR-001: Data Lakehouse Architecture Selection
**Code:** APP-020-ADR-001 | **Date:** 2024-07-01 | **Status:** Accepted

## Context & Problem
Enterprise Data Platform ต้องรองรับ:
- Batch Analytics, Real-time Streaming, ML/AI Workloads
- ข้อมูลหลาย Format: Structured, Semi-structured, Unstructured
- Cost ที่ scale ได้ตาม Data Volume

## Considered Options
1. **Traditional Data Warehouse (Snowflake)** — Managed, SQL-centric, Expensive at Scale
2. **Data Lakehouse (Delta Lake + Spark)** — Open, Flexible, Multi-workload
3. **Cloud-native DW (BigQuery/Redshift)** — Vendor-specific, Managed

## Decision Outcome
**Chosen Option: Data Lakehouse (Delta Lake + Apache Spark)**

เหตุผล:
- รองรับ Batch + Streaming + ML ใน Single Architecture
- ACID Transaction บน Data Lake (Delta Lake)
- ไม่ Vendor Lock-in
- TCO ต่ำกว่า Snowflake 40% ที่ Scale ของเรา

### Positive Consequences
- ✅ Unified Platform สำหรับ Analytics และ ML
- ✅ ประหยัดงบ ~8M THB/yr เมื่อเทียบกับ Snowflake

### Negative Consequences
- ⚠️ ต้องใช้ Skill Spark/Kafka ที่องค์กรยังขาดอยู่ (Training Required)
"""),

doc("EA-ADR-PLT-001","ADR",
    "EA-ADR: Kubernetes as Standard Container Orchestration Platform",
    "ETA","Platform","Accepted","1.0",
    "ea.platform","Internal","2024-01-15","",
    "ตัดสินใจกำหนด Kubernetes เป็น Standard Container Orchestration Platform สำหรับทุก Application ที่ใช้ Container",
    content="""# EA-ADR: Kubernetes as Standard Container Orchestration
**Code:** EA-ADR-PLT-001 | **Date:** 2024-01-15 | **Status:** Accepted | **Domain:** ETA

## Context & Problem
องค์กรมี Container Workloads ที่กระจัดกระจายโดยใช้ Tool หลากหลาย:
- Docker Swarm (บางทีม)
- VM-based Deployment (ส่วนใหญ่)
- ไม่มี Standard ที่ชัดเจน

## Considered Options
1. **Docker Swarm** — Simple, แต่ Limited Features
2. **Kubernetes** — Complex, แต่ Ecosystem ครบและ Industry Standard
3. **Nomad (HashiCorp)** — Flexible, แต่ Community เล็กกว่า

## Decision Outcome
**Chosen Option: Kubernetes (K8s)**

- Industry Standard ที่ Skill หาได้ง่าย
- Ecosystem ครบ: Helm, ArgoCD, Istio, Prometheus
- รองรับ Multi-cloud (EKS/AKS/GKE/On-prem)
- สอดคล้อง STD-PLT-001, STD-PLT-008

### Migration Path
- Phase 1: New Projects ใช้ K8s — 2024 Q1
- Phase 2: Core Systems Migrate — 2024 Q2-Q4
- Phase 3: Decommission Docker Swarm — 2025 Q1

### Positive Consequences
- ✅ Standardized Platform ลด Operational Complexity
- ✅ Leverage Ecosystem Tools ที่มีอยู่แล้ว (Helm, ArgoCD)

### Negative Consequences
- ⚠️ Learning Curve สำหรับทีม Ops (Training Plan Required)
- ⚠️ ต้องลงทุน K8s Infrastructure และ Tooling

## Links
- Enforces: STD-PLT-001, STD-PLT-008
"""),

# ── TEMPLATES ─────────────────────────────────────────────────────────────────

doc("EA-TPL-ADD-001","Template",
    "Architecture Design Document (ADD) — Template",
    "Cross-domain","Governance","Approved","1.0",
    "ea.lead","Public","2025-01-01","2026-01-01",
    "Template มาตรฐานสำหรับการจัดทำ Architecture Design Document (ADD) — Copy แล้วแก้ไขตาม App ที่ต้องการ",
    content="""# [Application Name] — Architecture Design Document
**Code:** [APP-XXX-ADD-v1.0] | **Application:** [APP-XXX] | **Version:** 1.0 | **Status:** Draft | **Owner:** [EA Team]

> **คำแนะนำ:** Copy Template นี้ สร้าง Document ใหม่ด้วย Code แบบ `APP-XXX-ADD-v1.0` แล้วแก้ไขแต่ละ Section

---

## 1. Executive Summary
[สรุปสถาปัตยกรรมของระบบในภาพรวม 3-5 ประโยค — วัตถุประสงค์ ขอบเขต และ Key Architecture Decisions]

## 2. System Overview & Business Context
- **Business Purpose:** [วัตถุประสงค์ทางธุรกิจ]
- **Business Capabilities Supported:** [BCAP-xxx, BCAP-yyy]
- **Application Classification:** [Core/High/Medium/Low — Critical/Non-Critical]
- **Key Stakeholders:** [Business Owner, IT Owner]
- **User Base:** [จำนวนและประเภทผู้ใช้งาน]

## 3. Architecture Goals & Constraints
### Quality Attributes
| Attribute | Requirement | Target |
|-----------|-------------|--------|
| Availability | [SLA %] | [Measurement] |
| Response Time | [ms] | [p95/p99] |
| Scalability | [Concurrent Users] | [Peak] |
| Data Retention | [Period] | [Requirement] |

### Architecture Principles Applied
- [STD-xxx]: [ชื่อ Standard]
- [STD-yyy]: [ชื่อ Standard]

### Constraints
- [Budget, Timeline, Technology, Regulatory]

## 4. Logical Architecture
```
[วาด Diagram Text-based หรืออธิบาย Layer Structure]

[Presentation Layer]
       ↓
[API/Application Layer]
       ↓
[Data Layer]
```

### Component Description
| Component | Technology | Responsibility |
|-----------|-----------|----------------|
| [Component A] | [Tech] | [หน้าที่] |

## 5. Data Architecture
- **Data Domains Involved:** [DDOM-xxx]
- **PII Data:** Yes/No — [รายละเอียดถ้ามี]
- **Data Classification:** [Public/Internal/Confidential/Restricted]
- **Data Flow:** [อธิบายการไหลของข้อมูล]

## 6. Integration Architecture
| System | Direction | Protocol | Description |
|--------|-----------|----------|-------------|
| [System A] | Inbound/Outbound | [REST/Event/File] | [คำอธิบาย] |

## 7. Security Architecture
- **Authentication:** [วิธีการ]
- **Authorization:** [RBAC/ABAC Model]
- **ABB Coverage:** [ABB-xxx, ABB-yyy]
- **Security Standards Applied:** [STD-SEC-xxx]
- **Compliance Frameworks:** [PDPA/ISO27001/PCI-DSS]

## 8. Technology Stack
| Category | Technology | Version | Standard Status |
|----------|-----------|---------|-----------------|
| Language | [Language] | [ver] | Approved/Trial |
| Framework | [Framework] | [ver] | Approved/Trial |
| Database | [DB] | [ver] | Approved/Trial |
| Infrastructure | [Platform] | [ver] | Approved/Trial |

## 9. Deployment Architecture
- **Deployment Model:** Cloud/On-Premise/Hybrid
- **Environments:** Dev/QA/UAT/Production/DR
- **DR Strategy:** [RTO/RPO targets]
- **Backup:** [Strategy]
- **Scaling:** [Auto-scaling approach]

## 10. Risks & Open Issues
| Risk/Issue | Severity | Status | Mitigation |
|------------|----------|--------|------------|
| [Risk 1] | High | Open | [Mitigation] |

## 11. ARB Decision Reference
- ARB Request: [ARB-YYYY-NNNN]
- Decision: [Approved/Conditionally Approved]
- Key Conditions: [รายการ Conditions]

## 12. Change History
| Version | Date | Changed By | Summary |
|---------|------|------------|---------|
| 1.0 | [DATE] | [Author] | Initial draft |
"""),

doc("EA-TPL-ADR-001","Template",
    "Architecture Decision Record (ADR) — Template",
    "Cross-domain","Governance","Approved","1.0",
    "ea.lead","Public","2025-01-01","2026-01-01",
    "Template สำหรับการจัดทำ Architecture Decision Record (ADR) — ใช้เมื่อต้องบันทึกการตัดสินใจด้านสถาปัตยกรรม",
    content="""# [Decision Title]
**Code:** [APP-XXX-ADR-NNN หรือ EA-ADR-DOMAIN-NNN] | **Date:** [DATE] | **Status:** [Proposed/Accepted/Deprecated/Superseded]

> **เมื่อใดควรทำ ADR:** เมื่อต้องตัดสินใจด้าน Technology, Architecture Pattern หรือ Design ที่มีผลกระทบระยะยาว

---

## Context & Problem
[อธิบาย Context ที่นำไปสู่การตัดสินใจ — ทำไมต้องตัดสินใจ, ข้อจำกัดที่มี]

## Decision Drivers
- [ปัจจัยที่ 1 — เช่น Cost, Performance, Security]
- [ปัจจัยที่ 2]
- [ปัจจัยที่ 3]

## Considered Options
1. **Option A — [ชื่อตัวเลือก]**: [คำอธิบายสั้น]
2. **Option B — [ชื่อตัวเลือก]**: [คำอธิบายสั้น]
3. **Option C — [ชื่อตัวเลือก]**: [คำอธิบายสั้น]

## Decision Outcome
**Chosen Option: [Option X]** — [เหตุผลหลักที่เลือก]

### Positive Consequences
- ✅ [ผลดีที่ 1]
- ✅ [ผลดีที่ 2]

### Negative Consequences / Trade-offs
- ⚠️ [Trade-off ที่ยอมรับได้ที่ 1]
- ⚠️ [Trade-off ที่ 2]

## Pros and Cons of Each Option

### Option A
- ✅ Pro 1
- ✅ Pro 2
- ❌ Con 1

### Option B
- ✅ Pro 1
- ❌ Con 1
- ❌ Con 2

### Option C
- ✅ Pro 1
- ❌ Con 1

## Implementation Notes
[ขั้นตอนหรือ Action Items หลังการตัดสินใจ]

## Links
- Supersedes: [ADR เดิม ถ้ามี]
- Implements: [Policy/Standard ที่เกี่ยวข้อง]
- Authorized by: [ARB Decision ถ้ามี]
"""),

]

# ── SEED ─────────────────────────────────────────────────────────────────────
def seed():
    with conn_ea() as c:
        # Apply DDL if tables don't exist yet
        c.execute("""CREATE TABLE IF NOT EXISTS ea_documents (
            id TEXT PRIMARY KEY, doc_code TEXT UNIQUE NOT NULL, doc_type TEXT NOT NULL,
            title TEXT NOT NULL, version TEXT DEFAULT '1.0', status TEXT DEFAULT 'Draft',
            domain TEXT DEFAULT '', category TEXT DEFAULT '', scope TEXT DEFAULT '',
            summary TEXT DEFAULT '', content TEXT DEFAULT '',
            confidentiality TEXT DEFAULT 'Internal', owner TEXT DEFAULT '',
            approved_by TEXT DEFAULT '', effective_date TEXT DEFAULT '',
            review_date TEXT DEFAULT '', expiry_date TEXT DEFAULT '',
            tags TEXT DEFAULT '[]', created_by TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS ea_doc_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT NOT NULL,
            version TEXT NOT NULL, change_summary TEXT DEFAULT '',
            content_snapshot TEXT DEFAULT '', status_snapshot TEXT DEFAULT '',
            changed_by TEXT DEFAULT '', changed_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS ea_doc_sections (
            id TEXT PRIMARY KEY, doc_id TEXT NOT NULL,
            section_no TEXT NOT NULL, title TEXT NOT NULL,
            content TEXT DEFAULT '', order_idx INTEGER DEFAULT 0)""")
        c.commit()

        existing = {r[0] for r in c.execute("SELECT doc_code FROM ea_documents").fetchall()}
        inserted = 0
        skipped = 0

        for d in DOCS:
            if d["doc_code"] in existing:
                skipped += 1
                continue
            c.execute("""INSERT INTO ea_documents
                (id,doc_code,doc_type,title,version,status,domain,category,scope,summary,content,
                 confidentiality,owner,approved_by,effective_date,review_date,expiry_date,tags,created_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["id"],d["doc_code"],d["doc_type"],d["title"],d["version"],d["status"],
                 d["domain"],d["category"],d["scope"],d["summary"],d["content"],
                 d["confidentiality"],d["owner"],d["approved_by"],
                 d["effective_date"],d["review_date"],d["expiry_date"],
                 d["tags"],d["created_by"],d["created_at"],d["updated_at"]))
            inserted += 1

        c.commit()

        # Seed repo_links for Documents → Applications
        app_links = [
            ("APP-001-ADD-v1", "APP-001"),
            ("APP-020-ADD-v1", "APP-020"),
            ("APP-042-ADD-v1", "APP-042"),
            ("APP-061-ADD-v1", "APP-061"),
            ("APP-080-ADD-v1", "APP-080"),
            ("APP-001-ADR-001", "APP-001"),
            ("APP-020-ADR-001", "APP-020"),
        ]
        doc_codes = {r[0]:r[1] for r in c.execute("SELECT doc_code, id FROM ea_documents").fetchall()}
        std_links = [
            ("EA-POL-GOV-001", "STD-GOV-003"), ("EA-POL-GOV-001", "STD-GOV-014"),
            ("EA-POL-SEC-001", "STD-SEC-001"), ("EA-POL-SEC-001", "STD-SEC-002"),
            ("EA-POL-SEC-001", "STD-SEC-005"), ("EA-POL-DAT-001", "STD-DAT-001"),
            ("EA-POL-DAT-001", "STD-DAT-003"), ("EA-POL-CLD-001", "STD-CLD-001"),
            ("EA-POL-CLD-001", "STD-CLD-004"), ("EA-POL-API-001", "STD-API-001"),
            ("EA-GDL-API-001", "STD-API-001"), ("EA-GDL-CLD-001", "STD-PLT-001"),
            ("EA-GDL-SEC-001", "STD-SEC-007"), ("EA-GDL-SEC-001", "STD-SEC-012"),
        ]

        existing_links = set()
        for r in c.execute("SELECT src_type||'|'||src_id||'|'||dst_type||'|'||dst_id||'|'||link_type FROM repo_links").fetchall():
            existing_links.add(r[0])

        link_inserted = 0
        import uuid as _uuid

        def try_link(src_type, src_id, dst_type, dst_id, link_type, strength="Primary", note=""):
            key = f"{src_type}|{src_id}|{dst_type}|{dst_id}|{link_type}"
            if key in existing_links: return
            existing_links.add(key)
            c.execute("""INSERT OR IGNORE INTO repo_links(id,src_type,src_id,dst_type,dst_id,link_type,strength,note,created_by,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                      (str(_uuid.uuid4()), src_type, src_id, dst_type, dst_id, link_type, strength, note, "ea.admin", NOW, NOW))
            nonlocal link_inserted
            link_inserted += 1

        for doc_code, app_id in app_links:
            doc_id = doc_codes.get(doc_code)
            if doc_id:
                lt = "Describes" if "ADD" in doc_code else "Decides-for"
                try_link("Document", doc_id, "Application", app_id, lt, "Primary", f"{doc_code} → {app_id}")

        for doc_code, std_code in std_links:
            doc_id = doc_codes.get(doc_code)
            std = c.execute("SELECT id FROM repo_standards WHERE code=?", (std_code,)).fetchone()
            if doc_id and std:
                try_link("Document", doc_id, "ArchitectureStandard", std[0], "Enforces", "Primary", f"{doc_code} enforces {std_code}")

        c.commit()

        # Summary
        total = c.execute("SELECT COUNT(*) FROM ea_documents").fetchone()[0]
        type_counts = {r[0]:r[1] for r in c.execute("SELECT doc_type, COUNT(*) FROM ea_documents GROUP BY doc_type").fetchall()}
        print(f"\n✅ EA Document Library Seeded")
        print(f"   Inserted: {inserted} | Skipped (existing): {skipped}")
        print(f"   Total documents: {total}")
        for t,cnt in sorted(type_counts.items()):
            print(f"   {DOC_TYPE_ICON.get(t,'📄')} {t}: {cnt}")
        print(f"   Links added: {link_inserted}")

DOC_TYPE_ICON = {'Policy':'🏛️','Procedure':'📋','Guideline':'💡','ADD':'🏗️','ADR':'🔑','Template':'📝','Runbook':'🚨'}

if __name__ == "__main__":
    print(f"Seeding EA Documents into: {EA_DB}")
    seed()
    print("\nDone!")
