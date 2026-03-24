"""
Seed 150 Architecture Standards — ครอบคลุมทุก category
รัน: python3 seed_standards.py
DB:  ea_domains.db
"""
import sqlite3, uuid, json
from datetime import datetime

EA_DB = "ea_domains.db"

def uid(): return "STD-" + uuid.uuid4().hex[:6].upper()
def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─────────────────────────────────────────────────────────────────────────────
# Format: (code, category, title, description, rationale, guidance, status, version, owner, eff_date, review_date)
# ─────────────────────────────────────────────────────────────────────────────
ALL_STANDARDS = [

  # ══════════════════════════════════════════════════════════════════
  # SECURITY  (25 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-SEC-001","Security","Zero Trust Architecture",
   "ทุก request ต้องผ่านการ authenticate และ authorize โดยไม่ไว้วางใจ network ภายในโดยปริยาย",
   "ลด attack surface จาก insider threat และ lateral movement",
   "ใช้ Identity-aware proxy, MFA, Least-privilege access, Micro-segmentation",
   "Active","1.2","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-002","Security","Data Encryption at Rest and in Transit",
   "ข้อมูล sensitive ต้องเข้ารหัสทั้งขณะเก็บ (AES-256) และขณะส่ง (TLS 1.3+)",
   "ป้องกันการรั่วไหลของข้อมูลเมื่อ medium ถูกเข้าถึงโดยไม่ได้รับอนุญาต",
   "ใช้ KMS สำหรับ key management, ห้ามใช้ TLS < 1.2 โดยเด็ดขาด",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-003","Security","Secret & Credential Management",
   "ห้ามฝัง secret, password, API key ใน source code หรือ config file",
   "ป้องกัน credential exposure ใน version control และ log files",
   "ใช้ HashiCorp Vault หรือ Kubernetes Secrets เท่านั้น, บังคับ secret rotation ทุก 90 วัน",
   "Active","1.1","Platform Team","2025-01-01","2026-12-31"),

  ("STD-SEC-004","Security","Vulnerability Management & Patching",
   "ทุก system ต้อง patch security vulnerability ภายใน SLA: Critical=24h, High=7d, Medium=30d",
   "ลดช่วงเวลาที่ระบบเปิดรับการโจมตีจาก known CVEs",
   "ใช้ automated scanning ทุก sprint, ต้อง sign-off จาก CISO ก่อน deploy ถ้ามี unpatched Critical",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-005","Security","Identity & Access Management (IAM) Standard",
   "ทุก system ต้องใช้ centralized IAM สำหรับ authentication และ authorization",
   "ป้องกัน account sprawl และ enforce consistent access policy",
   "ใช้ SSO ผ่าน Identity Platform, บังคับ MFA สำหรับ privileged access, review access ทุก 6 เดือน",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-006","Security","Privileged Access Management (PAM)",
   "Privileged account ต้องผ่าน PAM solution ทุกครั้ง ห้าม share credential",
   "ลด risk จาก compromised privileged account ซึ่งมี blast radius สูง",
   "ใช้ just-in-time access, session recording, ต้องมี approval workflow สำหรับ admin access",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-007","Security","Application Security (DevSecOps)",
   "Security ต้องถูก embed เข้าใน SDLC ทุกขั้นตอน — SAST, DAST, SCA บังคับก่อน release",
   "ค้นพบและแก้ security issue ตั้งแต่ต้น development lifecycle มี cost ต่ำกว่า production fix",
   "SAST ใน CI pipeline, DAST ใน staging, SCA สำหรับ 3rd-party library, OWASP Top 10 review",
   "Active","1.1","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-008","Security","Network Segmentation & Micro-segmentation",
   "Network ต้องแบ่ง zone ตาม trust level: DMZ, Internal, Restricted, Management",
   "จำกัด blast radius เมื่อเกิด breach และ enforce least-privilege network access",
   "ใช้ firewall rules + service mesh mTLS สำหรับ east-west, WAF สำหรับ north-south",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-009","Security","Security Logging & SIEM Integration",
   "ทุก critical system ต้องส่ง security event ไปยัง SIEM ใน near-real-time",
   "Enable threat detection, incident investigation, และ compliance reporting",
   "Log format: CEF/Syslog, Retention: minimum 1 ปี, Alert: SIEM rule สำหรับ MITRE ATT&CK patterns",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-010","Security","Penetration Testing Requirement",
   "ระบบ Tier 1 และ Tier 2 ต้องทำ penetration test อย่างน้อยปีละครั้ง",
   "ค้นพบ vulnerability ที่ automated tool ไม่สามารถตรวจพบได้",
   "ใช้ certified penetration tester, scope ครอบคลุม web/API/infra, remediate ภายใน 30 วัน",
   "Active","1.0","CISO Office","2025-06-01","2026-12-31"),

  ("STD-SEC-011","Security","Endpoint Security Standard",
   "ทุก endpoint (server, workstation, mobile) ต้องมี EDR agent และผ่าน compliance check",
   "ป้องกัน malware, ransomware, และ unauthorized access จาก endpoint",
   "บังคับ EDR, disk encryption, auto-lock, OS patch SLA เหมือน server",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-012","Security","Secure Software Development Lifecycle (SSDLC)",
   "ทุก software development project ต้องปฏิบัติตาม SSDLC framework",
   "Embed security ใน requirements, design, code, test, deploy ทุกขั้นตอน",
   "Security requirements ใน user story, threat modeling ใน design, security test ใน QA",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-013","Security","Third-Party & Supply Chain Security",
   "ทุก third-party component และ vendor ต้องผ่าน security assessment ก่อน onboard",
   "ลด supply chain risk จาก compromised vendor หรือ open-source library",
   "SCA สำหรับ open-source, vendor security questionnaire, contractual security obligation",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-014","Security","Data Loss Prevention (DLP)",
   "ข้อมูล Confidential และ Restricted ต้องถูก monitor และป้องกันการรั่วไหลด้วย DLP policy",
   "ตรวจจับและป้องกัน unauthorized data exfiltration",
   "DLP rules สำหรับ email, cloud storage, USB, กำหนด classification label ทุก document",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-015","Security","Incident Response & Business Continuity",
   "ต้องมี Incident Response Plan และทดสอบ tabletop exercise อย่างน้อยปีละครั้ง",
   "ลด MTTR และ business impact เมื่อเกิด security incident",
   "กำหนด RACI, escalation path, communication plan, forensic evidence preservation",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-016","Security","Cryptographic Standards",
   "ระบบต้องใช้เฉพาะ cryptographic algorithm ที่ได้รับอนุมัติ: AES-256, RSA-2048+, SHA-256+",
   "ป้องกันการใช้ algorithm ที่ถูก break แล้วเช่น MD5, SHA-1, DES",
   "ห้ามใช้ deprecated algorithm, กำหนด key rotation period, ใช้ FIPS-compliant library",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-017","Security","Security Architecture Review Requirement",
   "ระบบใหม่ที่มี criticality High+ ต้องผ่าน Security Architecture Review ก่อน go-live",
   "ตรวจสอบ security design ก่อน implementation ลด cost ของ rework",
   "Submit security design document, threat model, และ control mapping ต่อ CISO Office",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-018","Security","Web Application Firewall (WAF) Requirement",
   "ทุก web application ที่ expose สู่ internet ต้องมี WAF protection",
   "ป้องกัน OWASP Top 10 attacks: SQLi, XSS, CSRF, และ DDoS",
   "WAF ต้องอยู่ใน block mode, update rule set ทุก 2 สัปดาห์, monitor false positive",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-019","Security","Certificate & PKI Management",
   "ทุก TLS certificate ต้องออกโดย approved CA และมี validity ≤ 1 ปี",
   "ป้องกัน expired certificate และ man-in-the-middle attack",
   "ใช้ automated certificate renewal (cert-manager), alert 30 วันก่อน expiry",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-020","Security","API Security Standard",
   "ทุก API ต้องมี authentication (OAuth2/JWT), rate limiting, input validation",
   "ป้องกัน OWASP API Security Top 10",
   "ห้าม API key ใน URL parameter, บังคับ HTTPS, validate schema ทุก request",
   "Active","1.1","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-021","Security","Container & Kubernetes Security",
   "Container image ต้องผ่าน security scan, ห้าม run as root, กำหนด resource limits",
   "ลด attack surface ใน containerized workloads",
   "Scan image ใน CI/CD, ใช้ read-only filesystem, Network Policy บังคับ, Pod Security Standard",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-022","Security","Backup & Recovery Security",
   "Backup ต้องเข้ารหัส, ทดสอบ restore ทุกไตรมาส, เก็บ offsite copy",
   "ป้องกัน backup data breach และรับประกัน recoverability",
   "Encrypt backup with separate key, immutable backup storage, RTO/RPO test documentation",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-023","Security","Multi-Factor Authentication (MFA) Policy",
   "MFA บังคับสำหรับ: privileged access, remote access, sensitive application, admin console",
   "ลด risk จาก credential compromise — MFA ป้องกันได้ ~99% ของ automated attacks",
   "ใช้ TOTP หรือ hardware key, ห้าม SMS OTP สำหรับ privileged, bypass ต้องมี approval",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-024","Security","Security Compliance & Audit",
   "ระบบ Tier 1 ต้องผ่าน compliance audit ตาม framework ที่กำหนด: ISO27001, PDPA, PCI-DSS",
   "รักษา regulatory compliance และ build customer trust",
   "Annual audit, evidence collection, remediation tracking, ผล audit รายงานต่อ Board",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-SEC-025","Security","Secure Remote Access Standard",
   "ทุก remote access ต้องผ่าน VPN หรือ Zero Trust Network Access (ZTNA) พร้อม MFA",
   "ป้องกัน unauthorized access จาก unmanaged network",
   "ห้าม RDP/SSH direct internet, ใช้ bastion host หรือ ZTNA, session timeout 8 ชั่วโมง",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # API  (15 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-API-001","API","RESTful API Design Standard",
   "API ใหม่ทุกตัวต้องออกแบบตาม REST principles พร้อม OpenAPI 3.0 spec",
   "สร้าง consistency ของ developer experience และลดเวลา integration",
   "ใช้ noun-based resource URL, HTTP verbs, versioning (/v1/), pagination, error format RFC7807",
   "Active","2.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-002","API","API Gateway Mandatory Routing",
   "ทุก external API call ต้องผ่าน API Gateway — ห้าม expose service โดยตรงสู่ internet",
   "Central point สำหรับ auth, rate-limit, logging, และ circuit breaker",
   "ใช้ Kong Gateway เป็น standard, กำหนด rate limit ตาม consumer tier",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-003","API","Async-First Event Architecture",
   "การ communicate ระหว่าง microservices ที่ไม่ต้องการ immediate response ให้ใช้ async messaging",
   "ลด coupling, เพิ่ม resilience, รองรับ high-throughput",
   "ใช้ Apache Kafka เป็น standard message broker, กำหนด schema ด้วย Avro/JSON Schema",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-API-004","API","API Versioning Strategy",
   "ทุก API ต้องมี versioning strategy ที่ชัดเจน — URI versioning เป็น default (/v1/)",
   "ป้องกัน breaking change กระทบ consumer ที่ยังไม่ upgrade",
   "Support N-1 version minimum 12 เดือน, deprecation notice 6 เดือนล่วงหน้า, changelog บังคับ",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-005","API","API Rate Limiting & Throttling",
   "ทุก public API ต้องมี rate limit ตาม consumer tier เพื่อป้องกัน abuse",
   "ป้องกัน DDoS, fair usage, และ protect backend service",
   "กำหนด tier: Free=100/min, Standard=1000/min, Premium=10000/min, return 429 with Retry-After",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-006","API","API Documentation Standard",
   "ทุก API ต้องมี documentation ครบถ้วนใน developer portal ก่อน publish",
   "ลดเวลา onboarding developer และ support ticket",
   "OpenAPI spec + example request/response + error codes + changelog + sandbox environment",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-007","API","GraphQL Design Guideline",
   "GraphQL API ต้องมี schema design review, depth limit, และ complexity analysis",
   "ป้องกัน over-fetching, N+1 query, และ DoS จาก complex query",
   "กำหนด max depth=5, max complexity=100, ใช้ DataLoader สำหรับ batching",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-API-008","API","API Error Handling Standard",
   "ทุก API ต้องใช้ standard error format (RFC7807 Problem Details) และ HTTP status code ที่ถูกต้อง",
   "ลด debugging time และ improve developer experience",
   "ห้าม return 200 สำหรับ error, ต้องมี error code, message, detail field, correlation ID",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-009","API","API Contract Testing",
   "ทุก API integration ต้องมี contract test (Consumer-Driven Contract) ใน CI/CD",
   "ตรวจจับ breaking change ก่อน deployment กระทบ consumer จริง",
   "ใช้ Pact framework, contract เก็บใน Pact Broker, ต้อง pass ก่อน merge",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-API-010","API","Webhook Design Standard",
   "Webhook ต้องมี signature verification, retry mechanism, และ idempotent handler",
   "ป้องกัน replay attack และ ensure delivery ใน unreliable network",
   "ใช้ HMAC-SHA256 signature, exponential backoff retry, idempotency key บังคับ",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-011","API","API Deprecation Policy",
   "API ที่จะ deprecated ต้องแจ้ง consumer ล่วงหน้า 6 เดือนพร้อม migration guide",
   "ให้เวลา consumer plan migration และป้องกัน service disruption",
   "ส่ง email notification, เพิ่ม Deprecation header, sunset date ใน OpenAPI spec",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-012","API","Internal API Governance",
   "Internal API ต้องลงทะเบียนใน API registry และผ่าน architecture review",
   "ป้องกัน API sprawl, duplicate functionality, และ สร้าง reuse",
   "เช็ค API registry ก่อนสร้างใหม่, กำหนด owner, SLA, และ lifecycle",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-API-013","API","API Observability & SLO",
   "ทุก API ต้องมี SLO กำหนดและ monitor: availability ≥ 99.9%, p99 latency < 500ms",
   "ให้ visibility ของ API health และ trigger improvement เมื่อ SLO breach",
   "Dashboard per API, error budget tracking, alert เมื่อ burn rate สูง",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-API-014","API","Idempotency Design for Mutating APIs",
   "API ที่ mutate state (POST, PUT, DELETE) ต้องรองรับ idempotent operation",
   "ป้องกัน duplicate side-effect จาก retry ใน unreliable network",
   "ใช้ Idempotency-Key header, store key 24 ชั่วโมง, return same response สำหรับ duplicate",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-API-015","API","API Performance Standard",
   "API response time: p50 < 100ms, p95 < 300ms, p99 < 1000ms สำหรับ synchronous call",
   "ให้ user experience ที่ดีและรองรับ high-throughput",
   "Load test บังคับก่อน go-live, implement caching strategy, pagination สำหรับ list endpoint",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # DATA  (20 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-DAT-001","Data","Data Classification & Handling Policy",
   "ข้อมูลทุกชุดต้องมี classification: Public / Internal / Confidential / Restricted",
   "กำหนดมาตรการป้องกันที่เหมาะสมกับความสำคัญของข้อมูล",
   "Restricted = encrypt + audit log + MFA, ห้ามเก็บใน local storage / personal device",
   "Active","1.3","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-002","Data","Master Data Management Standard",
   "ข้อมูล master (Customer, Product, Employee) ต้องมี single source of truth และใช้ MDM system",
   "ป้องกัน data inconsistency ข้ามระบบและลด data reconciliation effort",
   "ห้าม duplicate master data ใน application DB, ต้อง subscribe จาก MDM API เท่านั้น",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-003","Data","PII Data Minimization",
   "เก็บ PII เฉพาะที่จำเป็นตามวัตถุประสงค์ที่ระบุ, ลบเมื่อพ้นระยะเวลาที่กำหนด",
   "ปฏิบัติตาม PDPA และลด liability จากการรั่วไหลของข้อมูลส่วนบุคคล",
   "ทำ PII inventory ทุก 6 เดือน, บังคับ data retention policy, anonymize ใน non-prod",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-004","Data","Data Quality Framework",
   "ข้อมูลที่ใช้ใน decision-making ต้องผ่าน quality gate: Completeness, Accuracy, Timeliness",
   "ข้อมูลไม่ดีนำไปสู่การตัดสินใจผิดพลาด — quality เป็น enabler ของ analytics",
   "กำหนด DQ metrics per domain, monitor ด้วย automated pipeline, escalate เมื่อต่ำกว่า threshold",
   "Active","1.1","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-005","Data","Data Retention & Archival Policy",
   "ข้อมูลทุกประเภทต้องมี retention period ที่กำหนด และ archived หรือ deleted ตาม schedule",
   "ปฏิบัติตาม regulatory requirement และลด storage cost",
   "Financial: 7 ปี, HR: 5 ปี, Customer: per PDPA, Log: 1 ปี, archive ไปยัง cold storage",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-006","Data","Data Lineage & Provenance",
   "ข้อมูลที่ใช้ใน reporting และ analytics ต้องมี lineage tracking ว่ามาจากที่ใด",
   "รองรับ audit, debugging, impact analysis เมื่อ upstream data เปลี่ยน",
   "ใช้ data catalog พร้อม lineage graph, document transformation logic, tag source system",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-007","Data","Data Access Control",
   "การ access ข้อมูลต้องใช้ RBAC หรือ ABAC ตาม data classification",
   "ป้องกัน unauthorized data access และ enforce need-to-know principle",
   "Restricted data: individual approval per access, audit log ทุก query, re-certify ทุก 3 เดือน",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-008","Data","Real-Time Data Streaming Standard",
   "Streaming data pipeline ต้องใช้ Apache Kafka เป็น standard backbone",
   "สร้าง reuse และ interoperability ระหว่าง data producer และ consumer",
   "กำหนด topic naming convention, schema registry บังคับ, consumer group ต้องมี owner",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-009","Data","Data Anonymization & Pseudonymization",
   "ข้อมูลส่วนบุคคลใน non-production environment ต้องถูก anonymize หรือ pseudonymize",
   "ป้องกัน PII exposure ใน dev/test environment",
   "ห้ามใช้ production PII ใน lower env โดยไม่ anonymize, ใช้ synthetic data สำหรับ test",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-010","Data","Database Design Standard",
   "Database schema ต้อง normalize ถึง 3NF เป็น minimum, มี FK constraints, index strategy",
   "ป้องกัน data anomaly, เพิ่ม query performance, และ enforce referential integrity",
   "กำหนด naming convention, ห้าม EAV pattern สำหรับ structured data, document ERD บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-DAT-011","Data","Data Backup & Recovery Standard",
   "ข้อมูล production ต้องมี backup ตาม RPO: Tier1=1h, Tier2=4h, Tier3=24h",
   "รับประกัน business continuity และ data recoverability",
   "Automated daily backup, weekly full, monthly archive, test restore ทุกไตรมาส",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-012","Data","Data Governance Framework",
   "ต้องมี Data Owner, Data Steward, และ Data Custodian สำหรับทุก data domain",
   "กำหนด accountability และ responsibility สำหรับ data quality และ compliance",
   "Data Owner=Business, Steward=Operations, Custodian=IT, ประชุม data governance ทุกเดือน",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-013","Data","API-Based Data Access",
   "การ access data ระหว่าง application ต้องผ่าน API ไม่ใช่ direct DB connection",
   "ป้องกัน tight coupling และ enforce access control ที่ application layer",
   "ห้าม shared DB user ข้าม application, ใช้ data service API แทน, exception ต้องมี approval",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-DAT-014","Data","Data Catalog & Metadata Management",
   "ทุก data asset ต้องลงทะเบียนใน data catalog พร้อม metadata: owner, classification, lineage",
   "ให้ data consumer ค้นหาและเข้าใจ data ได้โดยไม่ต้องถามทีม IT",
   "ใช้ centralized data catalog, metadata update ใน CI/CD, business glossary บังคับ",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-015","Data","Cross-Border Data Transfer Policy",
   "การส่งข้อมูลส่วนบุคคลข้ามประเทศต้องผ่าน legal review และได้รับ approval",
   "ปฏิบัติตาม PDPA ที่กำหนดว่าประเทศปลายทางต้องมีมาตรฐาน data protection เทียบเท่า",
   "กำหนด whitelist ประเทศ, ต้องมี DPA agreement, log การส่งข้อมูล",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-016","Data","Data Mesh Architecture Principle",
   "Data domain ต้องมี self-serve data product ที่ดูแลโดย domain team เอง",
   "กระจาย responsibility ลด bottleneck ของ central data team",
   "Domain team เป็น owner ของ data product, กำหนด SLO, publish ไปยัง data catalog",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-017","Data","Structured vs Unstructured Data Standard",
   "เลือก storage technology ตามประเภทข้อมูล: RDBMS, NoSQL, Object Store, Data Lake",
   "ป้องกันการใช้ technology ไม่เหมาะสมกับ data pattern",
   "Structured/Transactional=RDBMS, Semi-structured=MongoDB, Large Analytics=ClickHouse/S3",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-DAT-018","Data","Data Observability Standard",
   "ต้องมี monitoring สำหรับ data pipeline: freshness, volume, schema, quality",
   "ตรวจจับ data incident ก่อนกระทบ downstream consumer",
   "Alert เมื่อ freshness เกิน SLA, volume anomaly, schema drift, quality score ต่ำกว่า threshold",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-019","Data","Consent Management Standard",
   "ระบบที่เก็บ PII ต้องมี consent management สำหรับการ track และจัดการ consent ของ data subject",
   "ปฏิบัติตาม PDPA — data subject มีสิทธิ์ withdraw consent ได้ทุกเมื่อ",
   "เก็บ consent log, รองรับ right to erasure, granular consent per purpose",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-DAT-020","Data","Data Sharing Agreement",
   "การแชร์ข้อมูลกับ external party ต้องมี Data Sharing Agreement ที่ลงนามก่อน",
   "กำหนด legal framework, ป้องกัน liability, และ ensure reciprocal data protection",
   "ต้องมี purpose limitation, security obligation, breach notification, audit right",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # INFRASTRUCTURE  (20 standards)  ← NEW CATEGORY
  # ══════════════════════════════════════════════════════════════════
  ("STD-INF-001","Infrastructure","Server Hardening Baseline",
   "ทุก server ต้องผ่าน CIS Benchmark hardening ก่อน deploy เข้า production",
   "ลด attack surface จาก unnecessary service, default credential, และ weak config",
   "CIS Level 1 minimum, auto-remediation ด้วย Ansible, scan ทุกสัปดาห์, exception process",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-002","Infrastructure","OS Patch Management",
   "OS ทุก server ต้องได้รับ security patch ภายใน SLA ที่กำหนด",
   "ลด vulnerability window จาก unpatched OS",
   "Critical=48h, High=7d, Medium=30d, ใช้ patch automation, maintenance window ทุกเดือน",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-003","Infrastructure","Network Architecture Standard",
   "Network ต้องแบ่ง zone ชัดเจน: Internet, DMZ, Application, Database, Management",
   "จำกัด lateral movement และ enforce traffic control ระหว่าง zone",
   "Firewall ระหว่างทุก zone, default-deny policy, traffic flow documentation บังคับ",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-004","Infrastructure","DNS Management Standard",
   "DNS ต้องใช้ centralized management, DNSSEC บังคับสำหรับ public domain",
   "ป้องกัน DNS hijacking, cache poisoning, และ unauthorized record modification",
   "ใช้ authoritative DNS ที่ approved, TTL policy, monitoring สำหรับ unexpected changes",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-005","Infrastructure","Load Balancer & Traffic Management",
   "ระบบ production ต้องมี load balancer พร้อม health check และ connection draining",
   "เพิ่ม availability, ป้องกัน traffic ไปยัง unhealthy instance",
   "Health check interval ≤ 10s, connection drain timeout 30s, sticky session ต้องมีเหตุผล",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-006","Infrastructure","Storage Tiering Standard",
   "เลือก storage tier ตาม access pattern: Hot, Warm, Cold, Archive",
   "ลด storage cost โดย auto-tier ข้อมูลตาม access frequency",
   "Hot=SSD NVMe, Warm=SSD SATA, Cold=HDD, Archive=Object Storage Glacier class",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-007","Infrastructure","Capacity Planning & Forecasting",
   "ต้องทำ capacity planning ล่วงหน้า 6 เดือน สำหรับ CPU, Memory, Storage, Network",
   "ป้องกัน capacity exhaustion ที่กระทบ service availability",
   "Monitor utilization, alert ที่ 70%, forecast ด้วย trend analysis, review ทุกไตรมาส",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-008","Infrastructure","Disaster Recovery Standard",
   "ระบบ Tier 1 ต้องมี DR site พร้อม RTO ≤ 4h, RPO ≤ 1h",
   "รับประกัน business continuity เมื่อ primary site ล้มเหลว",
   "DR drill ทุก 6 เดือน, automated failover สำหรับ critical system, document runbook",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-009","Infrastructure","Infrastructure Monitoring & Alerting",
   "ทุก infrastructure component ต้องมี monitoring: CPU, Memory, Disk, Network, Application",
   "ตรวจจับ infrastructure issue ก่อนกระทบ end user",
   "Alert threshold: CPU>80%, Memory>85%, Disk>90%, PagerDuty integration สำหรับ critical",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-010","Infrastructure","Configuration Management (CMDB)",
   "ทุก infrastructure asset ต้องลงทะเบียนใน CMDB พร้อม relationship mapping",
   "Enable impact analysis, change management, และ asset lifecycle tracking",
   "Auto-discovery update CMDB, review accuracy ทุกไตรมาส, CMDB เป็น source of truth สำหรับ change",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-011","Infrastructure","Change Management for Infrastructure",
   "ทุก infrastructure change ต้องผ่าน Change Advisory Board (CAB) approval",
   "ลด risk จาก unauthorized หรือ poorly-planned change ที่กระทบ production",
   "Standard change: pre-approved, Normal change: CAB approval, Emergency: post-review",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-012","Infrastructure","Firewall Rule Management",
   "Firewall rule ต้องมี business justification, owner, expiry date, และ review ทุก 6 เดือน",
   "ป้องกัน rule bloat และ stale rule ที่สร้าง security risk",
   "ห้าม ANY-ANY rule, กำหนด least-privilege, cleanup expired rule, audit log ทุก change",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-013","Infrastructure","Physical Security Standard",
   "Data center ต้องมี physical access control: badge reader, CCTV, biometric สำหรับ server room",
   "ป้องกัน unauthorized physical access ที่นำไปสู่ data theft หรือ sabotage",
   "Access log 1 ปี, escort visitor, equipment removal process, periodic access review",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-014","Infrastructure","Power & Cooling Redundancy",
   "Data center ต้องมี power redundancy N+1 และ cooling system ที่รับประกัน uptime",
   "ป้องกัน service outage จาก power failure หรือ thermal event",
   "UPS + Generator, dual PDU per rack, cooling N+1, PUE monitoring, test ทุกปี",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-015","Infrastructure","Virtual Machine (VM) Standard",
   "VM ต้องสร้างจาก approved template, กำหนด resource ตาม tier, snapshot policy",
   "ลด VM sprawl, enforce security baseline, จัดการ lifecycle อย่างมีประสิทธิภาพ",
   "Approved OS list, max VM age = 3 ปีต้อง review, orphan VM cleanup ทุกไตรมาส",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-016","Infrastructure","Network Performance & QoS",
   "Network ต้องมี QoS policy สำหรับ prioritize critical traffic เช่น voice, video, FinTech",
   "รับประกัน performance ของ critical business application ใน congested network",
   "กำหนด traffic class, DSCP marking, bandwidth guarantee สำหรับ Tier 1 application",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-017","Infrastructure","IPv6 Readiness",
   "Infrastructure ใหม่ทุกชิ้นต้องรองรับ IPv6 หรือ dual-stack",
   "เตรียมพร้อมสำหรับ IPv4 exhaustion และ regulatory requirement ในอนาคต",
   "Dual-stack deployment, test IPv6 connectivity, กำหนด IPv6 addressing plan",
   "Draft","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-018","Infrastructure","Time Synchronization (NTP) Standard",
   "ทุก server ต้องใช้ NTP server ที่กำหนดและ time drift ต้องไม่เกิน 1 วินาที",
   "ป้องกัน authentication failure, log correlation error, และ certificate validation issue",
   "ใช้ internal NTP hierarchy, monitor drift, alert เมื่อเกิน threshold",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-019","Infrastructure","Infrastructure Cost Optimization",
   "ต้อง right-size infrastructure ทุกไตรมาสโดย analyze utilization จริง",
   "ลด wasted infrastructure cost จาก over-provisioning",
   "CPU <30% = downsize candidate, review reserved instance/saving plan ทุก 6 เดือน",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  ("STD-INF-020","Infrastructure","End-of-Life Hardware Disposal",
   "Hardware ที่ EOL ต้องผ่าน certified data destruction ก่อน disposal หรือ repurpose",
   "ป้องกัน data breach จาก improperly disposed hardware",
   "NIST 800-88 wiping สำหรับ storage, certificate of destruction บังคับ, asset registry update",
   "Active","1.0","Infrastructure Team","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # PLATFORM  (15 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-PLT-001","Platform","Container-First Deployment",
   "Application ใหม่ทุกตัวต้อง containerize ด้วย Docker และ deploy บน Kubernetes",
   "สร้าง consistency ของ deployment, เพิ่ม portability, รองรับ auto-scaling",
   "Base image ต้องผ่าน security scan, ห้ามใช้ root user ใน container, กำหนด resource limits",
   "Active","2.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-002","Platform","Infrastructure as Code (IaC)",
   "ทุก infrastructure provisioning ต้องทำผ่าน code (Terraform) — ห้าม manual provisioning",
   "สร้าง reproducibility, auditability, และลด configuration drift",
   "ใช้ Terraform + GitOps workflow, state ต้องเก็บใน remote backend, peer review บังคับ",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-003","Platform","High Availability Design Requirement",
   "ระบบ Tier 1 ต้องออกแบบให้ HA ด้วย minimum 99.9% uptime SLA",
   "ป้องกัน single point of failure และรองรับ business continuity",
   "ต้อง multi-AZ, active-active หรือ active-passive failover, DR test ทุก 6 เดือน",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-PLT-004","Platform","Observability Standard (Logs, Metrics, Traces)",
   "ทุก service ต้อง instrument ด้วย structured logging, metrics export, และ distributed tracing",
   "ลดเวลา MTTR, เพิ่ม visibility ของ system behavior",
   "Log: JSON structured, Metrics: Prometheus, Tracing: OpenTelemetry, Retention: 90 วัน",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-005","Platform","CI/CD Pipeline Standard",
   "ทุก application ต้องมี CI/CD pipeline: Build → Test → Security Scan → Deploy",
   "เพิ่ม deployment velocity, ลด manual error, enforce quality gate",
   "Git-based trigger, ห้าม skip test, deploy to prod ต้องมี approval, rollback < 5 นาที",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-006","Platform","GitOps Deployment Model",
   "Deployment config ต้องเก็บใน Git และใช้ GitOps controller (ArgoCD) sync สู่ cluster",
   "Git เป็น single source of truth สำหรับ desired state, audit trail ทุก change",
   "ArgoCD เป็น standard, manifest ใน separate repo, self-healing enable",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-007","Platform","Environment Management Standard",
   "ต้องมี environment แยกชัดเจน: Dev → UAT → Staging → Production",
   "ป้องกัน config bleed และ ensure production-like testing",
   "Production config isolation, promote artifact not code, environment parity principle",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-008","Platform","Kubernetes Resource Management",
   "ทุก Kubernetes workload ต้องกำหนด resource request, limit, และ HPA",
   "ป้องกัน noisy neighbor, enable auto-scaling, ensure cluster stability",
   "Request ≥ 50% limit, HPA min=2 replicas สำหรับ production, PodDisruptionBudget บังคับ",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-009","Platform","Cloud Native Architecture Principle",
   "Application ใหม่ต้องออกแบบตาม cloud-native principles: microservice, stateless, resilient",
   "ใช้ประโยชน์จาก cloud elasticity, managed service, และ pay-per-use",
   "Prefer managed service เหนือ self-managed, design for failure, chaos engineering",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-PLT-010","Platform","Service Level Objective (SLO) Management",
   "ทุก service ต้องกำหนด SLO และ track error budget",
   "สร้าง shared understanding ของ reliability target ระหว่าง dev และ ops",
   "SLO review ทุกไตรมาส, freeze deployment เมื่อ error budget habitual < 10%",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-011","Platform","Chaos Engineering Practice",
   "ระบบ Tier 1 ต้องผ่าน chaos experiment อย่างน้อยปีละ 2 ครั้ง",
   "พิสูจน์ resilience ของ system ใน controlled failure scenario",
   "เริ่มจาก dev/staging, document hypothesis, monitor ผลกระทบ, fix ก่อนขยายสู่ production",
   "Active","1.0","Platform Team","2025-06-01","2026-12-31"),

  ("STD-PLT-012","Platform","Release Management Standard",
   "Production release ต้องผ่าน change management process และมี rollback plan",
   "ลด risk จาก deployment failure และรับประกัน business impact ต่ำ",
   "Blue/green หรือ canary deployment สำหรับ critical service, release freeze ช่วง peak",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-013","Platform","Multi-Region Deployment Strategy",
   "ระบบ Tier 1 ที่มี global user base ต้องมี multi-region deployment strategy",
   "ลด latency สำหรับ global user และเพิ่ม geographic resilience",
   "Active-active หรือ active-passive ตาม cost/complexity trade-off, data sovereignty compliance",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-PLT-014","Platform","Platform Engineering Catalog",
   "Platform team ต้องมี service catalog สำหรับ self-service provisioning โดย developer",
   "ลด bottleneck ของ platform team, เพิ่ม developer autonomy",
   "ใช้ Backstage หรือ equivalent, golden path template, สร้าง new service < 5 นาที",
   "Draft","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-PLT-015","Platform","Technical Debt Management",
   "ทุก team ต้องจัดสรร 20% ของ sprint capacity สำหรับ technical debt reduction",
   "ป้องกัน debt สะสมจนกระทบ velocity และ increase defect rate",
   "Track debt ใน backlog, debt-to-feature ratio สูงสุด 30%, quarterly debt review",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # APPLICATION  (20 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-APP-001","Application","Clean Architecture & Separation of Concerns",
   "Application ต้องแยก business logic, data access, และ presentation layer ชัดเจน",
   "เพิ่ม testability, maintainability, และลด technical debt",
   "ใช้ layered architecture หรือ hexagonal architecture, ห้าม business logic ใน UI layer",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-002","Application","API-First Development",
   "ออกแบบ API contract ก่อน implement — Frontend และ Backend develop parallel ได้",
   "ลด dependency และเพิ่ม development velocity",
   "ใช้ OpenAPI spec เป็น contract, mock server ระหว่าง development, contract test บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-003","Application","Automated Testing Requirement",
   "ทุก service ต้องมี unit test coverage ≥ 80% และ integration test ก่อน merge to main",
   "ลด regression bug และเพิ่ม confidence ในการ deploy",
   "บังคับ CI gate: unit test + lint + security scan, E2E test สำหรับ critical user journey",
   "Active","1.1","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-004","Application","12-Factor Application Design",
   "Application ต้องปฏิบัติตาม 12-factor principles โดยเฉพาะ: Config via env, Stateless process",
   "เพิ่ม scalability, portability, และความง่ายในการ operate",
   "ห้าม hardcode config, ต้อง health check endpoint, graceful shutdown, horizontal scalable",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-APP-005","Application","Frontend Performance Standard",
   "Web application ต้องผ่าน Core Web Vitals: LCP<2.5s, FID<100ms, CLS<0.1",
   "Performance โดยตรงกระทบ user experience และ SEO ranking",
   "Lighthouse score ≥ 90, code splitting, lazy loading, CDN สำหรับ static asset",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-006","Application","Accessibility Standard (WCAG 2.1)",
   "Web application ต้องปฏิบัติตาม WCAG 2.1 Level AA",
   "รองรับผู้ใช้ที่มีความพิการและปฏิบัติตาม regulatory requirement",
   "Screen reader compatible, keyboard navigable, color contrast ≥ 4.5:1, alt text บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-007","Application","Session Management Standard",
   "Web session ต้องมี secure configuration: HttpOnly, Secure flag, SameSite, timeout",
   "ป้องกัน session hijacking, CSRF, และ XSS",
   "Session timeout 30 นาที inactive, regenerate session ID หลัง login, ห้าม session fixation",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-APP-008","Application","Input Validation & Output Encoding",
   "ทุก user input ต้องผ่าน validation และทุก output ต้อง encode ก่อน render",
   "ป้องกัน Injection attack: SQL, XSS, Command injection",
   "Whitelist validation, parameterized query บังคับ, context-aware output encoding",
   "Active","1.0","CISO Office","2025-01-01","2026-12-31"),

  ("STD-APP-009","Application","Dependency Management Standard",
   "ทุก 3rd-party dependency ต้องมี version pinning และ license compliance check",
   "ป้องกัน dependency hell, security vulnerability จาก outdated library, license violation",
   "SCA scan บังคับ, ห้าม use dependency ที่มี GPL license ใน proprietary software",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-010","Application","Microservice Decomposition Principle",
   "การ decompose microservice ต้องใช้ Domain-Driven Design boundary",
   "ป้องกัน distributed monolith และ ensure service independence",
   "One service per bounded context, ห้าม shared DB ระหว่าง service, size ≤ 2-pizza team",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-011","Application","Code Review & Merge Policy",
   "ทุก code change ต้องผ่าน peer review อย่างน้อย 1 คนก่อน merge สู่ main branch",
   "ลด defect, ปรับปรุง code quality, และแชร์ knowledge ภายในทีม",
   "PR ไม่เกิน 400 lines, review < 24 ชั่วโมง, ห้าม self-approve, checklist บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-012","Application","Feature Flag Management",
   "Feature toggle ต้องมี owner, expiry date, และ cleanup process",
   "ป้องกัน feature flag debt และ reduce complexity จาก orphan flags",
   "ตั้ง expiry ≤ 90 วัน, review ทุก sprint, remove flag หลัง feature stable 30 วัน",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-013","Application","API Client Resilience Pattern",
   "ทุก service ที่ call external dependency ต้องใช้ resilience pattern: retry, circuit breaker, timeout",
   "ป้องกัน cascading failure จาก slow/unavailable dependency",
   "Retry: max 3 ครั้ง exponential backoff, Circuit breaker: 50% error rate, Timeout: explicit",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-014","Application","Localization & Internationalization",
   "Application ที่รองรับ multi-language ต้องใช้ i18n framework และ externalize string",
   "ง่ายต่อการเพิ่ม language ใหม่โดยไม่ต้อง change code",
   "ห้าม hardcode string, ใช้ message bundle, test ด้วย pseudo-locale, RTL support",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-015","Application","Code Documentation Standard",
   "Code ต้องมี README ที่สมบูรณ์, inline comment สำหรับ complex logic, API doc",
   "ลดเวลา onboarding developer ใหม่และ maintenance cost",
   "README: setup, architecture, API, ops runbook, inline doc สำหรับ function complexity > 10",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-016","Application","Application Versioning Strategy",
   "Application ต้องใช้ Semantic Versioning (SemVer) และ maintain changelog",
   "Communicate impact ของ release ให้ผู้ใช้และ dependent service เข้าใจ",
   "MAJOR.MINOR.PATCH, CHANGELOG.md บังคับ, tag Git release, publish release notes",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-017","Application","Caching Strategy",
   "ต้องกำหนด caching strategy ที่ชัดเจน: cache level, TTL, invalidation strategy",
   "ปรับปรุง performance และลด load บน database และ backend service",
   "กำหนด cache-aside หรือ write-through, TTL ตาม data freshness requirement, cache stampede prevention",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-018","Application","Error Handling & Graceful Degradation",
   "Application ต้องมี global error handler และ degrade gracefully เมื่อ dependency ไม่พร้อม",
   "ให้ user experience ที่ดีแม้ส่วนหนึ่งของระบบล้มเหลว",
   "ห้าม expose stack trace สู่ user, กำหนด fallback behavior, friendly error message",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-APP-019","Application","Application Health Check Standard",
   "ทุก service ต้องมี health check endpoint: /health/live และ /health/ready",
   "Enable Kubernetes liveness/readiness probe และ load balancer health monitoring",
   "Liveness: basic process alive check, Readiness: dependency check, response < 1s",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-APP-020","Application","Static Code Analysis Requirement",
   "ทุก codebase ต้องผ่าน static analysis tool ใน CI pipeline ก่อน merge",
   "ค้นพบ code quality, security issue, และ maintainability problem ตั้งแต่ต้น",
   "ใช้ SonarQube, Quality Gate: 0 blocker, coverage ≥ 80%, ห้าม skip",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # INTEGRATION  (15 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-INT-001","Integration","Service Mesh for East-West Traffic",
   "การ communicate ระหว่าง microservices ใน cluster ต้องผ่าน service mesh (Istio)",
   "mTLS สำหรับ service-to-service, built-in observability, traffic management",
   "กำหนด DestinationRule และ VirtualService ทุก service, ใช้ circuit breaker pattern",
   "Active","1.0","Platform Team","2025-01-01","2026-12-31"),

  ("STD-INT-002","Integration","Legacy System Integration via Anti-Corruption Layer",
   "การ integrate กับ legacy system ต้องใช้ Anti-Corruption Layer (ACL) แยก domain model",
   "ป้องกัน legacy complexity ซึม penetrate เข้า new system",
   "ออกแบบ adapter/facade pattern, กำหนด contract ที่ new system owns, monitor legacy SLA",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-003","Integration","Enterprise Integration Pattern (EIP) Standard",
   "การ design integration ต้องใช้ Enterprise Integration Pattern ที่ appropriate",
   "สร้าง shared vocabulary และ proven solution สำหรับ common integration problem",
   "Document pattern ที่ใช้ใน ADR, ใช้ message-based integration สำหรับ decoupled system",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-004","Integration","Data Format & Schema Standard",
   "Integration data ต้องใช้ JSON หรือ Avro, มี schema registry สำหรับ event",
   "ป้องกัน data format inconsistency ระหว่าง producer และ consumer",
   "JSON Schema หรือ Avro สำหรับ event, schema evolution policy, backward compatibility",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-005","Integration","SAP Integration Standard",
   "การ integrate กับ SAP ต้องผ่าน SAP approved API (oData, BAPI, RFC) ไม่ใช่ direct DB",
   "ป้องกัน unsupported SAP integration ที่ break เมื่อ upgrade",
   "ใช้ SAP Integration Suite, document interface ทุกตัว, test ใน sandbox ก่อน production",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-006","Integration","Event-Driven Architecture Design",
   "Event ต้องมี schema, version, และ idempotent consumer",
   "ป้องกัน event schema break และ duplicate processing",
   "CloudEvents spec สำหรับ event format, dead letter queue, event sourcing สำหรับ audit",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-007","Integration","Batch Processing Standard",
   "Batch job ต้องมี idempotent execution, restart capability, และ monitoring",
   "ป้องกัน duplicate processing และ ensure visibility ของ batch status",
   "กำหนด job scheduling, checkpoint mechanism, alert เมื่อ job fail หรือ เกิน SLA",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-008","Integration","File Transfer Standard",
   "File-based integration ต้องใช้ SFTP หรือ managed file transfer, ห้าม FTP",
   "ป้องกัน clear-text transmission และ ensure file integrity",
   "SFTP หรือ HTTPS, checksum validation, กำหนด file naming convention, retention period",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-009","Integration","3rd-Party Integration Governance",
   "ทุก 3rd-party integration ต้องผ่าน architecture review และ security assessment",
   "ป้องกัน shadow integration และ ensure supply chain security",
   "Register ใน integration catalog, review data flow diagram, vendor security assessment",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-010","Integration","Integration Monitoring & Error Handling",
   "ทุก integration ต้องมี monitoring, alerting, และ dead letter queue สำหรับ failed message",
   "ตรวจจับ integration failure ก่อนกระทบ business process",
   "Alert ที่ error rate > 1%, DLQ review ทุกวัน, reprocessing capability บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-011","Integration","Master Data Synchronization",
   "การ sync master data ระหว่าง system ต้องมี conflict resolution strategy",
   "ป้องกัน data inconsistency จาก concurrent update",
   "กำหนด authoritative source, timestamp-based conflict resolution, sync log",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-INT-012","Integration","API Composition & Aggregation Pattern",
   "การรวมข้อมูลจากหลาย service ต้องทำที่ BFF หรือ API Composition layer",
   "ป้องกัน client ต้อง call หลาย API และลด chattiness",
   "BFF pattern สำหรับ frontend-specific aggregation, ห้าม aggregation ที่ gateway layer",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-013","Integration","Change Data Capture (CDC)",
   "การ sync data จาก OLTP สู่ analytical system ต้องใช้ CDC แทน batch ETL",
   "ลด latency ของ data synchronization และ load บน source system",
   "ใช้ Debezium หรือ cloud-native CDC, monitor lag, schema change handling",
   "Active","1.0","Data Office","2025-01-01","2026-12-31"),

  ("STD-INT-014","Integration","Integration Testing Standard",
   "ทุก integration point ต้องมี integration test ที่ run ใน CI/CD pipeline",
   "ตรวจจับ integration breakage ก่อน deploy สู่ production",
   "ใช้ contract test + integration test, test ใน staging environment ที่ production-like",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-INT-015","Integration","Distributed Transaction Management",
   "Distributed transaction ต้องใช้ Saga pattern แทน 2PC",
   "ป้องกัน distributed deadlock และ ensure eventual consistency",
   "Choreography หรือ Orchestration Saga, compensating transaction บังคับ, idempotent step",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  # ══════════════════════════════════════════════════════════════════
  # GOVERNANCE  (15 standards)
  # ══════════════════════════════════════════════════════════════════
  ("STD-GOV-001","Governance","Architecture Decision Record (ADR)",
   "ทุก significant architecture decision ต้องบันทึกเป็น ADR ใน repository",
   "สร้าง institutional memory, ป้องกันการตัดสินใจซ้ำ, และ onboard คนใหม่ได้เร็ว",
   "Format: Context / Decision / Consequences, เก็บใน /docs/adr/, review ใน ARB",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-002","Governance","Technology Lifecycle Management",
   "ทุก technology ต้องมี lifecycle plan: adoption → mainstream → deprecated → retired",
   "ป้องกัน tech debt สะสมจาก EOL technology ที่ไม่ได้ plan migration",
   "ทบทวน Tech Radar ทุก quarter, กำหนด migration plan ≥ 12 เดือนก่อน EOL",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-003","Governance","Architecture Review Board (ARB) Process",
   "ทุก significant architecture change ต้องผ่าน ARB review ก่อน implementation",
   "สร้าง oversight, enforce standards, และ identify cross-domain impact",
   "ARB ทุก 2 สัปดาห์, submit 1 สัปดาห์ล่วงหน้า, decision documented ใน EA Repository",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-004","Governance","Enterprise Architecture Roadmap",
   "EA ต้องมี 3-year roadmap ที่ align กับ business strategy และ review ทุก 6 เดือน",
   "สร้าง alignment ระหว่าง IT investment และ business direction",
   "Roadmap ครอบคลุม: application, data, technology, infrastructure, security",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-005","Governance","IT Project Architecture Gate",
   "ทุก IT project ที่มีงบ > 5 ล้านบาท ต้องผ่าน architecture gate review",
   "ป้องกัน project ที่สร้าง technical debt หรือ ขัดแย้งกับ EA direction",
   "Gate ที่ Initiation, Design, และ Go-live, EA sign-off บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-006","Governance","Technology Standardization Process",
   "Technology ใหม่ที่จะนำมาใช้ในองค์กรต้องผ่าน evaluation และ ARB approval",
   "ป้องกัน technology sprawl และสร้าง economies of scale",
   "ประเมิน: maturity, community, support, security, cost, lock-in risk",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-007","Governance","EA Metrics & KPI Reporting",
   "EA ต้องรายงาน KPI ต่อ CIO ทุกไตรมาส: tech debt ratio, standard compliance, roadmap progress",
   "แสดงคุณค่าของ EA และ identify area ที่ต้องการ attention",
   "Dashboard ที่ real-time, KPI: compliance rate ≥ 85%, ADR count, ARB cycle time",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-008","Governance","Vendor Lock-in Risk Management",
   "ต้อง assess vendor lock-in risk สำหรับทุก strategic technology choice",
   "รักษา negotiating power และ exit strategy กับ vendor",
   "กำหนด lock-in score, exit plan สำหรับ tier 1 vendor, portability test",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-009","Governance","Open Source Governance Policy",
   "การใช้ open source software ต้องผ่าน license review และ vulnerability assessment",
   "ป้องกัน license violation และ security risk จาก unmaintained project",
   "Approved license list, SCA scan, contribute back policy, avoid abandonware",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-010","Governance","IT Asset Lifecycle Management",
   "ทุก IT asset ต้องมี lifecycle: Procure → Deploy → Operate → Retire",
   "ป้องกัน shadow IT, enable capacity planning, ensure proper disposal",
   "CMDB as source of truth, asset tagging, refresh cycle ตาม category",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-011","Governance","Architecture Principle Compliance Audit",
   "Architecture compliance ต้องตรวจสอบ quarterly โดย EA team",
   "ตรวจจับ drift จาก standard และ trigger remediation",
   "Automated compliance check, exception register, trend reporting",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-012","Governance","Innovation Portfolio Management",
   "EA ต้องมี innovation pipeline: Explore → Experiment → Scale → Retire",
   "Balance ระหว่าง innovation และ stability, สร้าง structured path สู่ adoption",
   "20% budget สำหรับ innovation, PoC timeboxed 30-60 วัน, gate ก่อน scale",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-013","Governance","EA Communication & Stakeholder Engagement",
   "EA ต้องมี communication plan สำหรับ stakeholder แต่ละกลุ่ม",
   "สร้าง buy-in และ awareness ของ EA direction ทั่วองค์กร",
   "Monthly update สำหรับ CIO, quarterly สำหรับ business leader, annual all-hands",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-014","Governance","Standard Waiver & Exception Process",
   "การขอยกเว้น standard ต้องผ่าน formal process พร้อม risk acceptance",
   "ให้ flexibility ที่จำเป็นโดยยังคง governance integrity",
   "Submit exception request, ARB review, time-limited approval, remediation plan บังคับ",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),

  ("STD-GOV-015","Governance","Enterprise Capability Model",
   "EA ต้องมี Business Capability Model ที่ครอบคลุมและ update ทุกปี",
   "เป็น framework สำหรับ investment prioritization และ gap analysis",
   "Map application สู่ capability, identify gap และ redundancy, link สู่ strategy",
   "Active","1.0","Architecture Team","2025-01-01","2026-12-31"),
]

# ─────────────────────────────────────────────────────────────────────────────
def seed():
    ts = now()
    ea = sqlite3.connect(EA_DB)
    ea.row_factory = sqlite3.Row

    print(f"Total standards to seed: {len(ALL_STANDARDS)}")
    inserted = skipped = 0

    for row in ALL_STANDARDS:
        code, cat, title, desc, rat, guide, status, ver, owner, eff, rev = row
        existing = ea.execute("SELECT id FROM repo_standards WHERE code=?", (code,)).fetchone()
        if existing:
            skipped += 1
            continue
        sid = uid()
        ea.execute("""INSERT INTO repo_standards
            (id,code,category,title,description,rationale,guidance,status,version,owner,
             effective_date,review_date,tags,created_by,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, code, cat, title, desc, rat, guide, status, ver, owner,
             eff, rev, json.dumps([cat.lower()]), "seed", ts, ts))
        inserted += 1

    ea.commit()

    total = ea.execute("SELECT COUNT(*) FROM repo_standards").fetchone()[0]
    print(f"\n=== SEED STANDARDS COMPLETE ===")
    print(f"  Inserted : {inserted}")
    print(f"  Skipped  : {skipped} (already exist)")
    print(f"  Total    : {total} standards")
    print()
    for row in ea.execute("SELECT category, COUNT(*) cnt FROM repo_standards GROUP BY category ORDER BY cnt DESC").fetchall():
        print(f"  {row['category']:20s} : {row['cnt']} standards")

    ea.close()

if __name__ == "__main__":
    seed()
