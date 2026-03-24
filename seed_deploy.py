#!/usr/bin/env python3
"""
seed_deploy.py — Seed Deployment Topology data (deploy_nodes + deploy_edges)
into appport.db for MPX AppPort EA Portfolio

Run: python3 seed_deploy.py
"""
import sqlite3, json, os, uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "appport.db")
NOW = datetime.utcnow().isoformat(timespec="seconds")

DDL = """
CREATE TABLE IF NOT EXISTS deploy_nodes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, node_type TEXT NOT NULL DEFAULT 'Server',
    environment TEXT DEFAULT 'Production', provider TEXT DEFAULT '', region TEXT DEFAULT '',
    hostname TEXT DEFAULT '', ip_address TEXT DEFAULT '', os TEXT DEFAULT '',
    spec TEXT DEFAULT '', version TEXT DEFAULT '', status TEXT DEFAULT 'Active',
    notes TEXT DEFAULT '', tags TEXT DEFAULT '[]', x REAL DEFAULT 0, y REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS deploy_edges (
    id TEXT PRIMARY KEY, src_type TEXT NOT NULL, src_id TEXT NOT NULL,
    tgt_type TEXT NOT NULL, tgt_id TEXT NOT NULL, edge_type TEXT DEFAULT 'connects-to',
    protocol TEXT DEFAULT '', port TEXT DEFAULT '', environment TEXT DEFAULT 'Production',
    label TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now'))
);
"""

NODES = [
    # ── Cloud Zones ──────────────────────────────────────────────────────────────
    ("DN-CLD-AWS-PROD",  "AWS ap-southeast-1",     "CloudZone",    "Production", "AWS",        "ap-southeast-1", "", "", "", "", "VPC + Multi-AZ",      "", "[]"),
    ("DN-CLD-AWS-UAT",   "AWS ap-southeast-1 UAT", "CloudZone",    "UAT",        "AWS",        "ap-southeast-1", "", "", "", "", "VPC UAT",             "", "[]"),
    ("DN-CLD-ONPREM",    "On-Premise DC",           "CloudZone",    "Production", "On-Premise", "Bangkok HQ",     "", "", "", "", "Private Data Center", "", "[]"),

    # ── Load Balancers ────────────────────────────────────────────────────────────
    ("DN-LB-001", "AWS ALB (Prod)",           "LoadBalancer", "Production", "AWS",        "ap-southeast-1", "alb-prod.internal",   "10.0.1.10", "Amazon Linux 2", "ALB",         "Latest", "Active", "[]"),
    ("DN-LB-002", "Nginx LB (On-Prem)",       "LoadBalancer", "Production", "On-Premise", "Bangkok HQ",     "nginx-lb.mpx.local",  "192.168.1.10","Ubuntu 22.04", "Nginx 1.24",  "1.24",   "Active", '["legacy"]'),

    # ── Web / App Servers ─────────────────────────────────────────────────────────
    ("DN-SRV-001", "Core Banking App Server 1",  "Server", "Production", "On-Premise", "Bangkok HQ",     "cbs-app1.mpx.local",  "192.168.10.11","RHEL 8.8",     "8vCPU 32GB",  "RHEL 8.8",  "Active", '["core"]'),
    ("DN-SRV-002", "Core Banking App Server 2",  "Server", "Production", "On-Premise", "Bangkok HQ",     "cbs-app2.mpx.local",  "192.168.10.12","RHEL 8.8",     "8vCPU 32GB",  "RHEL 8.8",  "Active", '["core"]'),
    ("DN-SRV-003", "Internet Banking EC2",        "Server", "Production", "AWS",        "ap-southeast-1", "ibank-ec2.aws",       "10.0.2.20",   "Amazon Linux 2","t3.large",    "AL2",        "Active", '["cloud"]'),
    ("DN-SRV-004", "Mobile API Gateway EC2",      "Server", "Production", "AWS",        "ap-southeast-1", "mobile-api.aws",      "10.0.2.21",   "Amazon Linux 2","t3.xlarge",   "AL2",        "Active", '["cloud","api"]'),
    ("DN-SRV-005", "CRM App Server",              "Server", "Production", "AWS",        "ap-southeast-1", "crm-ec2.aws",         "10.0.3.10",   "Ubuntu 22.04",  "t3.large",    "22.04",      "Active", '["crm"]'),
    ("DN-SRV-006", "Data Platform EC2",           "Server", "Production", "AWS",        "ap-southeast-1", "data-ec2.aws",        "10.0.4.10",   "Amazon Linux 2","m5.2xlarge",  "AL2",        "Active", '["data"]'),
    ("DN-SRV-007", "HR System Server",            "Server", "Production", "On-Premise", "Bangkok HQ",     "hr-app1.mpx.local",   "192.168.20.10","Windows Server 2019","4vCPU 16GB","WS2019",  "Active", '["hr"]'),
    ("DN-SRV-008", "Treasury App Server",         "Server", "Production", "On-Premise", "Bangkok HQ",     "treasury-app.mpx.local","192.168.20.20","RHEL 8.8",  "8vCPU 32GB",  "RHEL 8.8",  "Active", '["finance"]'),

    # ── Databases ─────────────────────────────────────────────────────────────────
    ("DN-DB-001", "Core Banking DB (Oracle RAC)", "Database", "Production", "On-Premise", "Bangkok HQ",     "cbs-db-rac.mpx.local","192.168.10.50","Oracle Linux 8","32vCPU 256GB","Oracle 19c","Active",'["core","rac"]'),
    ("DN-DB-002", "Internet Banking RDS",          "Database", "Production", "AWS",        "ap-southeast-1", "ibank-rds.aws",       "10.0.5.10",   "Amazon RDS",    "db.r5.large", "MySQL 8.0", "Active",'["cloud"]'),
    ("DN-DB-003", "CRM PostgreSQL RDS",            "Database", "Production", "AWS",        "ap-southeast-1", "crm-rds.aws",         "10.0.5.11",   "Amazon RDS",    "db.t3.medium","PostgreSQL 14","Active",'["crm"]'),
    ("DN-DB-004", "Data Warehouse (Redshift)",     "Database", "Production", "AWS",        "ap-southeast-1", "dw-redshift.aws",     "10.0.5.20",   "Amazon Redshift","dc2.large 4n","Redshift", "Active",'["data","dw"]'),
    ("DN-DB-005", "HR Database (MSSQL)",           "Database", "Production", "On-Premise", "Bangkok HQ",     "hr-db.mpx.local",     "192.168.20.51","Windows Server 2019","8vCPU 64GB","MSSQL 2019","Active",'["hr"]'),
    ("DN-DB-006", "Treasury DB (Oracle)",          "Database", "Production", "On-Premise", "Bangkok HQ",     "treasury-db.mpx.local","192.168.20.52","Oracle Linux 8","16vCPU 128GB","Oracle 19c","Active",'["finance"]'),

    # ── Caches ───────────────────────────────────────────────────────────────────
    ("DN-CACHE-001", "Redis ElastiCache (Prod)",  "Cache", "Production", "AWS",        "ap-southeast-1", "redis.elasticache.aws","10.0.6.10", "ElastiCache",   "cache.r6g.large","Redis 7.0","Active",'["cloud"]'),
    ("DN-CACHE-002", "Redis On-Prem",             "Cache", "Production", "On-Premise", "Bangkok HQ",     "redis.mpx.local",     "192.168.30.10","Ubuntu 20.04","4vCPU 16GB",   "Redis 6.2","Active",'["legacy"]'),

    # ── Containers / K8s ─────────────────────────────────────────────────────────
    ("DN-K8S-001", "EKS Cluster (Prod)",      "K8sCluster", "Production", "AWS",   "ap-southeast-1", "eks-prod.aws",    "","Amazon EKS",   "3 nodes m5.xlarge","EKS 1.28","Active",'["cloud","k8s"]'),
    ("DN-K8S-002", "EKS Cluster (UAT)",       "K8sCluster", "UAT",        "AWS",   "ap-southeast-1", "eks-uat.aws",     "","Amazon EKS",   "2 nodes t3.large", "EKS 1.28","Active",'["cloud","k8s","uat"]'),

    # ── Message Queues ────────────────────────────────────────────────────────────
    ("DN-MQ-001", "Amazon SQS / SNS",         "Queue",   "Production", "AWS",        "ap-southeast-1", "sqs.aws",            "", "AWS SQS",  "Standard Queue",  "SQS",      "Active",'["cloud","async"]'),
    ("DN-MQ-002", "Apache Kafka (On-Prem)",   "Queue",   "Production", "On-Premise", "Bangkok HQ",     "kafka.mpx.local",    "192.168.40.10","Ubuntu 20.04","3 brokers 8vCPU","Kafka 3.4","Active",'["legacy","streaming"]'),

    # ── API Gateway ───────────────────────────────────────────────────────────────
    ("DN-GW-001", "AWS API Gateway",          "Gateway", "Production", "AWS",        "ap-southeast-1", "apigw.aws",          "", "AWS APIGW","Managed",         "REST/HTTP", "Active",'["cloud","api"]'),
    ("DN-GW-002", "Kong API Gateway (UAT)",   "Gateway", "UAT",        "AWS",        "ap-southeast-1", "kong-uat.aws",       "10.0.7.10","Ubuntu 22.04","4vCPU 8GB",   "Kong 3.4","Active",'["uat","api"]'),

    # ── CDN ───────────────────────────────────────────────────────────────────────
    ("DN-CDN-001", "AWS CloudFront",          "CDN",     "Production", "AWS",        "Global",         "cdn.mpx.co.th",      "", "CloudFront","Global CDN",      "CF",       "Active",'["cloud","cdn"]'),

    # ── Firewall ──────────────────────────────────────────────────────────────────
    ("DN-FW-001",  "Palo Alto FW (Prod)",     "Firewall","Production", "On-Premise", "Bangkok HQ",     "fw-prod.mpx.local",  "192.168.1.1","PAN-OS","HA Pair",     "PAN-OS 10.2","Active",'["security"]'),

    # ── Storage ───────────────────────────────────────────────────────────────────
    ("DN-STG-001", "AWS S3 (Doc/Media)",      "Storage", "Production", "AWS",        "ap-southeast-1", "s3-mpx-prod",        "", "AWS S3",   "Standard",        "S3",       "Active",'["cloud","storage"]'),

    # ── External APIs ─────────────────────────────────────────────────────────────
    ("DN-EXT-001", "National Credit Bureau API","ExternalAPI","Production","External","Thailand","ncb.or.th","","External","REST","v2","Active",'["external","credit"]'),
    ("DN-EXT-002", "SWIFT Network",            "ExternalAPI","Production","External","Global","swift.com","","External","ISO20022","","Active",'["external","finance"]'),
    ("DN-EXT-003", "LINE Notify / OA",         "ExternalAPI","Production","External","Global","api.line.me","","External","REST","v2","Active",'["external","notify"]'),
]

EDGES = [
    # ── Core Banking System (APP-001) ─────────────────────────────────────────────
    ("Application","APP-001","DeployNode","DN-LB-002",   "hosts",         "HTTP",   "8080","Production","Client → CBS"),
    ("DeployNode","DN-LB-002","DeployNode","DN-SRV-001","load-balances",  "HTTP",   "8080","Production","LB → App1"),
    ("DeployNode","DN-LB-002","DeployNode","DN-SRV-002","load-balances",  "HTTP",   "8080","Production","LB → App2"),
    ("Application","APP-001","DeployNode","DN-DB-001",   "uses",          "JDBC",   "1521","Production","CBS → Oracle RAC"),
    ("Application","APP-001","DeployNode","DN-CACHE-002","caches",        "TCP",    "6379","Production","CBS → Redis"),
    ("Application","APP-001","DeployNode","DN-MQ-002",   "calls",         "Kafka",  "9092","Production","CBS → Kafka Events"),
    ("Application","APP-001","DeployNode","DN-FW-001",   "routes-to",     "TCP",    "443", "Production","All traffic via FW"),
    ("Application","APP-001","DeployNode","DN-EXT-002",  "calls",         "HTTPS",  "443", "Production","SWIFT Payment"),

    # ── Internet Banking (APP-002) ─────────────────────────────────────────────────
    ("Application","APP-002","DeployNode","DN-CDN-001",  "routes-to",     "HTTPS",  "443", "Production","iBank → CloudFront"),
    ("Application","APP-002","DeployNode","DN-LB-001",   "hosts",         "HTTPS",  "443", "Production","ALB → iBank"),
    ("Application","APP-002","DeployNode","DN-SRV-003",  "deploys-on",    "HTTPS",  "8443","Production","iBank EC2"),
    ("Application","APP-002","DeployNode","DN-DB-002",   "uses",          "JDBC",   "3306","Production","iBank → MySQL RDS"),
    ("Application","APP-002","DeployNode","DN-CACHE-001","caches",        "TCP",    "6379","Production","Session Cache"),
    ("Application","APP-002","DeployNode","DN-GW-001",   "connects-to",   "HTTPS",  "443", "Production","API Gateway"),
    ("Application","APP-002","DeployNode","DN-MQ-001",   "calls",         "HTTPS",  "443", "Production","SQS Async Notify"),

    # ── Mobile Banking (APP-020) ──────────────────────────────────────────────────
    ("Application","APP-020","DeployNode","DN-GW-001",   "routes-to",     "HTTPS",  "443", "Production","Mobile → API GW"),
    ("Application","APP-020","DeployNode","DN-SRV-004",  "deploys-on",    "HTTPS",  "8443","Production","Mobile API EC2"),
    ("Application","APP-020","DeployNode","DN-CACHE-001","caches",        "TCP",    "6379","Production","Token Cache"),
    ("Application","APP-020","DeployNode","DN-EXT-003",  "calls",         "HTTPS",  "443", "Production","LINE Notify"),

    # ── CRM (APP-042) ─────────────────────────────────────────────────────────────
    ("Application","APP-042","DeployNode","DN-LB-001",   "hosts",         "HTTPS",  "443", "Production","ALB → CRM"),
    ("Application","APP-042","DeployNode","DN-SRV-005",  "deploys-on",    "HTTPS",  "8080","Production","CRM EC2"),
    ("Application","APP-042","DeployNode","DN-DB-003",   "uses",          "JDBC",   "5432","Production","CRM → PostgreSQL"),
    ("Application","APP-042","DeployNode","DN-STG-001",  "uses",          "HTTPS",  "443", "Production","S3 Attachments"),

    # ── Data Platform (APP-061) ───────────────────────────────────────────────────
    ("Application","APP-061","DeployNode","DN-SRV-006",  "deploys-on",    "HTTPS",  "8080","Production","Data Platform EC2"),
    ("Application","APP-061","DeployNode","DN-DB-004",   "uses",          "JDBC",   "5439","Production","Redshift DWH"),
    ("Application","APP-061","DeployNode","DN-MQ-002",   "calls",         "Kafka",  "9092","Production","Kafka Source"),
    ("Application","APP-061","DeployNode","DN-STG-001",  "uses",          "HTTPS",  "443", "Production","S3 Data Lake"),

    # ── HR System (APP-080) ───────────────────────────────────────────────────────
    ("Application","APP-080","DeployNode","DN-SRV-007",  "deploys-on",    "HTTP",   "8080","Production","HR App Server"),
    ("Application","APP-080","DeployNode","DN-DB-005",   "uses",          "JDBC",   "1433","Production","HR → MSSQL"),
    ("Application","APP-080","DeployNode","DN-EXT-001",  "calls",         "HTTPS",  "443", "Production","Credit Bureau Check"),

    # ── Treasury (APP-015) ────────────────────────────────────────────────────────
    ("Application","APP-015","DeployNode","DN-SRV-008",  "deploys-on",    "HTTP",   "8080","Production","Treasury App Server"),
    ("Application","APP-015","DeployNode","DN-DB-006",   "uses",          "JDBC",   "1521","Production","Treasury → Oracle"),
    ("Application","APP-015","DeployNode","DN-EXT-002",  "calls",         "HTTPS",  "443", "Production","SWIFT Settlement"),
    ("Application","APP-015","DeployNode","DN-MQ-002",   "calls",         "Kafka",  "9092","Production","Rate Event Stream"),

    # ── EKS workloads ────────────────────────────────────────────────────────────
    ("DeployNode","DN-SRV-003","DeployNode","DN-K8S-001","deploys-on",    "","","Production","EC2 in EKS cluster"),
    ("DeployNode","DN-SRV-004","DeployNode","DN-K8S-001","deploys-on",    "","","Production","EC2 in EKS cluster"),
    ("DeployNode","DN-SRV-005","DeployNode","DN-K8S-001","deploys-on",    "","","Production","EC2 in EKS cluster"),

    # ── Cloud Zone grouping ───────────────────────────────────────────────────────
    ("DeployNode","DN-K8S-001","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","EKS in AWS VPC Prod"),
    ("DeployNode","DN-DB-002","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","RDS in AWS Prod"),
    ("DeployNode","DN-CACHE-001","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","ElastiCache in AWS Prod"),
    ("DeployNode","DN-SRV-001","DeployNode","DN-CLD-ONPREM","connects-to","","","Production","App Server OnPrem"),
    ("DeployNode","DN-DB-001","DeployNode","DN-CLD-ONPREM","connects-to","","","Production","Oracle RAC OnPrem"),
]

def main():
    print(f"Seeding Deploy Topology into: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(DDL)

    ins_n = 0; skip_n = 0
    for row in NODES:
        (nid, name, node_type, env, provider, region, hostname, ip, os_, spec,
         version, status, tags) = row
        existing = conn.execute("SELECT id FROM deploy_nodes WHERE id=?", (nid,)).fetchone()
        if existing:
            skip_n += 1
            continue
        conn.execute("""
            INSERT INTO deploy_nodes
            (id,name,node_type,environment,provider,region,hostname,ip_address,
             os,spec,version,status,notes,tags,x,y,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)
        """, (nid, name, node_type, env, provider, region, hostname, ip,
              os_, spec, version, status, "", tags, NOW, NOW))
        ins_n += 1

    ins_e = 0; skip_e = 0
    for row in EDGES:
        (src_type, src_id, tgt_type, tgt_id,
         edge_type, protocol, port, env, label) = row
        existing = conn.execute(
            "SELECT id FROM deploy_edges WHERE src_id=? AND tgt_id=? AND edge_type=?",
            (src_id, tgt_id, edge_type)
        ).fetchone()
        if existing:
            skip_e += 1
            continue
        eid = "DE-" + str(uuid.uuid4())[:8].upper()
        conn.execute("""
            INSERT INTO deploy_edges
            (id,src_type,src_id,tgt_type,tgt_id,edge_type,protocol,port,environment,label,notes,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (eid, src_type, src_id, tgt_type, tgt_id, edge_type, protocol, port, env, label, "", NOW))
        ins_e += 1

    conn.commit()
    conn.close()

    print(f"\n✅ Deployment Topology Seeded")
    print(f"   Nodes  inserted: {ins_n} | skipped: {skip_n}")
    print(f"   Edges  inserted: {ins_e} | skipped: {skip_e}")
    print(f"   Total nodes: {len(NODES)} | Total edges: {len(EDGES)}")
    print("\nNode types:")
    from collections import Counter
    types = Counter(r[2] for r in NODES)
    for t,c in sorted(types.items()):
        print(f"   {t}: {c}")

if __name__ == "__main__":
    main()
