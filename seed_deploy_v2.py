#!/usr/bin/env python3
"""
seed_deploy_v2.py — Extended Deployment Topology Seed (v2)
Covers 30+ apps across all domains: Finance, CRM, HR, Analytics,
Infrastructure, Security, Operations, Supply Chain, Digital, Customer

Run: python3 seed_deploy_v2.py
"""
import sqlite3, json, os, uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "appport.db")
NOW = datetime.utcnow().isoformat(timespec="seconds")

# ─── Additional Nodes ──────────────────────────────────────────────────────────
# Format: (id, name, node_type, environment, provider, region, hostname, ip, os, spec, version, status, tags)

NEW_NODES = [
    # ── Cloud Zones (new providers) ─────────────────────────────────────────────
    ("DN-CLD-AZ-PROD",   "Azure Southeast Asia (Prod)", "CloudZone", "Production", "Azure",        "Southeast Asia",   "", "", "", "", "VNet + Availability Zones", "Active", '["azure","prod"]'),
    ("DN-CLD-AZ-UAT",    "Azure Southeast Asia (UAT)",  "CloudZone", "UAT",        "Azure",        "Southeast Asia",   "", "", "", "", "VNet UAT", "Active", '["azure","uat"]'),
    ("DN-CLD-GCP-PROD",  "GCP asia-southeast1 (Prod)",  "CloudZone", "Production", "GCP",          "asia-southeast1",  "", "", "", "", "VPC Prod", "Active", '["gcp","prod"]'),
    ("DN-CLD-SAAS",      "SaaS / Cloud Services",       "CloudZone", "Production", "Multi-Cloud",  "Global",           "", "", "", "", "3rd Party SaaS", "Active", '["saas"]'),
    ("DN-CLD-IBM",       "IBM Cloud (Bangkok DC)",       "CloudZone", "Production", "IBM",          "Bangkok HQ",       "", "", "", "", "On-Premise IBM", "Active", '["ibm","onprem"]'),

    # ── Azure Infrastructure ─────────────────────────────────────────────────────
    ("DN-AZ-AKS-001",  "AKS Cluster (Prod)",          "K8sCluster", "Production", "Azure", "Southeast Asia", "aks-prod.azure", "10.1.0.10", "Azure AKS",   "5 nodes D4s_v3",  "AKS 1.28",    "Active", '["azure","k8s"]'),
    ("DN-AZ-AKS-002",  "AKS Cluster (UAT)",           "K8sCluster", "UAT",        "Azure", "Southeast Asia", "aks-uat.azure",  "10.1.0.11", "Azure AKS",   "3 nodes D2s_v3",  "AKS 1.28",    "Active", '["azure","k8s","uat"]'),
    ("DN-AZ-APIM",     "Azure API Management",        "Gateway",    "Production", "Azure", "Southeast Asia", "apim.azure.com","",          "Azure APIM",  "Standard v2",     "APIM",        "Active", '["azure","api"]'),
    ("DN-AZ-DB-001",   "Azure SQL (Finance)",         "Database",   "Production", "Azure", "Southeast Asia", "fin-sql.azure",  "10.1.5.10", "Azure SQL",   "GP_Gen5_8",       "SQL 2022",    "Active", '["azure","sql","finance"]'),
    ("DN-AZ-COSMOS",   "Azure CosmosDB",              "Database",   "Production", "Azure", "Southeast Asia", "cosmos.azure",   "10.1.5.20", "CosmosDB",    "Provisioned 4000RU","v4",         "Active", '["azure","nosql"]'),
    ("DN-AZ-REDIS",    "Azure Cache for Redis",       "Cache",      "Production", "Azure", "Southeast Asia", "redis.azure",    "10.1.6.10", "Azure Redis", "C3 Standard",     "Redis 6.0",   "Active", '["azure","cache"]'),
    ("DN-AZ-SB",       "Azure Service Bus",           "Queue",      "Production", "Azure", "Southeast Asia", "sb.azure",       "",          "Azure SB",    "Premium 1MU",     "AMQP 1.0",    "Active", '["azure","queue"]'),
    ("DN-AZ-BLOB",     "Azure Blob Storage",          "Storage",    "Production", "Azure", "Southeast Asia", "blob.azure",     "",          "Azure Blob",  "LRS Hot Tier",    "REST",        "Active", '["azure","storage"]'),
    ("DN-AZ-LB",       "Azure Application Gateway",  "LoadBalancer","Production","Azure", "Southeast Asia", "agw.azure",      "10.1.1.10", "Azure AGW",   "WAF v2",          "WAFv2",       "Active", '["azure","lb","waf"]'),

    # ── GCP Infrastructure ───────────────────────────────────────────────────────
    ("DN-GCP-GKE-001", "GKE Cluster (Analytics)",    "K8sCluster", "Production", "GCP",   "asia-southeast1","gke-prod.gcp",  "", "GCP GKE",     "5 nodes n2-std-4","GKE 1.28",    "Active", '["gcp","k8s","analytics"]'),
    ("DN-GCP-BQ",      "Google BigQuery",             "Database",   "Production", "GCP",   "asia-southeast1","bigquery.gcp",  "", "BigQuery",    "On-demand",       "BigQuery",    "Active", '["gcp","dw","analytics"]'),
    ("DN-GCP-GCS",     "Google Cloud Storage",       "Storage",    "Production", "GCP",   "asia-southeast1","gcs.gcp",       "", "GCS",         "Standard",        "GCS",         "Active", '["gcp","storage"]'),
    ("DN-GCP-PUBSUB",  "Google Pub/Sub",             "Queue",      "Production", "GCP",   "asia-southeast1","pubsub.gcp",    "", "Pub/Sub",     "Standard",        "Pub/Sub",     "Active", '["gcp","queue","streaming"]'),
    ("DN-GCP-CR",      "Cloud Run (AI Workloads)",   "Container",  "Production", "GCP",   "asia-southeast1","run.gcp",       "", "Cloud Run",   "2vCPU 4GB",       "CR",          "Active", '["gcp","serverless","ai"]'),

    # ── IBM / Legacy Infrastructure ──────────────────────────────────────────────
    ("DN-IBM-AS400-01","IBM i AS/400 #1 (Core)",     "Server",     "Production", "IBM",   "Bangkok HQ",     "as400-01.mpx",  "192.168.50.10","IBM i 7.5","POWER9 128GB",  "IBM i 7.5",   "Active", '["ibm","legacy","core"]'),
    ("DN-IBM-AS400-02","IBM i AS/400 #2 (HR/Payroll)","Server",    "Production", "IBM",   "Bangkok HQ",     "as400-02.mpx",  "192.168.50.11","IBM i 7.5","POWER9 64GB",   "IBM i 7.5",   "Active", '["ibm","legacy","hr"]'),
    ("DN-IBM-MF-01",   "IBM Mainframe z/OS",         "Server",     "Production", "IBM",   "Bangkok HQ",     "mainframe.mpx", "192.168.50.20","IBM z/OS 2.5","IBM z16 4IFL","z/OS 2.5",  "Active", '["ibm","mainframe","legacy"]'),
    ("DN-IBM-DB2-01",  "IBM DB2/400 (Core Banking)", "Database",   "Production", "IBM",   "Bangkok HQ",     "db2-core.mpx",  "192.168.50.51","IBM DB2",  "POWER9 256GB",  "DB2 7.5",     "Active", '["ibm","db2","core"]'),
    ("DN-IBM-DB2-02",  "IBM DB2/400 (HR/Payroll)",   "Database",   "Production", "IBM",   "Bangkok HQ",     "db2-hr.mpx",    "192.168.50.52","IBM DB2",  "POWER9 128GB",  "DB2 7.5",     "Active", '["ibm","db2","hr"]'),

    # ── SAP Infrastructure ───────────────────────────────────────────────────────
    ("DN-SAP-APP-01",  "SAP Application Server #1",  "Server",     "Production", "On-Premise","Bangkok HQ","sap-app1.mpx",  "192.168.60.11","SUSE 15 SP4","16vCPU 128GB","SAP NW 7.57","Active",'["sap","erp"]'),
    ("DN-SAP-APP-02",  "SAP Application Server #2",  "Server",     "Production", "On-Premise","Bangkok HQ","sap-app2.mpx",  "192.168.60.12","SUSE 15 SP4","16vCPU 128GB","SAP NW 7.57","Active",'["sap","erp"]'),
    ("DN-SAP-HANA-01", "SAP HANA DB (Production)",   "Database",   "Production", "On-Premise","Bangkok HQ","sap-hana1.mpx", "192.168.60.51","SUSE 15 SP4","32vCPU 768GB","SAP HANA 2.0","Active",'["sap","hana","erp"]'),
    ("DN-SAP-HANA-02", "SAP HANA DB (Supply Chain)", "Database",   "Production", "On-Premise","Bangkok HQ","sap-hana2.mpx", "192.168.60.52","SUSE 15 SP4","32vCPU 512GB","SAP HANA 2.0","Active",'["sap","hana","supply"]'),
    ("DN-SAP-ROUTER",  "SAP Router / Web Dispatcher","Gateway",    "Production", "On-Premise","Bangkok HQ","sap-wd.mpx",    "192.168.60.10","SUSE 15",   "4vCPU 16GB",  "SAP WD 7.57","Active",'["sap","gateway"]'),

    # ── Windows / SQL Server Infrastructure ──────────────────────────────────────
    ("DN-WIN-SRV-001", "Windows App Server (Finance)","Server",    "Production", "On-Premise","Bangkok HQ","fin-app1.mpx",  "192.168.70.11","WS 2022",   "8vCPU 64GB",  "WS 2022",     "Active",'["windows","finance"]'),
    ("DN-WIN-SRV-002", "Windows App Server (Ops)",   "Server",     "Production", "On-Premise","Bangkok HQ","ops-app1.mpx",  "192.168.70.12","WS 2019",   "8vCPU 32GB",  "WS 2019",     "Active",'["windows","ops"]'),
    ("DN-WIN-SRV-003", "Windows App Server (Treasury)","Server",   "Production", "On-Premise","Bangkok HQ","tsy-app1.mpx",  "192.168.70.13","WS 2022",   "8vCPU 64GB",  "WS 2022",     "Active",'["windows","finance"]'),
    ("DN-MSSQL-002",   "MS SQL Server (Operations)", "Database",   "Production", "On-Premise","Bangkok HQ","sql-ops.mpx",   "192.168.70.51","WS 2022",   "16vCPU 128GB","SQL 2022",    "Active",'["mssql","ops"]'),
    ("DN-MSSQL-003",   "MS SQL Server (Batch/ETL)",  "Database",   "Production", "On-Premise","Bangkok HQ","sql-etl.mpx",   "192.168.70.52","WS 2019",   "8vCPU 64GB",  "SQL 2019",    "Active",'["mssql","etl"]'),
    ("DN-ORA-001",     "Oracle DB (Risk/Finance)",   "Database",   "Production", "On-Premise","Bangkok HQ","ora-fin.mpx",   "192.168.70.60","Oracle Linux 8","16vCPU 256GB","Oracle 19c","Active",'["oracle","finance"]'),

    # ── Specialized Infrastructure ────────────────────────────────────────────────
    ("DN-SNOW-001",    "Snowflake Data Cloud",       "Database",   "Production", "AWS",   "ap-southeast-1", "snowflake.cloud","", "Snowflake", "Enterprise",     "Snowflake",   "Active",'["cloud","dw","saas"]'),
    ("DN-KAFKA-002",   "Kafka Cluster (IoT/Stream)", "Queue",      "Production", "AWS",   "ap-southeast-1", "kafka2.mpx",    "10.0.40.10","Ubuntu 20.04","5 brokers 16vCPU","Kafka 3.5","Active",'["kafka","iot","streaming"]'),
    ("DN-TSDB-001",    "TimescaleDB (IoT)",          "Database",   "Production", "AWS",   "ap-southeast-1", "tsdb.aws",      "10.0.5.30", "Amazon RDS","db.r5.2xlarge", "PG+Timescale", "Active",'["timescale","iot","tsdb"]'),
    ("DN-ELASTIC-001", "Elasticsearch Cluster",      "Database",   "Production", "AWS",   "ap-southeast-1", "elastic.aws",   "10.0.5.40", "Amazon ES", "3 nodes r6g.2xl","ES 8.x",    "Active",'["elastic","search","siem"]'),
    ("DN-SPLUNK-001",  "Splunk Enterprise Cluster",  "Server",     "Production", "On-Premise","Bangkok HQ","splunk.mpx",    "192.168.80.10","RHEL 8","3 indexers 32GB","Splunk 9.x","Active",'["splunk","siem","security"]'),
    ("DN-VAULT-001",   "HashiCorp Vault",            "Server",     "Production", "AWS",   "ap-southeast-1", "vault.aws",     "10.0.2.50", "Amazon Linux 2","t3.medium",   "Vault 1.14",  "Active",'["vault","secrets","security"]'),
    ("DN-LDAP-001",    "Active Directory / LDAP",    "Server",     "Production", "On-Premise","Bangkok HQ","ad.mpx.local",  "192.168.1.20","WS 2022",  "4vCPU 16GB",  "AD DS",       "Active",'["ad","ldap","identity"]'),
    ("DN-NFS-001",     "NFS / File Share Server",    "Storage",    "Production", "On-Premise","Bangkok HQ","nfs.mpx.local", "192.168.90.10","RHEL 8",  "2vCPU 8GB 50TB NAS","NFS 4.1", "Active",'["nfs","storage","shared"]'),

    # ── SaaS Representations ─────────────────────────────────────────────────────
    ("DN-SAAS-SF",     "Salesforce Platform",        "ExternalAPI","Production","External","US (SaaS)","salesforce.com","","SaaS","Multi-tenant","Spring 24","Active",'["saas","crm"]'),
    ("DN-SAAS-WD",     "Workday Platform",           "ExternalAPI","Production","External","US (SaaS)","workday.com",   "","SaaS","Multi-tenant","2024R1",   "Active",'["saas","hcm","hr"]'),
    ("DN-SAAS-OKTA",   "Okta Identity Cloud",        "ExternalAPI","Production","External","US (SaaS)","okta.com",      "","SaaS","Multi-tenant","2024.04",  "Active",'["saas","identity","iam"]'),
    ("DN-SAAS-SN",     "ServiceNow Cloud",           "ExternalAPI","Production","External","US (SaaS)","service-now.com","","SaaS","Multi-tenant","Washington","Active",'["saas","itsm"]'),
    ("DN-SAAS-AZURE",  "Azure Active Directory",     "ExternalAPI","Production","External","Global","aad.microsoft.com","","SaaS","Multi-tenant","AAD",    "Active",'["saas","identity","azure"]'),
    ("DN-EXT-BOT",     "Bank of Thailand API",       "ExternalAPI","Production","External","Thailand","bot.or.th",     "","External REST","Rate/FX Data","v3","Active",'["external","finance","fx"]'),
    ("DN-EXT-SET",     "SET Market Data API",        "ExternalAPI","Production","External","Thailand","set.or.th",     "","External REST","Market Data","v2","Active",'["external","finance","market"]'),
    ("DN-EXT-KBANK",   "KBank Open Banking API",     "ExternalAPI","Production","External","Thailand","openapi.kasikornbank.com","","REST","Open Banking","v3","Active",'["external","banking"]'),
    ("DN-EXT-NDID",    "NDID e-KYC",                "ExternalAPI","Production","External","Thailand","ndid.co.th",    "","REST","Identity Verify","v2","Active",'["external","kyc","identity"]'),
    ("DN-EXT-PROMPT",  "PromptPay (ITMX)",          "ExternalAPI","Production","External","Thailand","itmx.co.th",    "","ISO 20022","Payment Rail","v3","Active",'["external","payment","promptpay"]'),
]

# ─── Additional Edges ──────────────────────────────────────────────────────────
# Format: (src_type, src_id, tgt_type, tgt_id, edge_type, protocol, port, env, label)

NEW_EDGES = [
    # ── APP-001 SAP S/4HANA ───────────────────────────────────────────────────────
    ("Application","APP-001","DeployNode","DN-SAP-ROUTER",  "routes-to",   "HTTPS","443","Production","SAP Web Dispatcher"),
    ("Application","APP-001","DeployNode","DN-SAP-APP-01",  "deploys-on",  "HTTP", "8080","Production","SAP App Server 1"),
    ("Application","APP-001","DeployNode","DN-SAP-APP-02",  "deploys-on",  "HTTP", "8080","Production","SAP App Server 2"),
    ("Application","APP-001","DeployNode","DN-SAP-HANA-01", "uses",        "JDBC", "30015","Production","SAP HANA Primary"),
    ("Application","APP-001","DeployNode","DN-LDAP-001",    "calls",       "LDAP", "389","Production","AD Authentication"),
    ("Application","APP-001","DeployNode","DN-NFS-001",     "uses",        "NFS",  "2049","Production","File Attachments"),
    ("Application","APP-001","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Premise DC"),
    ("Application","APP-001","DeployNode","DN-EXT-BOT",     "calls",       "HTTPS","443","Production","FX Rate Feed"),

    # ── APP-002 Salesforce CRM ───────────────────────────────────────────────────
    ("Application","APP-002","DeployNode","DN-SAAS-SF",     "deploys-on",  "HTTPS","443","Production","Salesforce SaaS"),
    ("Application","APP-002","DeployNode","DN-CLD-SAAS",    "connects-to", "","","Production","SaaS Zone"),
    ("Application","APP-002","DeployNode","DN-SAAS-OKTA",   "uses",        "HTTPS","443","Production","SSO via Okta"),
    ("Application","APP-002","DeployNode","DN-AZ-APIM",     "routes-to",   "HTTPS","443","Production","Integration via APIM"),
    ("Application","APP-002","DeployNode","DN-EXT-KBANK",   "calls",       "HTTPS","443","Production","Payment Integration"),

    # ── APP-003 Core Banking AS/400 ──────────────────────────────────────────────
    ("Application","APP-003","DeployNode","DN-IBM-AS400-01","deploys-on",  "SNA",  "","Production","IBM i Primary"),
    ("Application","APP-003","DeployNode","DN-IBM-DB2-01",  "uses",        "DRDA", "446","Production","DB2/400 Core"),
    ("Application","APP-003","DeployNode","DN-IBM-MF-01",   "calls",       "MQ",   "1414","Production","Mainframe GL Batch"),
    ("Application","APP-003","DeployNode","DN-MQ-002",      "calls",       "Kafka","9092","Production","Real-time Events"),
    ("Application","APP-003","DeployNode","DN-CLD-IBM",     "connects-to", "","","Production","IBM DC Zone"),
    ("Application","APP-003","DeployNode","DN-EXT-002",     "calls",       "HTTPS","443","Production","SWIFT Payments"),
    ("Application","APP-003","DeployNode","DN-EXT-PROMPT",  "calls",       "HTTPS","443","Production","PromptPay"),
    ("Application","APP-003","DeployNode","DN-FW-001",      "routes-to",   "TCP",  "","Production","All via Firewall"),

    # ── APP-004 HR WorkDay ────────────────────────────────────────────────────────
    ("Application","APP-004","DeployNode","DN-SAAS-WD",     "deploys-on",  "HTTPS","443","Production","Workday SaaS"),
    ("Application","APP-004","DeployNode","DN-SAAS-OKTA",   "uses",        "SAML", "443","Production","SSO/SAML"),
    ("Application","APP-004","DeployNode","DN-CLD-SAAS",    "connects-to", "","","Production","SaaS Zone"),
    ("Application","APP-004","DeployNode","DN-AZ-APIM",     "routes-to",   "HTTPS","443","Production","HR Data Integration"),
    ("Application","APP-004","DeployNode","DN-LDAP-001",    "calls",       "LDAP", "389","Production","AD Sync"),

    # ── APP-005 AI Analytics Hub ──────────────────────────────────────────────────
    ("Application","APP-005","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Cluster"),
    ("Application","APP-005","DeployNode","DN-GCP-GKE-001", "deploys-on",  "","","Production","GKE AI Workloads"),
    ("Application","APP-005","DeployNode","DN-GCP-CR",      "uses",        "HTTPS","443","Production","Cloud Run Inference"),
    ("Application","APP-005","DeployNode","DN-DB-003",      "uses",        "JDBC", "5432","Production","App PostgreSQL"),
    ("Application","APP-005","DeployNode","DN-GCP-BQ",      "uses",        "JDBC", "443","Production","BigQuery Analytics"),
    ("Application","APP-005","DeployNode","DN-SNOW-001",    "calls",       "JDBC", "443","Production","Snowflake DW"),
    ("Application","APP-005","DeployNode","DN-CACHE-001",   "caches",      "TCP",  "6379","Production","Redis Feature Cache"),
    ("Application","APP-005","DeployNode","DN-GCP-PUBSUB",  "calls",       "HTTPS","443","Production","Event Streaming"),
    ("Application","APP-005","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","AWS Prod Zone"),
    ("Application","APP-005","DeployNode","DN-CLD-GCP-PROD","connects-to","","","Production","GCP Prod Zone"),

    # ── APP-007 K8s Platform ──────────────────────────────────────────────────────
    ("Application","APP-007","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Prod Cluster"),
    ("Application","APP-007","DeployNode","DN-K8S-002",     "deploys-on",  "","","UAT","EKS UAT Cluster"),
    ("Application","APP-007","DeployNode","DN-AZ-AKS-001",  "deploys-on",  "","","Production","AKS Prod Cluster"),
    ("Application","APP-007","DeployNode","DN-GCP-GKE-001", "deploys-on",  "","","Production","GKE Analytics Cluster"),
    ("Application","APP-007","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","AWS Zone"),
    ("Application","APP-007","DeployNode","DN-CLD-AZ-PROD", "connects-to","","","Production","Azure Zone"),
    ("Application","APP-007","DeployNode","DN-CLD-GCP-PROD","connects-to","","","Production","GCP Zone"),
    ("Application","APP-007","DeployNode","DN-VAULT-001",   "uses",        "HTTPS","8200","Production","Secrets Management"),

    # ── APP-008 Data Warehouse v2 (Snowflake) ─────────────────────────────────────
    ("Application","APP-008","DeployNode","DN-SNOW-001",    "deploys-on",  "JDBC", "443","Production","Snowflake DW"),
    ("Application","APP-008","DeployNode","DN-CLD-SAAS",    "connects-to", "","","Production","SaaS Zone"),
    ("Application","APP-008","DeployNode","DN-MQ-002",      "calls",       "Kafka","9092","Production","Kafka CDC Source"),
    ("Application","APP-008","DeployNode","DN-GCP-GCS",     "uses",        "HTTPS","443","Production","GCS Data Lake"),
    ("Application","APP-008","DeployNode","DN-DB-004",      "replicates-to","JDBC","5439","Production","Redshift Mirror"),

    # ── APP-009 Supply Chain SAP ──────────────────────────────────────────────────
    ("Application","APP-009","DeployNode","DN-SAP-APP-01",  "deploys-on",  "HTTP", "8080","Production","SAP App Server"),
    ("Application","APP-009","DeployNode","DN-SAP-HANA-02", "uses",        "JDBC", "30015","Production","SAP HANA SC"),
    ("Application","APP-009","DeployNode","DN-SAP-ROUTER",  "routes-to",   "HTTPS","443","Production","SAP Web Dispatcher"),
    ("Application","APP-009","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Prem DC"),
    ("Application","APP-009","DeployNode","DN-MQ-001",      "calls",       "HTTPS","443","Production","SQS Async Orders"),

    # ── APP-010 Customer Portal ────────────────────────────────────────────────────
    ("Application","APP-010","DeployNode","DN-CDN-001",     "routes-to",   "HTTPS","443","Production","CloudFront CDN"),
    ("Application","APP-010","DeployNode","DN-LB-001",      "hosts",       "HTTPS","443","Production","AWS ALB"),
    ("Application","APP-010","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Cluster"),
    ("Application","APP-010","DeployNode","DN-DB-003",      "uses",        "JDBC", "5432","Production","PostgreSQL"),
    ("Application","APP-010","DeployNode","DN-CACHE-001",   "caches",      "TCP",  "6379","Production","Session Cache"),
    ("Application","APP-010","DeployNode","DN-GW-001",      "routes-to",   "HTTPS","443","Production","API Gateway"),
    ("Application","APP-010","DeployNode","DN-SAAS-OKTA",   "uses",        "OIDC", "443","Production","OAuth Login"),
    ("Application","APP-010","DeployNode","DN-EXT-NDID",    "calls",       "HTTPS","443","Production","eKYC Verification"),

    # ── APP-016 Identity Platform (Okta) ──────────────────────────────────────────
    ("Application","APP-016","DeployNode","DN-SAAS-OKTA",   "deploys-on",  "HTTPS","443","Production","Okta SaaS"),
    ("Application","APP-016","DeployNode","DN-LDAP-001",    "uses",        "LDAP", "389","Production","AD Directory Sync"),
    ("Application","APP-016","DeployNode","DN-CLD-SAAS",    "connects-to", "","","Production","SaaS Zone"),
    ("Application","APP-016","DeployNode","DN-SAAS-AZURE",  "replicates-to","HTTPS","443","Production","Azure AD Sync"),

    # ── APP-017 ITSM ServiceNow ────────────────────────────────────────────────────
    ("Application","APP-017","DeployNode","DN-SAAS-SN",     "deploys-on",  "HTTPS","443","Production","ServiceNow SaaS"),
    ("Application","APP-017","DeployNode","DN-CLD-SAAS",    "connects-to", "","","Production","SaaS Zone"),
    ("Application","APP-017","DeployNode","DN-ELASTIC-001", "uses",        "HTTPS","9200","Production","Log Search"),
    ("Application","APP-017","DeployNode","DN-AZ-SB",       "calls",       "AMQP","5671","Production","Event Integration"),

    # ── APP-018 Batch Processing v2 ───────────────────────────────────────────────
    ("Application","APP-018","DeployNode","DN-SRV-007",     "deploys-on",  "","","Production","RHEL Batch Server"),
    ("Application","APP-018","DeployNode","DN-ORA-001",     "uses",        "JDBC", "1521","Production","Oracle 12c"),
    ("Application","APP-018","DeployNode","DN-MQ-002",      "calls",       "Kafka","9092","Production","Output Events"),
    ("Application","APP-018","DeployNode","DN-NFS-001",     "uses",        "NFS",  "2049","Production","Batch File Input"),
    ("Application","APP-018","DeployNode","DN-MSSQL-003",   "uses",        "JDBC", "1433","Production","ETL Target"),
    ("Application","APP-018","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Prem DC"),

    # ── APP-022 e-Commerce Platform ───────────────────────────────────────────────
    ("Application","APP-022","DeployNode","DN-CDN-001",     "routes-to",   "HTTPS","443","Production","CloudFront CDN"),
    ("Application","APP-022","DeployNode","DN-AZ-LB",       "hosts",       "HTTPS","443","Production","Azure App Gateway WAF"),
    ("Application","APP-022","DeployNode","DN-AZ-AKS-001",  "deploys-on",  "","","Production","AKS Cluster"),
    ("Application","APP-022","DeployNode","DN-AZ-DB-001",   "uses",        "JDBC", "1433","Production","Azure SQL"),
    ("Application","APP-022","DeployNode","DN-AZ-REDIS",    "caches",      "TCP",  "6380","Production","Session & Cart Cache"),
    ("Application","APP-022","DeployNode","DN-AZ-BLOB",     "uses",        "HTTPS","443","Production","Product Images"),
    ("Application","APP-022","DeployNode","DN-AZ-SB",       "calls",       "AMQP","5671","Production","Order Events"),
    ("Application","APP-022","DeployNode","DN-CLD-AZ-PROD", "connects-to", "","","Production","Azure Zone"),
    ("Application","APP-022","DeployNode","DN-EXT-003",     "calls",       "HTTPS","443","Production","LINE Notify"),
    ("Application","APP-022","DeployNode","DN-EXT-PROMPT",  "calls",       "HTTPS","443","Production","PromptPay Checkout"),

    # ── APP-023 Risk Mgmt System ──────────────────────────────────────────────────
    ("Application","APP-023","DeployNode","DN-WIN-SRV-001", "deploys-on",  "","","Production","Finance App Server"),
    ("Application","APP-023","DeployNode","DN-ORA-001",     "uses",        "JDBC", "1521","Production","Oracle 19c"),
    ("Application","APP-023","DeployNode","DN-EXT-BOT",     "calls",       "HTTPS","443","Production","BOT Risk Data"),
    ("Application","APP-023","DeployNode","DN-EXT-SET",     "calls",       "HTTPS","443","Production","SET Market Data"),
    ("Application","APP-023","DeployNode","DN-KAFKA-002",   "calls",       "Kafka","9092","Production","Risk Event Stream"),
    ("Application","APP-023","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Prem DC"),

    # ── APP-024 ML Feature Store ──────────────────────────────────────────────────
    ("Application","APP-024","DeployNode","DN-GCP-GKE-001", "deploys-on",  "","","Production","GKE ML Cluster"),
    ("Application","APP-024","DeployNode","DN-GCP-CR",      "deploys-on",  "HTTPS","443","Production","Cloud Run Serving"),
    ("Application","APP-024","DeployNode","DN-DB-003",      "uses",        "JDBC", "5432","Production","Feature Registry DB"),
    ("Application","APP-024","DeployNode","DN-CACHE-001",   "caches",      "TCP",  "6379","Production","Feature Cache"),
    ("Application","APP-024","DeployNode","DN-GCP-BQ",      "uses",        "HTTPS","443","Production","Training Data"),
    ("Application","APP-024","DeployNode","DN-GCP-GCS",     "uses",        "HTTPS","443","Production","Model Artifacts"),
    ("Application","APP-024","DeployNode","DN-GCP-PUBSUB",  "calls",       "HTTPS","443","Production","Feature Updates"),

    # ── APP-029 ServiceMesh Istio ──────────────────────────────────────────────────
    ("Application","APP-029","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Mesh"),
    ("Application","APP-029","DeployNode","DN-AZ-AKS-001",  "deploys-on",  "","","Production","AKS Mesh"),
    ("Application","APP-029","DeployNode","DN-GCP-GKE-001", "deploys-on",  "","","Production","GKE Mesh"),
    ("Application","APP-029","DeployNode","DN-VAULT-001",   "uses",        "HTTPS","8200","Production","mTLS Cert Management"),

    # ── APP-032 Cyber SIEM (Splunk) ────────────────────────────────────────────────
    ("Application","APP-032","DeployNode","DN-SPLUNK-001",  "deploys-on",  "","","Production","Splunk Cluster"),
    ("Application","APP-032","DeployNode","DN-ELASTIC-001", "replicates-to","HTTPS","9200","Production","ES Mirror"),
    ("Application","APP-032","DeployNode","DN-KAFKA-002",   "calls",       "Kafka","9092","Production","Log Ingestion"),
    ("Application","APP-032","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Prem DC"),
    ("Application","APP-032","DeployNode","DN-CLD-AWS-PROD","connects-to", "","","Production","AWS Log Sources"),
    ("Application","APP-032","DeployNode","DN-FW-001",      "calls",       "Syslog","514","Production","Firewall Logs"),

    # ── APP-035 IoT Data Platform ──────────────────────────────────────────────────
    ("Application","APP-035","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Cluster"),
    ("Application","APP-035","DeployNode","DN-KAFKA-002",   "calls",       "Kafka","9092","Production","IoT Event Stream"),
    ("Application","APP-035","DeployNode","DN-TSDB-001",    "uses",        "JDBC", "5432","Production","TimescaleDB"),
    ("Application","APP-035","DeployNode","DN-STG-001",     "uses",        "HTTPS","443","Production","S3 Cold Storage"),
    ("Application","APP-035","DeployNode","DN-GCP-PUBSUB",  "calls",       "HTTPS","443","Production","GCP Event Bridge"),
    ("Application","APP-035","DeployNode","DN-GW-001",      "routes-to",   "MQTTS","8883","Production","MQTT API GW"),
    ("Application","APP-035","DeployNode","DN-CLD-AWS-PROD","connects-to", "","","Production","AWS Zone"),

    # ── APP-048 Fraud Detection AI ─────────────────────────────────────────────────
    ("Application","APP-048","DeployNode","DN-K8S-001",     "deploys-on",  "","","Production","EKS Cluster"),
    ("Application","APP-048","DeployNode","DN-GCP-CR",      "deploys-on",  "HTTPS","443","Production","Cloud Run Inference"),
    ("Application","APP-048","DeployNode","DN-KAFKA-002",   "calls",       "Kafka","9092","Production","Transaction Stream"),
    ("Application","APP-048","DeployNode","DN-DB-003",      "uses",        "JDBC", "5432","Production","Case DB"),
    ("Application","APP-048","DeployNode","DN-CACHE-001",   "caches",      "TCP",  "6379","Production","Rule Cache"),
    ("Application","APP-048","DeployNode","DN-ELASTIC-001", "uses",        "HTTPS","9200","Production","Alert Search"),
    ("Application","APP-048","DeployNode","DN-EXT-001",     "calls",       "HTTPS","443","Production","NCB Credit Check"),

    # ── APP-050 Gen-AI Copilot ─────────────────────────────────────────────────────
    ("Application","APP-050","DeployNode","DN-AZ-AKS-001",  "deploys-on",  "","","Production","AKS Cluster"),
    ("Application","APP-050","DeployNode","DN-AZ-COSMOS",   "uses",        "HTTPS","443","Production","CosmosDB Chat History"),
    ("Application","APP-050","DeployNode","DN-AZ-REDIS",    "caches",      "TCP",  "6380","Production","Prompt Cache"),
    ("Application","APP-050","DeployNode","DN-AZ-SB",       "calls",       "AMQP","5671","Production","Async AI Jobs"),
    ("Application","APP-050","DeployNode","DN-AZ-BLOB",     "uses",        "HTTPS","443","Production","Document Storage"),
    ("Application","APP-050","DeployNode","DN-AZ-APIM",     "routes-to",   "HTTPS","443","Production","AI API Gateway"),
    ("Application","APP-050","DeployNode","DN-CLD-AZ-PROD", "connects-to", "","","Production","Azure Zone"),
    ("Application","APP-050","DeployNode","DN-SAAS-OKTA",   "uses",        "OIDC", "443","Production","Auth"),

    # ── APP-065 PingFederate IAM ───────────────────────────────────────────────────
    ("Application","APP-065","DeployNode","DN-SRV-003",     "deploys-on",  "HTTPS","9031","Production","EC2 Ping Server"),
    ("Application","APP-065","DeployNode","DN-DB-003",      "uses",        "JDBC", "5432","Production","Config DB"),
    ("Application","APP-065","DeployNode","DN-LDAP-001",    "uses",        "LDAP", "389","Production","AD Directory"),
    ("Application","APP-065","DeployNode","DN-SAAS-AZURE",  "replicates-to","HTTPS","443","Production","Azure AD Federation"),
    ("Application","APP-065","DeployNode","DN-CLD-AWS-PROD","connects-to", "","","Production","AWS Zone"),

    # ── APP-075 SWIFT Gateway ──────────────────────────────────────────────────────
    ("Application","APP-075","DeployNode","DN-WIN-SRV-003", "deploys-on",  "","","Production","Treasury App Server"),
    ("Application","APP-075","DeployNode","DN-ORA-001",     "uses",        "JDBC", "1521","Production","Oracle DB"),
    ("Application","APP-075","DeployNode","DN-EXT-002",     "calls",       "HTTPS","443","Production","SWIFT Network"),
    ("Application","APP-075","DeployNode","DN-MQ-002",      "calls",       "Kafka","9092","Production","Settlement Events"),
    ("Application","APP-075","DeployNode","DN-FW-001",      "routes-to",   "TCP",  "","Production","Secure via FW"),
    ("Application","APP-075","DeployNode","DN-CLD-ONPREM",  "connects-to", "","","Production","On-Prem DC"),

    # ── Inter-app & Infrastructure connections ─────────────────────────────────────
    ("DeployNode","DN-SAP-APP-01","DeployNode","DN-SAP-HANA-01","uses",   "JDBC","30015","Production","SAP HANA primary"),
    ("DeployNode","DN-SAP-APP-02","DeployNode","DN-SAP-HANA-01","uses",   "JDBC","30015","Production","SAP HANA replica"),
    ("DeployNode","DN-AZ-AKS-001","DeployNode","DN-CLD-AZ-PROD","connects-to","","","Production","AKS in Azure VNet"),
    ("DeployNode","DN-AZ-AKS-002","DeployNode","DN-CLD-AZ-UAT","connects-to","","","UAT","AKS in Azure VNet UAT"),
    ("DeployNode","DN-GCP-GKE-001","DeployNode","DN-CLD-GCP-PROD","connects-to","","","Production","GKE in GCP VPC"),
    ("DeployNode","DN-IBM-AS400-01","DeployNode","DN-CLD-IBM","connects-to","","","Production","AS400 in IBM DC"),
    ("DeployNode","DN-IBM-MF-01","DeployNode","DN-CLD-IBM","connects-to","","","Production","Mainframe in IBM DC"),
    ("DeployNode","DN-SPLUNK-001","DeployNode","DN-CLD-ONPREM","connects-to","","","Production","Splunk On-Prem"),
    ("DeployNode","DN-WIN-SRV-001","DeployNode","DN-CLD-ONPREM","connects-to","","","Production","Finance Server On-Prem"),
    ("DeployNode","DN-SAP-APP-01","DeployNode","DN-CLD-ONPREM","connects-to","","","Production","SAP On-Prem"),
    ("DeployNode","DN-KAFKA-002","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","Kafka in AWS"),
    ("DeployNode","DN-TSDB-001","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","TimescaleDB in AWS"),
    ("DeployNode","DN-ELASTIC-001","DeployNode","DN-CLD-AWS-PROD","connects-to","","","Production","Elastic in AWS"),
]


def main():
    print(f"Seeding Extended Deploy Topology into: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # ensure tables exist
    conn.executescript("""
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
    """)

    ins_n = skip_n = 0
    for row in NEW_NODES:
        (nid, name, node_type, env, provider, region, hostname, ip,
         os_, spec, version, status, tags) = row
        if conn.execute("SELECT id FROM deploy_nodes WHERE id=?", (nid,)).fetchone():
            skip_n += 1; continue
        conn.execute("""
            INSERT INTO deploy_nodes
            (id,name,node_type,environment,provider,region,hostname,ip_address,
             os,spec,version,status,notes,tags,x,y,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)
        """, (nid, name, node_type, env, provider, region, hostname, ip,
              os_, spec, version, status, "", tags, NOW, NOW))
        ins_n += 1

    ins_e = skip_e = 0
    for row in NEW_EDGES:
        (src_type, src_id, tgt_type, tgt_id,
         edge_type, protocol, port, env, label) = row
        if conn.execute(
            "SELECT id FROM deploy_edges WHERE src_id=? AND tgt_id=? AND edge_type=?",
            (src_id, tgt_id, edge_type)
        ).fetchone():
            skip_e += 1; continue
        eid = "DE-" + str(uuid.uuid4())[:8].upper()
        conn.execute("""
            INSERT INTO deploy_edges
            (id,src_type,src_id,tgt_type,tgt_id,edge_type,protocol,port,environment,label,notes,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (eid, src_type, src_id, tgt_type, tgt_id,
              edge_type, protocol, port, env, label, "", NOW))
        ins_e += 1

    conn.commit()

    # summary stats
    total_n = conn.execute("SELECT COUNT(*) FROM deploy_nodes").fetchone()[0]
    total_e = conn.execute("SELECT COUNT(*) FROM deploy_edges").fetchone()[0]
    linked = conn.execute("""
        SELECT COUNT(DISTINCT src_id) FROM deploy_edges WHERE src_type='Application'
    """).fetchone()[0]
    conn.close()

    from collections import Counter
    print(f"\n✅ Extended Deployment Topology Seeded")
    print(f"   Nodes  inserted: {ins_n} | skipped: {skip_n} | total: {total_n}")
    print(f"   Edges  inserted: {ins_e} | skipped: {skip_e} | total: {total_e}")
    print(f"   Apps with topology: {linked}")
    print(f"\nNew node types added:")
    types = Counter(r[2] for r in NEW_NODES)
    for t, c in sorted(types.items()):
        print(f"   {t}: {c}")

if __name__ == "__main__":
    main()
