#!/usr/bin/env python3
"""
seed_tech.py — Seed 100 Tech Stack entries into ea_domains.db
Tables: tech_catalog, tech_versions, tech_servers, tech_usage, tech_radar
"""
import sqlite3, json, random
from datetime import datetime, timedelta

DB_PATH = "/Users/nuntapol/Desktop/bin/2.0 B32.43/ea_domains.db"
APP_DB  = "/Users/nuntapol/Desktop/bin/2.0 B32.43/appport.db"

# ── helpers ──────────────────────────────────────────────────────────────────
def ago(days): return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
def future(days): return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

# ── 100 Tech Catalog entries ──────────────────────────────────────────────────
# (name, vendor, category, sub_category, tier, standard_status, tags, description)
TECH_CATALOG = [
    # ── Languages ────────────────────────────────────────────────────────────
    ("Python",          "Python Software Foundation", "Language",   "Scripting",    "Tier 1","Approved",   ["open-source","interpreted"],        "General-purpose high-level language"),
    ("Java",            "Oracle",                      "Language",   "OOP",          "Tier 1","Approved",   ["open-source","jvm","enterprise"],    "Enterprise-grade OOP language on JVM"),
    ("Go",              "Google",                      "Language",   "Systems",      "Tier 2","Approved",   ["open-source","compiled","cloud"],    "Fast compiled language for cloud services"),
    ("TypeScript",      "Microsoft",                   "Language",   "Web",          "Tier 1","Approved",   ["open-source","typed","frontend"],    "Typed superset of JavaScript"),
    ("Kotlin",          "JetBrains",                   "Language",   "OOP",          "Tier 2","Approved",   ["jvm","android","modern"],            "Modern JVM language replacing Java"),
    ("Rust",            "Rust Foundation",             "Language",   "Systems",      "Tier 3","Trial",      ["open-source","memory-safe"],         "Systems language with memory safety"),
    ("C#",              "Microsoft",                   "Language",   "OOP",          "Tier 2","Approved",   ["dotnet","enterprise"],               ".NET ecosystem primary language"),
    ("Scala",           "EPFL",                        "Language",   "Functional",   "Tier 3","Hold",       ["jvm","functional","spark"],          "Functional + OOP on JVM, used in Spark"),
    ("R",               "R Foundation",                "Language",   "Data Science", "Tier 2","Approved",   ["open-source","statistics","data"],   "Statistical computing & visualization"),
    ("Swift",           "Apple",                       "Language",   "Mobile",       "Tier 2","Approved",   ["ios","mobile","apple"],              "iOS/macOS native language"),

    # ── Frameworks ───────────────────────────────────────────────────────────
    ("Spring Boot",     "VMware/Broadcom",             "Framework",  "Web Backend",  "Tier 1","Approved",   ["java","microservices","enterprise"],  "Java microservice framework"),
    ("FastAPI",         "Sebastián Ramírez",           "Framework",  "Web Backend",  "Tier 1","Approved",   ["python","async","openapi"],           "Modern async Python web framework"),
    ("React",           "Meta",                        "Framework",  "Frontend",     "Tier 1","Approved",   ["javascript","spa","frontend"],        "UI component library for SPA"),
    ("Angular",         "Google",                      "Framework",  "Frontend",     "Tier 2","Approved",   ["typescript","spa","enterprise"],      "Full-featured frontend framework"),
    ("Vue.js",          "Evan You",                    "Framework",  "Frontend",     "Tier 2","Approved",   ["javascript","spa","lightweight"],     "Progressive JavaScript framework"),
    ("Django",          "Django Software Foundation",  "Framework",  "Web Backend",  "Tier 2","Approved",   ["python","fullstack","orm"],           "Batteries-included Python web framework"),
    ("Express.js",      "OpenJS Foundation",           "Framework",  "Web Backend",  "Tier 2","Approved",   ["nodejs","rest","lightweight"],        "Minimal Node.js web framework"),
    ("Next.js",         "Vercel",                      "Framework",  "Frontend",     "Tier 2","Approved",   ["react","ssr","fullstack"],            "React SSR/SSG framework"),
    ("Quarkus",         "Red Hat",                     "Framework",  "Web Backend",  "Tier 3","Trial",      ["java","cloud-native","graalvm"],      "Kubernetes-native Java framework"),
    ("Flutter",         "Google",                      "Framework",  "Mobile",       "Tier 2","Approved",   ["dart","mobile","cross-platform"],    "Cross-platform mobile UI framework"),

    # ── Databases – RDBMS ────────────────────────────────────────────────────
    ("PostgreSQL",      "PostgreSQL Global Dev Group", "Database",   "RDBMS",        "Tier 1","Approved",   ["open-source","relational","acid"],    "Advanced open-source RDBMS"),
    ("MySQL",           "Oracle",                      "Database",   "RDBMS",        "Tier 2","Approved",   ["open-source","relational"],           "Widely-used open-source RDBMS"),
    ("Microsoft SQL Server","Microsoft",               "Database",   "RDBMS",        "Tier 1","Approved",   ["microsoft","enterprise","windows"],   "Enterprise-grade RDBMS by Microsoft"),
    ("Oracle Database", "Oracle",                      "Database",   "RDBMS",        "Tier 1","Approved",   ["enterprise","commercial","acid"],     "Enterprise RDBMS with advanced features"),
    ("MariaDB",         "MariaDB Foundation",          "Database",   "RDBMS",        "Tier 3","Hold",       ["open-source","mysql-compatible"],     "MySQL fork, may be superseded"),

    # ── Databases – NoSQL ────────────────────────────────────────────────────
    ("MongoDB",         "MongoDB Inc.",                "Database",   "Document",     "Tier 1","Approved",   ["nosql","document","flexible-schema"], "Document-oriented NoSQL database"),
    ("Redis",           "Redis Ltd.",                  "Database",   "In-Memory",    "Tier 1","Approved",   ["cache","session","pub-sub"],          "In-memory data structure store"),
    ("Elasticsearch",   "Elastic",                     "Database",   "Search",       "Tier 1","Approved",   ["search","analytics","logging"],       "Distributed search & analytics engine"),
    ("Apache Cassandra","Apache",                      "Database",   "Wide-Column",  "Tier 2","Approved",   ["open-source","distributed","nosql"],  "Distributed wide-column store"),
    ("ClickHouse",      "ClickHouse Inc.",             "Database",   "OLAP",         "Tier 2","Approved",   ["analytics","columnar","fast"],        "Column-oriented OLAP database"),

    # ── Messaging ────────────────────────────────────────────────────────────
    ("Apache Kafka",    "Apache",                      "Messaging",  "Event Stream", "Tier 1","Approved",   ["open-source","streaming","event"],    "Distributed event streaming platform"),
    ("RabbitMQ",        "Broadcom/VMware",             "Messaging",  "Message Queue","Tier 2","Approved",   ["amqp","queue","async"],              "Open-source message broker"),
    ("AWS SQS",         "Amazon",                      "Messaging",  "Cloud Queue",  "Tier 2","Approved",   ["cloud","aws","managed"],             "Fully managed message queue service"),
    ("Azure Service Bus","Microsoft",                  "Messaging",  "Cloud Queue",  "Tier 2","Approved",   ["cloud","azure","enterprise"],        "Cloud messaging service for Azure"),
    ("NATS",            "CNCF",                        "Messaging",  "Event Stream", "Tier 3","Trial",      ["cloud-native","lightweight","fast"],  "High-performance messaging system"),

    # ── Infrastructure / Platform ─────────────────────────────────────────────
    ("Kubernetes",      "CNCF",                        "Platform",   "Container Orchestration","Tier 1","Approved",["open-source","k8s","cloud-native"],"Container orchestration platform"),
    ("Docker",          "Docker Inc.",                 "Platform",   "Container",    "Tier 1","Approved",   ["container","devops","oci"],           "Container platform & runtime"),
    ("Helm",            "CNCF",                        "Platform",   "Package Manager","Tier 1","Approved", ["kubernetes","chart","deployment"],    "Kubernetes package manager"),
    ("Terraform",       "HashiCorp",                   "Tool",       "IaC",          "Tier 1","Approved",   ["iac","devops","multi-cloud"],         "Infrastructure as Code tool"),
    ("Ansible",         "Red Hat",                     "Tool",       "Config Mgmt",  "Tier 2","Approved",   ["automation","config","agentless"],   "Agentless IT automation"),
    ("ArgoCD",          "CNCF",                        "Tool",       "GitOps",       "Tier 1","Approved",   ["gitops","kubernetes","cd"],           "GitOps CD for Kubernetes"),

    # ── Cloud Providers ───────────────────────────────────────────────────────
    ("AWS EC2",         "Amazon",                      "Cloud",      "Compute",      "Tier 1","Approved",   ["aws","compute","virtual-machine"],    "Amazon EC2 virtual compute"),
    ("AWS RDS",         "Amazon",                      "Cloud",      "Managed DB",   "Tier 1","Approved",   ["aws","database","managed"],           "Amazon managed relational DB"),
    ("AWS S3",          "Amazon",                      "Cloud",      "Object Storage","Tier 1","Approved",  ["aws","storage","object"],             "Amazon object storage service"),
    ("Azure AKS",       "Microsoft",                   "Cloud",      "Managed K8s",  "Tier 1","Approved",   ["azure","kubernetes","managed"],       "Azure managed Kubernetes service"),
    ("Azure Blob Storage","Microsoft",                 "Cloud",      "Object Storage","Tier 2","Approved",  ["azure","storage","object"],           "Azure object storage service"),
    ("GCP BigQuery",    "Google",                      "Cloud",      "Data Warehouse","Tier 2","Approved",  ["gcp","analytics","serverless"],       "Google serverless data warehouse"),
    ("GCP GKE",         "Google",                      "Cloud",      "Managed K8s",  "Tier 2","Approved",   ["gcp","kubernetes","managed"],        "Google managed Kubernetes Engine"),

    # ── Security ──────────────────────────────────────────────────────────────
    ("HashiCorp Vault",  "HashiCorp",                  "Security",   "Secrets Mgmt", "Tier 1","Approved",   ["secrets","pki","encryption"],         "Secrets management & encryption"),
    ("Keycloak",         "Red Hat",                    "Security",   "IAM",          "Tier 1","Approved",   ["iam","sso","oauth2","oidc"],           "Open-source identity & access mgmt"),
    ("SonarQube",        "SonarSource",                "Security",   "Code Quality", "Tier 1","Approved",   ["sast","code-quality","devsecops"],    "Code quality & security scanner"),
    ("OWASP ZAP",        "OWASP",                      "Security",   "DAST",         "Tier 2","Approved",   ["dast","pen-test","open-source"],      "Dynamic application security testing"),
    ("Trivy",            "Aqua Security",              "Security",   "Container Scan","Tier 1","Approved",  ["vulnerability","container","iac"],    "Container & IaC vulnerability scanner"),
    ("Falco",            "CNCF",                       "Security",   "Runtime Sec",  "Tier 2","Trial",      ["runtime","kubernetes","detection"],   "Cloud-native runtime security"),

    # ── Observability ─────────────────────────────────────────────────────────
    ("Prometheus",       "CNCF",                       "Observability","Metrics",    "Tier 1","Approved",   ["monitoring","metrics","open-source"], "Monitoring & alerting toolkit"),
    ("Grafana",          "Grafana Labs",               "Observability","Dashboard",  "Tier 1","Approved",   ["dashboard","visualization","metrics"],"Observability & analytics platform"),
    ("Elastic APM",      "Elastic",                    "Observability","APM",        "Tier 2","Approved",   ["apm","tracing","performance"],        "Application performance monitoring"),
    ("Jaeger",           "CNCF",                       "Observability","Tracing",    "Tier 2","Approved",   ["tracing","distributed","open-source"],"Distributed tracing system"),
    ("OpenTelemetry",    "CNCF",                       "Observability","Telemetry",  "Tier 1","Approved",   ["otel","standard","observability"],    "Observability instrumentation standard"),
    ("Loki",             "Grafana Labs",               "Observability","Logging",    "Tier 2","Approved",   ["logging","grafana","lightweight"],    "Log aggregation system"),

    # ── DevOps / CI-CD ────────────────────────────────────────────────────────
    ("Jenkins",          "CloudBees/Community",        "Tool",       "CI/CD",        "Tier 2","Hold",       ["ci","java","legacy"],                 "Legacy CI/CD; plan to migrate"),
    ("GitLab CI",        "GitLab",                     "Tool",       "CI/CD",        "Tier 1","Approved",   ["ci-cd","devops","integrated"],        "Integrated GitLab CI/CD pipeline"),
    ("GitHub Actions",   "GitHub/Microsoft",           "Tool",       "CI/CD",        "Tier 1","Approved",   ["ci-cd","github","cloud"],             "Native GitHub automation & CI/CD"),
    ("Nexus Repository", "Sonatype",                   "Tool",       "Artifact Registry","Tier 1","Approved",["artifact","maven","npm"],            "Universal artifact repository manager"),
    ("Harbor",           "CNCF",                       "Tool",       "Container Registry","Tier 2","Approved",["registry","container","oci"],       "Cloud-native container registry"),
    ("SonarCloud",       "SonarSource",                "Tool",       "Code Quality", "Tier 2","Approved",   ["sast","cloud","code-quality"],        "Cloud-based code quality analysis"),

    # ── API / Integration ────────────────────────────────────────────────────
    ("Kong Gateway",     "Kong Inc.",                  "Platform",   "API Gateway",  "Tier 1","Approved",   ["api-gateway","proxy","plugins"],      "Open-source API gateway"),
    ("Apigee",           "Google/Apigee",              "Platform",   "API Gateway",  "Tier 2","Approved",   ["api-management","gcp","analytics"],   "Full lifecycle API management"),
    ("MuleSoft",         "Salesforce",                 "Platform",   "ESB/iPaaS",    "Tier 2","Approved",   ["integration","esb","enterprise"],    "Enterprise integration platform"),
    ("Apache Camel",     "Apache",                     "Framework",  "Integration",  "Tier 2","Approved",   ["open-source","eip","microservices"],  "Enterprise integration patterns library"),
    ("WSO2 API Manager", "WSO2",                       "Platform",   "API Gateway",  "Tier 3","Hold",       ["api","wso2","on-premise"],            "On-prem API management; under review"),

    # ── Data & Analytics ─────────────────────────────────────────────────────
    ("Apache Spark",     "Apache",                     "Platform",   "Big Data",     "Tier 1","Approved",   ["big-data","streaming","ml"],          "Unified analytics engine for big data"),
    ("Apache Airflow",   "Apache",                     "Tool",       "Workflow",     "Tier 1","Approved",   ["dag","etl","scheduler"],              "Workflow orchestration platform"),
    ("dbt",              "dbt Labs",                   "Tool",       "Data Transform","Tier 2","Approved",  ["sql","transformation","analytics"],   "SQL-first data transformation tool"),
    ("Databricks",       "Databricks",                 "Platform",   "Data Platform","Tier 1","Approved",   ["lakehouse","spark","ml"],             "Unified data analytics platform"),
    ("Apache Flink",     "Apache",                     "Platform",   "Streaming",    "Tier 2","Trial",      ["streaming","realtime","stateful"],    "Stateful stream processing engine"),
    ("Tableau",          "Salesforce",                 "Tool",       "BI/Viz",       "Tier 2","Approved",   ["bi","visualization","dashboard"],     "Business intelligence & analytics"),
    ("Power BI",         "Microsoft",                  "Tool",       "BI/Viz",       "Tier 1","Approved",   ["bi","microsoft","dashboard"],         "Microsoft business intelligence tool"),

    # ── ML / AI ──────────────────────────────────────────────────────────────
    ("TensorFlow",       "Google",                     "Framework",  "ML/DL",        "Tier 2","Approved",   ["ml","deep-learning","python"],        "Open-source machine learning platform"),
    ("PyTorch",          "Meta",                       "Framework",  "ML/DL",        "Tier 2","Approved",   ["ml","deep-learning","research"],     "Dynamic deep learning framework"),
    ("MLflow",           "Databricks",                 "Tool",       "ML Lifecycle", "Tier 2","Approved",   ["mlops","experiment","registry"],     "ML lifecycle management platform"),
    ("Hugging Face",     "Hugging Face",               "Platform",   "LLM/NLP",      "Tier 3","Trial",      ["llm","nlp","transformers"],           "Open-source ML model hub & library"),
    ("LangChain",        "LangChain Inc.",             "Framework",  "LLM/Agents",   "Tier 3","Trial",      ["llm","agents","rag"],                 "LLM application development framework"),
    ("Ray",              "Anyscale",                   "Platform",   "Distributed ML","Tier 3","Trial",     ["distributed","ml","python"],         "Distributed computing for AI/ML"),

    # ── OS / Runtime ─────────────────────────────────────────────────────────
    ("Ubuntu Server",    "Canonical",                  "OS",         "Linux",        "Tier 1","Approved",   ["linux","server","lts"],               "Enterprise Ubuntu LTS server OS"),
    ("Red Hat Enterprise Linux","Red Hat",             "OS",         "Linux",        "Tier 1","Approved",   ["linux","enterprise","rhel"],          "Enterprise Linux by Red Hat"),
    ("Windows Server",   "Microsoft",                  "OS",         "Windows",      "Tier 2","Approved",   ["windows","microsoft","enterprise"],   "Microsoft Windows Server OS"),
    ("Alpine Linux",     "Alpine Linux Project",       "OS",         "Linux",        "Tier 2","Approved",   ["container","minimal","musl"],         "Minimal Linux for containers"),
    ("Node.js",          "OpenJS Foundation",          "Runtime",    "JavaScript",   "Tier 1","Approved",   ["javascript","server","async"],        "JavaScript runtime on V8 engine"),
    ("JVM (OpenJDK)",    "OpenJDK Community",          "Runtime",    "JVM",          "Tier 1","Approved",   ["java","jvm","open-source"],           "Open-source Java Virtual Machine"),

    # ── Networking / Service Mesh ────────────────────────────────────────────
    ("Istio",            "CNCF",                       "Platform",   "Service Mesh", "Tier 1","Approved",   ["service-mesh","kubernetes","mtls"],   "Service mesh for microservices"),
    ("Nginx",            "F5/Nginx",                   "Platform",   "Web Server",   "Tier 1","Approved",   ["web-server","proxy","load-balancer"], "High-performance web server & proxy"),
    ("HAProxy",          "HAProxy Technologies",       "Platform",   "Load Balancer","Tier 2","Approved",   ["load-balancer","tcp","ha"],           "Reliable high-performance load balancer"),
    ("Consul",           "HashiCorp",                  "Platform",   "Service Discovery","Tier 2","Approved",["service-discovery","dns","config"],  "Service discovery & configuration"),

    # ── Storage ───────────────────────────────────────────────────────────────
    ("MinIO",            "MinIO Inc.",                 "Storage",    "Object Storage","Tier 2","Approved",  ["s3-compatible","on-prem","open-source"],"S3-compatible on-premise storage"),
    ("Ceph",             "CNCF",                       "Storage",    "Distributed FS","Tier 2","Approved",  ["distributed","block","object","file"], "Distributed storage cluster"),
    ("Longhorn",         "CNCF",                       "Storage",    "Block Storage","Tier 2","Approved",   ["kubernetes","persistent","csi"],      "Cloud-native block storage for K8s"),

    # ── Legacy / Retiring ─────────────────────────────────────────────────────
    ("SOAP/WS",          "W3C",                        "Protocol",   "Web Services", "Tier 4","Deprecated", ["legacy","soap","xml"],                "SOAP-based web services; decommissioning"),
    ("Oracle WebLogic",  "Oracle",                     "Platform",   "App Server",   "Tier 3","Hold",       ["java","app-server","legacy"],         "Oracle Java EE app server; migration planned"),
    ("IBM MQ",           "IBM",                        "Messaging",  "Message Queue","Tier 3","Hold",       ["ibm","messaging","enterprise"],       "IBM enterprise messaging; evaluating replacement"),
    ("Crystal Reports",  "SAP",                        "Tool",       "Reporting",    "Tier 4","Deprecated", ["legacy","reporting","sap"],           "Legacy Crystal Reports; replacing with Power BI"),
    ("Subversion (SVN)", "Apache",                     "Tool",       "VCS",          "Tier 4","Deprecated", ["legacy","vcs","cvs"],                 "Legacy VCS; migrated to Git"),
]

# ── Version data: (tech_name, versions[]) ────────────────────────────────────
# Each version: (label, major, minor, patch, type, release_date, eol_date, lifecycle, is_latest, is_lts)
TECH_VERSIONS = {
    "Python":           [
        ("3.12.3", 3,12,3,"GA",  ago(180), future(365*2), "Active",    1, 0),
        ("3.11.9", 3,11,9,"LTS", ago(400), future(365),   "Active",    0, 1),
        ("3.10.14",3,10,14,"LTS",ago(730), ago(90),       "EOL",       0, 1),
        ("3.9.19", 3, 9,19,"LTS",ago(1200),ago(30),       "EOL",       0, 1),
    ],
    "Java":             [
        ("21.0.3", 21,0,3,"LTS", ago(200), future(365*3), "Active",    1, 1),
        ("17.0.11",17,0,11,"LTS",ago(400), future(365*2), "Active",    0, 1),
        ("11.0.23",11,0,23,"LTS",ago(900), future(180),   "Maintenance-only",0,1),
        ("8u412",  8,0,412,"LTS",ago(2000),future(90),    "Maintenance-only",0,1),
    ],
    "PostgreSQL":       [
        ("16.3",   16,3,0,"GA",  ago(30),  future(365*3), "Active",    1, 0),
        ("15.7",   15,7,0,"GA",  ago(200), future(365*2), "Active",    0, 0),
        ("14.12",  14,12,0,"GA", ago(500), future(365),   "Active",    0, 0),
        ("13.15",  13,15,0,"GA", ago(800), ago(60),       "EOL",       0, 0),
    ],
    "Redis":            [
        ("7.2.5",  7, 2,5,"GA",  ago(90),  future(365*2), "Active",    1, 0),
        ("7.0.15", 7, 0,15,"GA", ago(300), future(365),   "Active",    0, 0),
        ("6.2.14", 6, 2,14,"LTS",ago(700), ago(120),      "EOL",       0, 1),
    ],
    "MongoDB":          [
        ("7.0.9",  7, 0,9,"GA",  ago(60),  future(365*2), "Active",    1, 0),
        ("6.0.15", 6, 0,15,"LTS",ago(400), future(365),   "Active",    0, 1),
        ("5.0.26", 5, 0,26,"LTS",ago(800), ago(90),       "EOL",       0, 1),
    ],
    "React":            [
        ("18.3.1", 18,3,1,"GA",  ago(60),  None,          "Active",    1, 0),
        ("18.2.0", 18,2,0,"GA",  ago(300), None,          "Maintenance-only",0,0),
        ("17.0.2", 17,0,2,"GA",  ago(900), ago(180),      "EOL",       0, 0),
    ],
    "Kubernetes":       [
        ("1.30.1", 1,30,1,"GA",  ago(30),  future(365),   "Active",    1, 0),
        ("1.29.5", 1,29,5,"GA",  ago(150), future(270),   "Active",    0, 0),
        ("1.28.10",1,28,10,"GA", ago(300), future(90),    "Maintenance-only",0,0),
        ("1.27.14",1,27,14,"GA", ago(500), ago(30),       "EOL",       0, 0),
    ],
    "Apache Kafka":     [
        ("3.7.0",  3, 7,0,"GA",  ago(90),  future(365),   "Active",    1, 0),
        ("3.6.2",  3, 6,2,"GA",  ago(270), future(180),   "Active",    0, 0),
        ("3.4.1",  3, 4,1,"GA",  ago(600), ago(60),       "EOL",       0, 0),
    ],
    "Spring Boot":      [
        ("3.3.0",  3, 3,0,"GA",  ago(60),  future(365),   "Active",    1, 0),
        ("3.2.5",  3, 2,5,"GA",  ago(180), future(270),   "Active",    0, 0),
        ("2.7.18", 2, 7,18,"GA", ago(700), ago(180),      "EOL",       0, 0),
    ],
    "Elasticsearch":    [
        ("8.13.4", 8,13,4,"GA",  ago(30),  future(365),   "Active",    1, 0),
        ("8.12.2", 8,12,2,"GA",  ago(120), future(270),   "Active",    0, 0),
        ("7.17.21",7,17,21,"GA", ago(600), ago(90),       "EOL",       0, 0),
    ],
    "Node.js":          [
        ("20.14.0",20,14,0,"LTS",ago(90),  future(365*2), "Active",    1, 1),
        ("18.20.3",18,20,3,"LTS",ago(400), future(180),   "Active",    0, 1),
        ("16.20.2",16,20,2,"LTS",ago(700), ago(120),      "EOL",       0, 1),
    ],
    "Nginx":            [
        ("1.26.1", 1,26,1,"Stable",ago(60), future(365),  "Active",    1, 0),
        ("1.24.0", 1,24,0,"Stable",ago(400),future(180),  "Active",    0, 0),
        ("1.22.1", 1,22,1,"Stable",ago(700),ago(90),      "EOL",       0, 0),
    ],
    "Ubuntu Server":    [
        ("24.04 LTS",24,4,0,"LTS",ago(90), future(365*5), "Active",    1, 1),
        ("22.04 LTS",22,4,0,"LTS",ago(700),future(365*3), "Active",    0, 1),
        ("20.04 LTS",20,4,0,"LTS",ago(1500),future(365),  "Maintenance-only",0,1),
    ],
    "Docker":           [
        ("26.1.3", 26,1,3,"GA",  ago(30),  future(365),   "Active",    1, 0),
        ("25.0.5", 25,0,5,"GA",  ago(200), future(180),   "Active",    0, 0),
        ("24.0.9", 24,0,9,"GA",  ago(400), ago(60),       "EOL",       0, 0),
    ],
    "Terraform":        [
        ("1.8.4",  1, 8,4,"GA",  ago(30),  future(365),   "Active",    1, 0),
        ("1.7.5",  1, 7,5,"GA",  ago(150), future(180),   "Active",    0, 0),
        ("1.5.7",  1, 5,7,"GA",  ago(400), ago(60),       "EOL",       0, 0),
    ],
}

# ── Server inventory (15 servers) ─────────────────────────────────────────────
SERVERS = [
    ("prd-app-01",  "10.0.1.11", "Production", "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",16,64,"infra-team","Active"),
    ("prd-app-02",  "10.0.1.12", "Production", "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",16,64,"infra-team","Active"),
    ("prd-db-01",   "10.0.1.21", "Production", "Physical", "DC-Bangkok",  "Red Hat Enterprise Linux","9.2",32,256,"dba-team","Active"),
    ("prd-db-02",   "10.0.1.22", "Production", "Physical", "DC-Bangkok",  "Red Hat Enterprise Linux","9.2",32,256,"dba-team","Active"),
    ("prd-k8s-m01", "10.0.1.30", "Production", "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",8, 32,"platform-team","Active"),
    ("prd-k8s-w01", "10.0.1.31", "Production", "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",16,64,"platform-team","Active"),
    ("prd-k8s-w02", "10.0.1.32", "Production", "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",16,64,"platform-team","Active"),
    ("uat-app-01",  "10.0.2.11", "UAT",        "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",8, 32,"infra-team","Active"),
    ("uat-db-01",   "10.0.2.21", "UAT",        "VM",       "DC-Bangkok",  "Ubuntu Server","22.04 LTS",8, 32,"dba-team","Active"),
    ("dev-app-01",  "10.0.3.11", "Dev",        "VM",       "DC-Bangkok",  "Ubuntu Server","24.04 LTS",4, 16,"dev-team","Active"),
    ("cloud-eks-01","N/A",       "Production", "Cloud",    "AWS-ap-southeast-1","Ubuntu Server","22.04 LTS",8,32,"cloud-team","Active"),
    ("cloud-eks-02","N/A",       "Production", "Cloud",    "AWS-ap-southeast-1","Ubuntu Server","22.04 LTS",8,32,"cloud-team","Active"),
    ("cloud-rds-01","N/A",       "Production", "Cloud",    "AWS-ap-southeast-1","Amazon Linux","2023",4,32,"cloud-team","Active"),
    ("legacy-app-01","10.0.1.99","Production", "Physical", "DC-Bangkok",  "Windows Server","2019",8, 32,"infra-team","Active"),
    ("dr-app-01",   "10.10.1.11","DR",         "VM",       "DC-Chonburi", "Ubuntu Server","22.04 LTS",8,32,"infra-team","Active"),
]

# ── Tech Radar positions ──────────────────────────────────────────────────────
RADAR = {
    "Languages & Frameworks": {
        "Adopt":  ["Python","Java","TypeScript","Spring Boot","FastAPI","React","Node.js"],
        "Trial":  ["Go","Kotlin","Next.js","Quarkus","Flutter"],
        "Assess": ["Rust","Swift","Vue.js"],
        "Hold":   ["Scala","Django","Angular"],
    },
    "Platforms":  {
        "Adopt":  ["Kubernetes","Docker","Apache Kafka","Istio","Nginx","Kong Gateway"],
        "Trial":  ["Apache Flink","GCP GKE","Azure AKS"],
        "Assess": ["NATS","Falco","WSO2 API Manager"],
        "Hold":   ["Oracle WebLogic","IBM MQ"],
    },
    "Tools": {
        "Adopt":  ["Terraform","ArgoCD","GitHub Actions","SonarQube","Prometheus","Grafana","Apache Airflow","Power BI"],
        "Trial":  ["dbt","Helm","OpenTelemetry","LangChain","Ray"],
        "Assess": ["Hugging Face","SonarCloud","Falco"],
        "Hold":   ["Jenkins","Crystal Reports","Subversion (SVN)"],
    },
    "Infrastructure": {
        "Adopt":  ["AWS EC2","AWS S3","AWS RDS","Redis","PostgreSQL","Elasticsearch","Ubuntu Server","JVM (OpenJDK)"],
        "Trial":  ["GCP BigQuery","MinIO","Longhorn","ClickHouse"],
        "Assess": ["Ceph","Alpine Linux"],
        "Hold":   ["Oracle Database","Microsoft SQL Server","Windows Server","MariaDB"],
    },
}

# ── App → tech usage mapping ──────────────────────────────────────────────────
# (app_id, tech_name, installed_version, environment, usage_type)
APP_TECH_USAGE = [
    ("APP-001","Java","17.0.11","Production","Runtime"),
    ("APP-001","Spring Boot","3.2.5","Production","Runtime"),
    ("APP-001","Oracle Database","19c","Production","Runtime"),
    ("APP-001","Apache Kafka","3.6.2","Production","Runtime"),
    ("APP-002","Python","3.11.9","Production","Runtime"),
    ("APP-002","PostgreSQL","15.7","Production","Runtime"),
    ("APP-002","Redis","7.0.15","Production","Runtime"),
    ("APP-003","Java","8u412","Production","Runtime"),
    ("APP-003","Oracle Database","12c","Production","Runtime"),
    ("APP-004","Node.js","18.20.3","Production","Runtime"),
    ("APP-004","React","18.2.0","Production","Runtime"),
    ("APP-004","PostgreSQL","15.7","Production","Runtime"),
    ("APP-005","Python","3.12.3","Production","Runtime"),
    ("APP-005","TensorFlow","2.16.1","Production","Runtime"),
    ("APP-005","Apache Kafka","3.7.0","Production","Runtime"),
    ("APP-005","MongoDB","7.0.9","Production","Runtime"),
    ("APP-006","Java","8u412","Production","Runtime"),
    ("APP-006","Oracle Database","11g","Production","Runtime"),
    ("APP-007","Kubernetes","1.29.5","Production","Infrastructure"),
    ("APP-007","Docker","26.1.3","Production","Infrastructure"),
    ("APP-007","Helm","3.15.1","Production","Tool"),
    ("APP-007","ArgoCD","2.11.0","Production","Tool"),
    ("APP-008","Apache Spark","3.5.1","Production","Runtime"),
    ("APP-008","Python","3.11.9","Production","Runtime"),
    ("APP-008","ClickHouse","24.4.1","Production","Runtime"),
    ("APP-009","Java","17.0.11","Production","Runtime"),
    ("APP-009","Spring Boot","3.2.5","Production","Runtime"),
    ("APP-010","TypeScript","5.4.5","Production","Runtime"),
    ("APP-010","Next.js","14.2.3","Production","Runtime"),
    ("APP-010","PostgreSQL","16.3","Production","Runtime"),
    ("APP-010","Redis","7.2.5","Production","Runtime"),
    ("APP-011","Java","8u412","Production","Runtime"),
    ("APP-011","Oracle Database","12c","Production","Runtime"),
    ("APP-012","TypeScript","5.4.5","Production","Tool"),
    ("APP-012","Node.js","20.14.0","Production","Runtime"),
    ("APP-013","Power BI","Nov-2023","Production","Runtime"),
    ("APP-014","Java","11.0.23","Production","Runtime"),
    ("APP-015","Java","17.0.11","Production","Runtime"),
    ("APP-015","Spring Boot","3.2.5","Production","Runtime"),
    ("APP-016","Java","17.0.11","Production","Runtime"),
    ("APP-016","Keycloak","24.0.4","Production","Runtime"),
    ("APP-016","PostgreSQL","15.7","Production","Runtime"),
    ("APP-017","Node.js","18.20.3","Production","Runtime"),
    ("APP-018","Python","3.11.9","Production","Runtime"),
    ("APP-018","Apache Airflow","2.9.1","Production","Runtime"),
    ("APP-018","PostgreSQL","15.7","Production","Runtime"),
    ("APP-019","Java","17.0.11","Production","Runtime"),
    ("APP-020","Nginx","1.26.1","Production","Infrastructure"),
    ("APP-020","Kong Gateway","3.7.0","Production","Runtime"),
    ("APP-021","Java","8u412","Production","Runtime"),
    ("APP-022","TypeScript","5.4.5","Production","Runtime"),
    ("APP-022","React","18.3.1","Production","Runtime"),
    ("APP-022","Node.js","20.14.0","Production","Runtime"),
    ("APP-022","MongoDB","6.0.15","Production","Runtime"),
    ("APP-023","Python","3.12.3","Production","Runtime"),
    ("APP-024","Python","3.12.3","Production","Runtime"),
    ("APP-024","MLflow","2.12.1","Production","Runtime"),
    ("APP-025","Java","11.0.23","Production","Runtime"),
    ("APP-026","Java","17.0.11","Production","Runtime"),
    ("APP-027","Python","3.11.9","Production","Runtime"),
    ("APP-028","Crystal Reports","14.3","Production","Runtime"),
    ("APP-029","Go","1.22.3","Production","Runtime"),
    ("APP-029","Istio","1.21.2","Production","Infrastructure"),
    ("APP-030","Java","17.0.11","Production","Runtime"),
]

# ── Seed functions ────────────────────────────────────────────────────────────
def next_id(prefix, conn, table, id_col="id"):
    rows = conn.execute(f"SELECT {id_col} FROM {table} WHERE {id_col} LIKE '{prefix}-%' ORDER BY {id_col} DESC LIMIT 1").fetchone()
    if rows:
        last = int(rows[0].split("-")[1])
        return f"{prefix}-{str(last+1).zfill(4)}"
    return f"{prefix}-0001"

def seed_catalog(conn):
    print("→ Seeding tech_catalog ...")
    inserted = 0
    for i, (name, vendor, cat, sub, tier, status, tags, desc) in enumerate(TECH_CATALOG, 1):
        tid = f"TC-{str(i).zfill(4)}"
        exists = conn.execute("SELECT 1 FROM tech_catalog WHERE id=?", (tid,)).fetchone()
        if not exists:
            conn.execute("""INSERT INTO tech_catalog(id,name,vendor,category,sub_category,tier,standard_status,tags,description,created_by,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tid, name, vendor, cat, sub, tier, status,
                 json.dumps(tags), desc, "seed_script",
                 ago(random.randint(90,730)), ago(random.randint(1,30))))
            inserted += 1
    print(f"   tech_catalog: {inserted} rows inserted")

def seed_versions(conn):
    print("→ Seeding tech_versions ...")
    inserted = 0
    for tech_name, versions in TECH_VERSIONS.items():
        row = conn.execute("SELECT id FROM tech_catalog WHERE name=?", (tech_name,)).fetchone()
        if not row:
            print(f"   WARNING: tech '{tech_name}' not found in catalog")
            continue
        tech_id = row[0]
        for j, (label, major, minor, patch, rtype, rdate, eol, lifecycle, is_latest, is_lts) in enumerate(versions):
            vid = f"TV-{tech_id.split('-')[1]}-{str(j+1).zfill(2)}"
            exists = conn.execute("SELECT 1 FROM tech_versions WHERE id=?", (vid,)).fetchone()
            if not exists:
                conn.execute("""INSERT INTO tech_versions(id,tech_id,version_label,major,minor,patch,release_type,release_date,eol_date,lifecycle_phase,is_latest,is_lts,created_at)
                                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (vid, tech_id, label, major, minor, patch, rtype, rdate, eol, lifecycle, is_latest, is_lts, ago(random.randint(1,30))))
                inserted += 1
    print(f"   tech_versions: {inserted} rows inserted")

def seed_servers(conn):
    print("→ Seeding tech_servers ...")
    inserted = 0
    for i, (host, ip, env, stype, loc, osname, osver, cpu, ram, managed, status) in enumerate(SERVERS, 1):
        sid = f"SRV-{str(i).zfill(4)}"
        exists = conn.execute("SELECT 1 FROM tech_servers WHERE id=?", (sid,)).fetchone()
        if not exists:
            conn.execute("""INSERT INTO tech_servers(id,hostname,ip_address,environment,server_type,location,os_name,os_version,cpu_core,ram_gb,managed_by,status,created_by,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sid, host, ip, env, stype, loc, osname, osver, cpu, ram, managed, status,
                 "seed_script", ago(random.randint(90,730)), ago(random.randint(1,30))))
            inserted += 1
    print(f"   tech_servers: {inserted} rows inserted")

def seed_usage(conn):
    print("→ Seeding tech_usage (app + server) ...")
    inserted = 0
    # App-based usage
    for i, (app_id, tech_name, inst_ver, env, utype) in enumerate(APP_TECH_USAGE, 1):
        row = conn.execute("SELECT id FROM tech_catalog WHERE name=?", (tech_name,)).fetchone()
        if not row:
            continue
        tech_id = row[0]
        uid = f"TU-{str(i).zfill(4)}"
        exists = conn.execute("SELECT 1 FROM tech_usage WHERE id=?", (uid,)).fetchone()
        if not exists:
            # try to find matching version_id
            ver_row = conn.execute("SELECT id FROM tech_versions WHERE tech_id=? AND version_label=? LIMIT 1", (tech_id, inst_ver)).fetchone()
            ver_id = ver_row[0] if ver_row else None
            conn.execute("""INSERT INTO tech_usage(id,tech_id,version_id,usage_target_type,app_id,environment,usage_type,installed_version,install_date,created_by,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, tech_id, ver_id, "App", app_id, env, utype, inst_ver,
                 ago(random.randint(30,500)), "seed_script",
                 ago(random.randint(1,30)), ago(random.randint(1,10))))
            inserted += 1

    # Server-based OS/runtime usage
    server_tech_pairs = [
        ("SRV-0001","Ubuntu Server","22.04 LTS"),
        ("SRV-0002","Ubuntu Server","22.04 LTS"),
        ("SRV-0003","Red Hat Enterprise Linux","9.2"),
        ("SRV-0004","Red Hat Enterprise Linux","9.2"),
        ("SRV-0005","Ubuntu Server","22.04 LTS"),
        ("SRV-0006","Ubuntu Server","22.04 LTS"),
        ("SRV-0007","Ubuntu Server","22.04 LTS"),
        ("SRV-0008","Ubuntu Server","22.04 LTS"),
        ("SRV-0009","Ubuntu Server","22.04 LTS"),
        ("SRV-0010","Ubuntu Server","24.04 LTS"),
        ("SRV-0011","Ubuntu Server","22.04 LTS"),
        ("SRV-0012","Ubuntu Server","22.04 LTS"),
        ("SRV-0014","Windows Server","2019"),
        ("SRV-0015","Ubuntu Server","22.04 LTS"),
        ("SRV-0001","PostgreSQL","15.7"),
        ("SRV-0003","Oracle Database","19c"),
        ("SRV-0006","Kubernetes","1.29.5"),
        ("SRV-0007","Kubernetes","1.29.5"),
        ("SRV-0001","Node.js","18.20.3"),
        ("SRV-0002","Java","17.0.11"),
        ("SRV-0011","Apache Kafka","3.7.0"),
        ("SRV-0001","Nginx","1.26.1"),
        ("SRV-0002","Nginx","1.26.1"),
    ]
    base = len(APP_TECH_USAGE) + 1
    for j, (srv_id, tech_name, inst_ver) in enumerate(server_tech_pairs, base):
        row = conn.execute("SELECT id FROM tech_catalog WHERE name=?", (tech_name,)).fetchone()
        if not row:
            continue
        tech_id = row[0]
        uid = f"TU-{str(j).zfill(4)}"
        exists = conn.execute("SELECT 1 FROM tech_usage WHERE id=?", (uid,)).fetchone()
        if not exists:
            srv_row = conn.execute("SELECT environment FROM tech_servers WHERE id=?", (srv_id,)).fetchone()
            env = srv_row[0] if srv_row else "Production"
            conn.execute("""INSERT INTO tech_usage(id,tech_id,version_id,usage_target_type,server_id,environment,usage_type,installed_version,install_date,created_by,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, tech_id, None, "Server", srv_id, env, "Runtime", inst_ver,
                 ago(random.randint(30,500)), "seed_script",
                 ago(random.randint(1,30)), ago(random.randint(1,10))))
            inserted += 1

    print(f"   tech_usage: {inserted} rows inserted")

def seed_radar(conn):
    print("→ Seeding tech_radar ...")
    inserted = 0
    quarters = ["2025-Q3","2025-Q4","2026-Q1"]
    ring_movement = {
        "Python":    [("Adopt",""),("Adopt","Adopt"),("Adopt","Adopt")],
        "Jenkins":   [("Trial",""),("Hold","Trial"),("Hold","Hold")],
        "Crystal Reports":[("Hold",""),("Deprecated","Hold"),("Deprecated","Deprecated")],
        "LangChain": [("Assess",""),("Trial","Assess"),("Trial","Trial")],
    }
    rid = 1
    for quadrant, rings in RADAR.items():
        for ring, techs in rings.items():
            for tech_name in techs:
                row = conn.execute("SELECT id FROM tech_catalog WHERE name=?", (tech_name,)).fetchone()
                if not row:
                    continue
                tech_id = row[0]
                prev = None
                for q in quarters:
                    # check override
                    if tech_name in ring_movement:
                        idx = quarters.index(q)
                        actual_ring, actual_prev = ring_movement[tech_name][idx]
                    else:
                        actual_ring = ring
                        actual_prev = prev if prev and prev != ring else None
                    radar_id = f"TR-{str(rid).zfill(4)}"
                    exists = conn.execute("SELECT 1 FROM tech_radar WHERE id=?", (radar_id,)).fetchone()
                    if not exists:
                        conn.execute("""INSERT INTO tech_radar(id,tech_id,radar_date,ring,quadrant,rationale,decided_by,prev_ring,created_at)
                                        VALUES(?,?,?,?,?,?,?,?,?)""",
                            (radar_id, tech_id, q, actual_ring, quadrant,
                             f"{tech_name} positioned as {actual_ring} in {quadrant}",
                             "ARB", actual_prev, ago(random.randint(1,30))))
                        inserted += 1
                    prev = actual_ring
                    rid += 1

    print(f"   tech_radar: {inserted} rows inserted")

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'='*60}")
    print(f"  Tech Stack Seed — ea_domains.db")
    print(f"{'='*60}")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")

    seed_catalog(conn)
    seed_versions(conn)
    seed_servers(conn)
    seed_usage(conn)
    seed_radar(conn)

    conn.commit()
    conn.close()

    # Summary
    conn2 = sqlite3.connect(DB_PATH)
    c = conn2.cursor()
    print(f"\n{'='*60}")
    print("  Final counts:")
    for tbl in ["tech_catalog","tech_versions","tech_servers","tech_usage","tech_vulnerabilities","tech_radar"]:
        n = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        print(f"  {tbl:<30} {n:>4} rows")
    conn2.close()
    print(f"{'='*60}")
    print("✅ Done!")

if __name__ == "__main__":
    main()
