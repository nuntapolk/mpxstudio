"""Seed Tech Catalog — 100 entries with versions, radar, vulnerabilities."""
import sqlite3, uuid, random
from datetime import datetime, timedelta

DB = "ea_domains.db"

def uid(prefix): return f"{prefix}-" + uuid.uuid4().hex[:6].upper()

TECH_DATA = [
    # (name, vendor, category, sub_category, tier, status, website)
    # ── Languages ──────────────────────────────────────────────────────────────
    ("Python",          "Python Software Foundation", "Language", "General Purpose",  "Tier 1", "Approved",    "python.org"),
    ("Java",            "Oracle",                     "Language", "General Purpose",  "Tier 1", "Approved",    "java.com"),
    ("TypeScript",      "Microsoft",                  "Language", "Web/JS",           "Tier 1", "Approved",    "typescriptlang.org"),
    ("JavaScript",      "ECMA International",         "Language", "Web/JS",           "Tier 1", "Approved",    "ecma-international.org"),
    ("Go",              "Google",                     "Language", "Systems",          "Tier 2", "Approved",    "go.dev"),
    ("Kotlin",          "JetBrains",                  "Language", "JVM",              "Tier 2", "Approved",    "kotlinlang.org"),
    ("Rust",            "Rust Foundation",            "Language", "Systems",          "Tier 3", "Assess",      "rust-lang.org"),
    ("C#",              "Microsoft",                  "Language", "General Purpose",  "Tier 2", "Approved",    "dotnet.microsoft.com"),
    ("PHP",             "The PHP Group",              "Language", "Web",              "Tier 3", "Hold",        "php.net"),
    ("Ruby",            "Ruby Association",           "Language", "General Purpose",  "Tier 3", "Hold",        "ruby-lang.org"),
    ("Swift",           "Apple",                      "Language", "Mobile/Systems",   "Tier 2", "Approved",    "swift.org"),
    ("Scala",           "EPFL",                       "Language", "JVM/Functional",   "Tier 3", "Hold",        "scala-lang.org"),
    # ── Frameworks ─────────────────────────────────────────────────────────────
    ("FastAPI",         "Sebastián Ramírez",          "Framework","Web/API",          "Tier 1", "Approved",    "fastapi.tiangolo.com"),
    ("React",           "Meta",                       "Framework","Frontend",         "Tier 1", "Approved",    "react.dev"),
    ("Spring Boot",     "VMware Tanzu",               "Framework","Web/API",          "Tier 1", "Approved",    "spring.io"),
    ("Next.js",         "Vercel",                     "Framework","Full-Stack Web",   "Tier 1", "Approved",    "nextjs.org"),
    ("Vue.js",          "Evan You",                   "Framework","Frontend",         "Tier 2", "Approved",    "vuejs.org"),
    ("Angular",         "Google",                     "Framework","Frontend",         "Tier 2", "Approved",    "angular.io"),
    ("Django",          "Django Software Foundation", "Framework","Web/API",          "Tier 2", "Approved",    "djangoproject.com"),
    ("Express.js",      "OpenJS Foundation",          "Framework","Web/API",          "Tier 2", "Approved",    "expressjs.com"),
    ("NestJS",          "Kamil Myśliwiec",            "Framework","Web/API",          "Tier 2", "Trial",       "nestjs.com"),
    ("Gin",             "gin-gonic",                  "Framework","Web/API",          "Tier 2", "Trial",       "gin-gonic.com"),
    ("Laravel",         "Taylor Otwell",              "Framework","Web/API",          "Tier 3", "Hold",        "laravel.com"),
    ("ASP.NET Core",    "Microsoft",                  "Framework","Web/API",          "Tier 2", "Approved",    "dotnet.microsoft.com"),
    # ── Databases ─────────────────────────────────────────────────────────────
    ("PostgreSQL",      "PostgreSQL Global Dev Group","Database", "RDBMS",            "Tier 1", "Approved",    "postgresql.org"),
    ("MySQL",           "Oracle",                     "Database", "RDBMS",            "Tier 1", "Approved",    "mysql.com"),
    ("MongoDB",         "MongoDB Inc.",               "Database", "NoSQL/Document",   "Tier 2", "Approved",    "mongodb.com"),
    ("Redis",           "Redis Ltd.",                 "Database", "In-Memory/Cache",  "Tier 1", "Approved",    "redis.io"),
    ("Elasticsearch",   "Elastic",                    "Database", "Search/Analytics", "Tier 2", "Approved",    "elastic.co"),
    ("SQLite",          "D. Richard Hipp",            "Database", "Embedded RDBMS",   "Tier 2", "Approved",    "sqlite.org"),
    ("Microsoft SQL Server","Microsoft",              "Database", "RDBMS",            "Tier 2", "Approved",    "microsoft.com/sql-server"),
    ("Oracle Database", "Oracle",                     "Database", "RDBMS",            "Tier 2", "Hold",        "oracle.com"),
    ("Cassandra",       "Apache Foundation",          "Database", "NoSQL/Wide-Column","Tier 3", "Assess",      "cassandra.apache.org"),
    ("ClickHouse",      "ClickHouse Inc.",            "Database", "OLAP/Analytics",   "Tier 2", "Trial",       "clickhouse.com"),
    # ── Platforms / Runtime ────────────────────────────────────────────────────
    ("Kubernetes",      "CNCF",                       "Platform", "Container Orchestration","Tier 1","Approved","kubernetes.io"),
    ("Docker",          "Docker Inc.",                "Platform", "Containerization", "Tier 1", "Approved",    "docker.com"),
    ("Apache Kafka",    "Apache Foundation",          "Platform", "Messaging/Streaming","Tier 1","Approved",   "kafka.apache.org"),
    ("RabbitMQ",        "VMware",                     "Platform", "Messaging",        "Tier 2", "Hold",        "rabbitmq.com"),
    ("AWS",             "Amazon",                     "Platform", "Cloud",            "Tier 1", "Approved",    "aws.amazon.com"),
    ("Azure",           "Microsoft",                  "Platform", "Cloud",            "Tier 1", "Approved",    "azure.microsoft.com"),
    ("GCP",             "Google",                     "Platform", "Cloud",            "Tier 2", "Approved",    "cloud.google.com"),
    ("Nginx",           "F5 Inc.",                    "Platform", "Web Server/Proxy", "Tier 1", "Approved",    "nginx.com"),
    ("Node.js",         "OpenJS Foundation",          "Platform", "Runtime",          "Tier 1", "Approved",    "nodejs.org"),
    ("Apache Tomcat",   "Apache Foundation",          "Platform", "Java Runtime",     "Tier 2", "Approved",    "tomcat.apache.org"),
    ("Istio",           "CNCF",                       "Platform", "Service Mesh",     "Tier 2", "Trial",       "istio.io"),
    # ── Tools ─────────────────────────────────────────────────────────────────
    ("GitLab",          "GitLab Inc.",                "Tool",     "DevOps/SCM",       "Tier 1", "Approved",    "gitlab.com"),
    ("GitHub",          "Microsoft",                  "Tool",     "SCM",              "Tier 1", "Approved",    "github.com"),
    ("Jenkins",         "Jenkins Community",          "Tool",     "CI/CD",            "Tier 2", "Hold",        "jenkins.io"),
    ("GitHub Actions",  "Microsoft",                  "Tool",     "CI/CD",            "Tier 1", "Approved",    "github.com/features/actions"),
    ("ArgoCD",          "CNCF",                       "Tool",     "GitOps/CD",        "Tier 1", "Approved",    "argoproj.github.io"),
    ("Terraform",       "HashiCorp",                  "Tool",     "IaC",              "Tier 1", "Approved",    "terraform.io"),
    ("Ansible",         "Red Hat",                    "Tool",     "Config Management","Tier 2", "Approved",    "ansible.com"),
    ("SonarQube",       "SonarSource",                "Tool",     "Code Quality",     "Tier 1", "Approved",    "sonarsource.com"),
    ("Prometheus",      "CNCF",                       "Tool",     "Monitoring",       "Tier 1", "Approved",    "prometheus.io"),
    ("Grafana",         "Grafana Labs",               "Tool",     "Observability",    "Tier 1", "Approved",    "grafana.com"),
    ("Jaeger",          "CNCF",                       "Tool",     "Distributed Tracing","Tier 2","Trial",      "jaegertracing.io"),
    ("Kibana",          "Elastic",                    "Tool",     "Log Visualization","Tier 2", "Approved",    "elastic.co"),
    ("Vault",           "HashiCorp",                  "Tool",     "Secrets Management","Tier 1","Approved",    "vaultproject.io"),
    ("Helm",            "CNCF",                       "Tool",     "K8s Package Mgr",  "Tier 1", "Approved",    "helm.sh"),
    ("Apache Airflow",  "Apache Foundation",          "Tool",     "Workflow/Pipeline","Tier 2", "Approved",    "airflow.apache.org"),
    ("dbt",             "dbt Labs",                   "Tool",     "Data Transform",   "Tier 2", "Trial",       "getdbt.com"),
    ("Postman",         "Postman Inc.",               "Tool",     "API Testing",      "Tier 2", "Approved",    "postman.com"),
    ("JIRA",            "Atlassian",                  "Tool",     "Project Mgmt",     "Tier 2", "Approved",    "atlassian.com"),
    # ── Infrastructure / OS ────────────────────────────────────────────────────
    ("Ubuntu Server",   "Canonical",                  "Infrastructure","Linux OS",    "Tier 1", "Approved",    "ubuntu.com"),
    ("Red Hat Enterprise Linux","Red Hat",            "Infrastructure","Linux OS",    "Tier 1", "Approved",    "redhat.com"),
    ("Windows Server",  "Microsoft",                  "Infrastructure","OS",          "Tier 2", "Approved",    "microsoft.com"),
    ("VMware vSphere",  "Broadcom",                   "Infrastructure","Virtualization","Tier 2","Hold",       "vmware.com"),
    ("Proxmox VE",      "Proxmox Server Solutions",   "Infrastructure","Virtualization","Tier 2","Trial",      "proxmox.com"),
    ("HAProxy",         "HAProxy Technologies",       "Infrastructure","Load Balancer","Tier 2","Approved",    "haproxy.com"),
    ("AWS S3",          "Amazon",                     "Infrastructure","Object Storage","Tier 1","Approved",   "aws.amazon.com/s3"),
    ("AWS RDS",         "Amazon",                     "Infrastructure","Managed DB",  "Tier 1", "Approved",   "aws.amazon.com/rds"),
    ("AWS EKS",         "Amazon",                     "Infrastructure","Managed K8s", "Tier 1", "Approved",   "aws.amazon.com/eks"),
    ("Azure AKS",       "Microsoft",                  "Infrastructure","Managed K8s", "Tier 2", "Approved",   "azure.microsoft.com"),
    ("Cloudflare",      "Cloudflare Inc.",            "Infrastructure","CDN/Security","Tier 1", "Approved",   "cloudflare.com"),
    # ── Security ──────────────────────────────────────────────────────────────
    ("Keycloak",        "Red Hat",                    "Security",  "IAM/SSO",         "Tier 1", "Approved",   "keycloak.org"),
    ("OWASP ZAP",       "OWASP",                      "Security",  "DAST/Scanning",   "Tier 2", "Approved",   "owasp.org"),
    ("Trivy",           "Aqua Security",              "Security",  "Container Scan",  "Tier 1", "Approved",   "trivy.dev"),
    ("Snyk",            "Snyk Ltd.",                  "Security",  "SCA/SAST",        "Tier 2", "Trial",      "snyk.io"),
    ("HashiCorp Vault", "HashiCorp",                  "Security",  "Secrets/PKI",     "Tier 1", "Approved",   "vaultproject.io"),
    ("Cert-Manager",    "CNCF",                       "Security",  "TLS Automation",  "Tier 2", "Approved",   "cert-manager.io"),
    # ── Library ───────────────────────────────────────────────────────────────
    ("SQLAlchemy",      "Michael Bayer",              "Library",   "ORM/Python",      "Tier 1", "Approved",   "sqlalchemy.org"),
    ("Pydantic",        "Samuel Colvin",              "Library",   "Validation/Python","Tier 1","Approved",   "pydantic.dev"),
    ("Axios",           "Matt Zabriskie",             "Library",   "HTTP/JavaScript", "Tier 1", "Approved",   "axios-http.com"),
    ("Lodash",          "JS Foundation",              "Library",   "Utility/JavaScript","Tier 2","Approved",  "lodash.com"),
    ("Pandas",          "NumFOCUS",                   "Library",   "Data/Python",     "Tier 1", "Approved",   "pandas.pydata.org"),
    ("NumPy",           "NumFOCUS",                   "Library",   "Scientific/Python","Tier 2","Approved",   "numpy.org"),
    ("Apache Log4j",    "Apache Foundation",          "Library",   "Logging/Java",    "Tier 3", "Hold",       "logging.apache.org"),
    # ── Messaging / Integration ────────────────────────────────────────────────
    ("Kong Gateway",    "Kong Inc.",                  "Platform",  "API Gateway",     "Tier 1", "Approved",   "konghq.com"),
    ("AWS SQS",         "Amazon",                     "Platform",  "Message Queue",   "Tier 2", "Approved",   "aws.amazon.com/sqs"),
    ("Apache ActiveMQ", "Apache Foundation",          "Platform",  "Messaging",       "Tier 3", "Deprecated", "activemq.apache.org"),
    # ── Analytics / BI ────────────────────────────────────────────────────────
    ("Apache Spark",    "Apache Foundation",          "Platform",  "Data Processing", "Tier 2", "Approved",   "spark.apache.org"),
    ("Power BI",        "Microsoft",                  "Tool",      "Business Intelligence","Tier 1","Approved","powerbi.microsoft.com"),
    ("Tableau",         "Salesforce",                 "Tool",      "Business Intelligence","Tier 2","Approved","tableau.com"),
    ("Apache Superset", "Apache Foundation",          "Tool",      "BI/Self-service", "Tier 2", "Trial",      "superset.apache.org"),
    ("dbt Core",        "dbt Labs",                   "Tool",      "Data Transform",  "Tier 2", "Trial",      "getdbt.com"),
    # ── AI / ML ───────────────────────────────────────────────────────────────
    ("TensorFlow",      "Google",                     "Library",   "Machine Learning","Tier 2", "Approved",   "tensorflow.org"),
    ("PyTorch",         "Meta",                       "Library",   "Machine Learning","Tier 2", "Approved",   "pytorch.org"),
    ("LangChain",       "LangChain Inc.",             "Library",   "LLM/AI",          "Tier 3", "Assess",     "langchain.com"),
    ("OpenAI API",      "OpenAI",                     "Platform",  "LLM/AI",          "Tier 2", "Trial",      "openai.com"),
]

VERSIONS = {
    "Python":       [("3.12.3","3","12","3","2024-05-15","2028-10","GA",1,1),("3.11.9","3","11","9","2024-04-02","2027-10","LTS",0,1),("3.10.14","3","10","14","2024-03-19","2026-10","Maintenance",0,0)],
    "Java":         [("21.0.3","21","0","3","2024-04-16","2031-09","LTS",1,1),("17.0.11","17","0","11","2024-04-16","2029-09","LTS",0,1),("11.0.23","11","0","23","2024-04-16","2026-09","LTS",0,0)],
    "TypeScript":   [("5.4.5","5","4","5","2024-04-03","—","GA",1,0),("5.3.3","5","3","3","2024-01-10","—","GA",0,0)],
    "JavaScript":   [("ES2024","ES2024","0","0","2024-06-01","—","GA",1,0)],
    "Go":           [("1.22.3","1","22","3","2024-05-07","—","GA",1,0),("1.21.10","1","21","10","2024-05-07","—","Maintenance",0,0)],
    "Kotlin":       [("2.0.0","2","0","0","2024-05-21","—","GA",1,0),("1.9.24","1","9","24","2024-05-23","—","Maintenance",0,0)],
    "Rust":         [("1.78.0","1","78","0","2024-05-02","—","GA",1,0)],
    "C#":           [("12.0","12","0","0","2023-11-14","—","GA",1,0),("11.0","11","0","0","2022-11-08","—","Maintenance",0,0)],
    "PHP":          [("8.3.7","8","3","7","2024-05-09","2027-11","GA",1,0),("8.2.19","8","2","19","2024-05-09","2026-12","Maintenance",0,0)],
    "FastAPI":      [("0.111.0","0","111","0","2024-04-25","—","GA",1,0),("0.110.3","0","110","3","2024-04-15","—","GA",0,0)],
    "React":        [("18.3.1","18","3","1","2024-04-26","—","GA",1,0),("18.2.0","18","2","0","2022-06-14","—","Maintenance",0,0)],
    "Spring Boot":  [("3.2.5","3","2","5","2024-05-16","2025-02","GA",1,0),("3.1.11","3","1","11","2024-04-17","2024-11","Maintenance",0,0),("2.7.18","2","7","18","2024-02-22","2023-11","EOL",0,0)],
    "Next.js":      [("14.2.3","14","2","3","2024-05-07","—","GA",1,0),("13.5.6","13","5","6","2023-10-16","—","Maintenance",0,0)],
    "Vue.js":       [("3.4.26","3","4","26","2024-04-24","—","GA",1,0),("2.7.16","2","7","16","2023-12-01","2025-12","Maintenance",0,0)],
    "Django":       [("5.0.6","5","0","6","2024-05-01","2025-04","GA",1,0),("4.2.13","4","2","13","2024-05-01","2026-04","LTS",0,1)],
    "PostgreSQL":   [("16.3","16","3","0","2024-05-09","2028-11","GA",1,0),("15.7","15","7","0","2024-05-09","2027-11","Maintenance",0,0),("14.12","14","12","0","2024-05-09","2026-11","Maintenance",0,0),("13.15","13","15","0","2024-05-09","2025-11","Maintenance",0,0)],
    "MySQL":        [("8.4.0","8","4","0","2024-04-30","2032-04","LTS",1,1),("8.0.37","8","0","37","2024-04-30","2026-04","Maintenance",0,0)],
    "MongoDB":      [("7.0.9","7","0","9","2024-04-30","2027-08","GA",1,0),("6.0.15","6","0","15","2024-04-30","2025-07","Maintenance",0,0)],
    "Redis":        [("7.2.5","7","2","5","2024-05-01","2027-01","GA",1,0),("7.0.15","7","0","15","2024-01-10","2026-01","Maintenance",0,0)],
    "Kubernetes":   [("1.30.1","1","30","1","2024-05-22","2025-06","GA",1,0),("1.29.5","1","29","5","2024-05-22","2025-02","Maintenance",0,0),("1.28.10","1","28","10","2024-05-22","2024-10","Maintenance",0,0)],
    "Docker":       [("26.1.3","26","1","3","2024-05-14","—","GA",1,0),("25.0.5","25","0","5","2024-04-09","—","Maintenance",0,0)],
    "Apache Kafka": [("3.7.0","3","7","0","2024-03-04","—","GA",1,0),("3.6.2","3","6","2","2024-02-07","—","Maintenance",0,0)],
    "Nginx":        [("1.26.1","1","26","1","2024-05-29","—","Stable",1,0),("1.25.5","1","25","5","2024-04-23","—","Mainline",0,0)],
    "Node.js":      [("22.2.0","22","2","0","2024-05-15","2027-04","GA",1,0),("20.14.0","20","14","0","2024-06-01","2026-04","LTS",0,1),("18.20.3","18","20","3","2024-04-10","2025-04","Maintenance",0,0)],
    "Ubuntu Server":[("24.04 LTS","24","04","0","2024-04-25","2029-04","LTS",1,1),("22.04 LTS","22","04","0","2022-04-21","2027-04","LTS",0,1),("20.04 LTS","20","04","0","2020-04-23","2025-04","Maintenance",0,0)],
    "Apache Kafka": [("3.7.0","3","7","0","2024-03-04","—","GA",1,0)],
    "Keycloak":     [("24.0.5","24","0","5","2024-05-29","—","GA",1,0),("23.0.7","23","0","7","2024-03-01","—","Maintenance",0,0)],
    "Terraform":    [("1.8.4","1","8","4","2024-05-30","—","GA",1,0),("1.7.5","1","7","5","2024-03-27","—","Maintenance",0,0)],
    "Helm":         [("3.15.1","3","15","1","2024-05-23","—","GA",1,0)],
    "Kong Gateway": [("3.7.1","3","7","1","2024-05-08","—","GA",1,0),("3.6.1","3","6","1","2024-03-01","—","Maintenance",0,0)],
    "Power BI":     [("May 2024","2024","5","0","2024-05-14","—","GA",1,0)],
    "Apache Log4j": [("2.23.1","2","23","1","2024-02-19","—","GA",1,0),("2.17.2","2","17","2","2022-02-22","—","Security-patch",0,0)],
    "SQLite":       [("3.46.0","3","46","0","2024-05-23","—","GA",1,0)],
    "Pandas":       [("2.2.2","2","2","2","2024-04-10","—","GA",1,0)],
    "Elasticsearch":[("8.13.4","8","13","4","2024-05-16","—","GA",1,0),("7.17.21","7","17","21","2024-04-09","—","Maintenance",0,0)],
    "Grafana":      [("10.4.3","10","4","3","2024-05-16","—","GA",1,0),("9.5.17","9","5","17","2024-04-09","—","Maintenance",0,0)],
    "Prometheus":   [("2.52.0","2","52","0","2024-05-15","—","GA",1,0)],
    "ArgoCD":       [("2.11.2","2","11","2","2024-05-29","—","GA",1,0),("2.10.11","2","10","11","2024-05-22","—","Maintenance",0,0)],
}

# CVE data (tech_name -> list of CVE tuples)
CVES = {
    "Apache Log4j": [
        ("CVE-2021-44228","Critical",10.0,"Log4Shell: JNDI injection RCE","< 2.15.0","2.15.0","2021-12-10","Patched"),
        ("CVE-2021-45046","Critical",9.0,"Log4Shell bypass via JNDI lookup","< 2.16.0","2.16.0","2021-12-14","Patched"),
        ("CVE-2021-45105","High",    7.5,"Infinite recursion DoS","< 2.17.0","2.17.0","2021-12-18","Patched"),
        ("CVE-2022-23302", "High",   8.8,"JMSSink deserialization RCE","< 2.17.1","2.17.1","2022-01-18","Patched"),
    ],
    "Spring Boot": [
        ("CVE-2022-22965","Critical",9.8,"Spring4Shell: RCE via DataBinder","< 5.3.18","5.3.18","2022-03-31","Patched"),
        ("CVE-2023-20873","High",    7.5,"Actuator endpoint bypass","< 3.0.6","3.0.6","2023-04-20","Patched"),
    ],
    "Apache Kafka": [
        ("CVE-2023-25194","High",    8.8,"JNDI injection via SASL config","< 3.4.0","3.4.0","2023-02-07","Patched"),
    ],
    "Nginx": [
        ("CVE-2024-24989","Medium",  5.9,"HTTP/3 QUIC null pointer deref","< 1.25.4","1.25.4","2024-02-14","Patched"),
        ("CVE-2021-23017","High",    7.7,"Off-by-one heap write in resolver","< 1.20.1","1.20.1","2021-05-25","Patched"),
    ],
    "OpenSSL": [
        ("CVE-2022-0778","High",7.5,"Infinite loop in BN_mod_sqrt","< 1.1.1n","1.1.1n","2022-03-15","Patched"),
    ],
    "PostgreSQL": [
        ("CVE-2024-0985","High",8.0,"Non-owner SECURITY INVOKER view abuse","< 16.2","16.2","2024-02-08","Patched"),
        ("CVE-2023-5869","High",8.8,"Integer overflow in array modification","< 15.5","15.5","2023-11-09","Patched"),
    ],
    "MongoDB": [
        ("CVE-2024-1351","Medium",6.5,"Incorrect authorization check","< 7.0.6","7.0.6","2024-03-07","Patched"),
    ],
    "Redis": [
        ("CVE-2023-41056","High",8.1,"Heap buffer overflow in SINTERCARD","< 7.2.4","7.2.4","2024-01-09","Patched"),
        ("CVE-2023-28856","Medium",6.5,"HRANDFIELD crashes on invalid count","< 7.0.11","7.0.11","2023-04-17","Patched"),
    ],
    "PHP": [
        ("CVE-2024-4577","Critical",9.8,"Argument injection in CGI mode (Windows)","< 8.3.8","8.3.8","2024-06-09","Patched"),
        ("CVE-2023-3824","Critical",9.8,"Buffer underread in phar parsing","< 8.0.30","8.0.30","2023-08-11","Patched"),
    ],
    "Kubernetes": [
        ("CVE-2023-5528","High",    8.8,"Node privilege escalation via hostPath","< 1.28.4","1.28.4","2023-11-14","Patched"),
        ("CVE-2023-2727","High",    6.5,"Bypass of imagePolicyWebhook","< 1.27.3","1.27.3","2023-06-15","Patched"),
    ],
    "Docker": [
        ("CVE-2024-21626","High",8.6,"Container breakout via runc WORKDIR","< 26.0.0","26.0.0","2024-01-31","Patched"),
    ],
    "Elasticsearch": [
        ("CVE-2023-31419","High",7.5,"StackOverflow via _search request","< 8.9.1","8.9.1","2023-10-26","Patched"),
    ],
    "Node.js": [
        ("CVE-2024-21892","High",7.8,"Code injection in Linux via PATH manipulation","< 20.11.1","20.11.1","2024-02-14","Patched"),
    ],
}

RADAR_HISTORY = [
    # (name, quarter, ring, quadrant)
    ("Python",       "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("Java",         "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("TypeScript",   "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("Go",           "2026-Q1","Trial",  "Languages & Frameworks"),
    ("Rust",         "2026-Q1","Assess", "Languages & Frameworks"),
    ("PHP",          "2026-Q1","Hold",   "Languages & Frameworks"),
    ("Ruby",         "2026-Q1","Hold",   "Languages & Frameworks"),
    ("FastAPI",      "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("React",        "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("Spring Boot",  "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("Next.js",      "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("Vue.js",       "2026-Q1","Trial",  "Languages & Frameworks"),
    ("Django",       "2026-Q1","Adopt",  "Languages & Frameworks"),
    ("NestJS",       "2026-Q1","Trial",  "Languages & Frameworks"),
    ("Laravel",      "2026-Q1","Hold",   "Languages & Frameworks"),
    ("Kubernetes",   "2026-Q1","Adopt",  "Platforms"),
    ("Docker",       "2026-Q1","Adopt",  "Platforms"),
    ("Apache Kafka", "2026-Q1","Adopt",  "Platforms"),
    ("RabbitMQ",     "2026-Q1","Hold",   "Platforms"),
    ("AWS",          "2026-Q1","Adopt",  "Platforms"),
    ("Azure",        "2026-Q1","Adopt",  "Platforms"),
    ("Kong Gateway", "2026-Q1","Adopt",  "Platforms"),
    ("Node.js",      "2026-Q1","Adopt",  "Platforms"),
    ("Istio",        "2026-Q1","Trial",  "Platforms"),
    ("Apache Spark", "2026-Q1","Trial",  "Platforms"),
    ("GitLab",       "2026-Q1","Adopt",  "Tools"),
    ("GitHub Actions","2026-Q1","Adopt", "Tools"),
    ("ArgoCD",       "2026-Q1","Adopt",  "Tools"),
    ("Terraform",    "2026-Q1","Adopt",  "Tools"),
    ("SonarQube",    "2026-Q1","Adopt",  "Tools"),
    ("Prometheus",   "2026-Q1","Adopt",  "Tools"),
    ("Grafana",      "2026-Q1","Adopt",  "Tools"),
    ("Jenkins",      "2026-Q1","Hold",   "Tools"),
    ("Helm",         "2026-Q1","Adopt",  "Tools"),
    ("Vault",        "2026-Q1","Adopt",  "Tools"),
    ("Apache Airflow","2026-Q1","Trial", "Tools"),
    ("Power BI",     "2026-Q1","Adopt",  "Tools"),
    ("Tableau",      "2026-Q1","Trial",  "Tools"),
    ("LangChain",    "2026-Q1","Assess", "Tools"),
    ("PostgreSQL",   "2026-Q1","Adopt",  "Infrastructure"),
    ("MySQL",        "2026-Q1","Adopt",  "Infrastructure"),
    ("Redis",        "2026-Q1","Adopt",  "Infrastructure"),
    ("MongoDB",      "2026-Q1","Trial",  "Infrastructure"),
    ("Elasticsearch","2026-Q1","Adopt",  "Infrastructure"),
    ("Oracle Database","2026-Q1","Hold", "Infrastructure"),
    ("Ubuntu Server","2026-Q1","Adopt",  "Infrastructure"),
    ("Cloudflare",   "2026-Q1","Adopt",  "Infrastructure"),
    ("Apache ActiveMQ","2026-Q1","Hold", "Infrastructure"),
    ("Apache Log4j", "2026-Q1","Hold",   "Languages & Frameworks"),
    ("OpenAI API",   "2026-Q1","Assess", "Platforms"),
    # Previous quarter (movement tracking)
    ("Go",           "2025-Q3","Trial",  "Languages & Frameworks"),
    ("NestJS",       "2025-Q3","Assess", "Languages & Frameworks"),
    ("Istio",        "2025-Q3","Assess", "Platforms"),
    ("Apache Spark", "2025-Q3","Assess", "Platforms"),
    ("LangChain",    "2025-Q3","Assess", "Tools"),
    ("RabbitMQ",     "2025-Q3","Trial",  "Platforms"),
    ("Jenkins",      "2025-Q3","Hold",   "Tools"),
]

def seed():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    now = datetime.utcnow().isoformat()

    # Build name->id map
    tech_id_map = {}

    # Insert tech_catalog
    print("Inserting tech_catalog...")
    for row in TECH_DATA:
        name, vendor, cat, subcat, tier, status, website = row
        existing = conn.execute("SELECT id FROM tech_catalog WHERE name=?", (name,)).fetchone()
        if existing:
            tech_id_map[name] = existing["id"]
            continue
        tid = uid("TC")
        tech_id_map[name] = tid
        conn.execute("""INSERT INTO tech_catalog
            (id,name,vendor,category,sub_category,tier,standard_status,website_url,created_by,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,'system',?,?)""",
            (tid, name, vendor, cat, subcat, tier, status, website, now, now))

    conn.commit()
    print(f"  → {len(tech_id_map)} tech entries")

    # Insert tech_versions
    print("Inserting tech_versions...")
    ver_count = 0
    ver_id_map = {}  # (tech_name, version_label) -> ver_id
    for name, versions in VERSIONS.items():
        tid = tech_id_map.get(name)
        if not tid:
            continue
        for v in versions:
            label, major, minor, patch, rdate, eol, rtype, is_latest, is_lts = v
            existing = conn.execute("SELECT id FROM tech_versions WHERE tech_id=? AND version_label=?", (tid, label)).fetchone()
            if existing:
                ver_id_map[(name, label)] = existing["id"]
                continue
            vid = uid("TV")
            ver_id_map[(name, label)] = vid
            eol_date = None if eol == "—" else eol
            lifecycle = "EOL" if eol_date and eol_date < "2025" else ("Maintenance-only" if rtype == "Maintenance" else "Active")
            conn.execute("""INSERT INTO tech_versions
                (id,tech_id,version_label,major,minor,patch,release_type,release_date,eol_date,lifecycle_phase,is_latest,is_lts,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (vid, tid, label, int(major) if major.isdigit() else 0,
                 int(minor) if minor.isdigit() else 0,
                 int(patch) if patch.isdigit() else 0,
                 rtype, rdate, eol_date, lifecycle, is_latest, is_lts, now))
            ver_count += 1

    conn.commit()
    print(f"  → {ver_count} versions")

    # Insert tech_vulnerabilities
    print("Inserting CVE records...")
    cve_count = 0
    for name, cves in CVES.items():
        tid = tech_id_map.get(name)
        if not tid:
            continue
        # find latest version id
        latest_ver = conn.execute("SELECT id FROM tech_versions WHERE tech_id=? AND is_latest=1", (tid,)).fetchone()
        vid = latest_ver["id"] if latest_ver else None
        for cve in cves:
            cve_id, severity, cvss, desc, affected, fixed_in, pub_date, status = cve
            existing = conn.execute("SELECT id FROM tech_vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
            if existing:
                continue
            conn.execute("""INSERT INTO tech_vulnerabilities
                (id,tech_id,version_id,cve_id,severity,cvss_score,description,affected_versions,
                 fixed_in_version,published_date,status,fetched_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid("CVE"), tid, vid, cve_id, severity, cvss, desc, affected,
                 fixed_in, pub_date, status, now, now, now))
            cve_count += 1

    conn.commit()
    print(f"  → {cve_count} CVE records")

    # Insert tech_radar
    print("Inserting radar entries...")
    radar_count = 0
    RATIONALE = {
        "Adopt":  "เทคโนโลยีนี้ผ่านการพิสูจน์ในระบบ Production แล้ว แนะนำให้ใช้เป็น Standard",
        "Trial":  "มีศักยภาพสูง กำลังทดสอบใน project จริง — ติดตามผลลัพธ์ก่อนยกระดับ",
        "Assess": "น่าสนใจ ให้ทีมศึกษาและทำ PoC ก่อนตัดสินใจ",
        "Hold":   "ไม่แนะนำให้นำมาใช้ใหม่ — ให้วางแผน migration ออก",
    }
    # Build previous quarter map
    prev_ring_map = {}
    for name, quarter, ring, quad in RADAR_HISTORY:
        if quarter == "2025-Q3":
            prev_ring_map[name] = ring

    for name, quarter, ring, quad in RADAR_HISTORY:
        tid = tech_id_map.get(name)
        if not tid:
            continue
        existing = conn.execute("SELECT id FROM tech_radar WHERE tech_id=? AND radar_date=?", (tid, quarter)).fetchone()
        if existing:
            continue
        prev = prev_ring_map.get(name) if quarter == "2026-Q1" else None
        conn.execute("""INSERT INTO tech_radar(id,tech_id,radar_date,ring,quadrant,rationale,decided_by,prev_ring,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (uid("TR"), tid, quarter, ring, quad, RATIONALE.get(ring,""), "ARB", prev, now))
        radar_count += 1

    conn.commit()
    print(f"  → {radar_count} radar entries")

    # Summary
    print("\n=== SEED COMPLETE ===")
    for tbl in ["tech_catalog","tech_versions","tech_vulnerabilities","tech_radar"]:
        count = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        print(f"  {tbl}: {count} rows")

    conn.close()

if __name__ == "__main__":
    seed()
