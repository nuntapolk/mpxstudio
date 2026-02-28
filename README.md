# MPX AppPort EA Portfolio

Enterprise Application Portfolio Management System

---

## โครงสร้างไฟล์

```
mpx-appport/
├── server.py          ← FastAPI backend
├── requirements.txt   ← Python dependencies
├── appport.db         ← SQLite database (สร้างอัตโนมัติตอนรันครั้งแรก)
├── README.md
└── static/
    ├── index.html     ← Frontend (Full Stack mode)
    └── MPX_Logo.png   ← Logo (วางไว้ที่นี่)
```

---

## วิธีติดตั้งและรัน

### 1. ติดตั้ง Dependencies

```bash
pip install fastapi uvicorn
```

### 2. รัน Server

```bash
python server.py
```

หรือใช้ uvicorn โดยตรง:

```bash
uvicorn server:app --reload --port 8000
```

### 3. เปิด Browser

| URL | รายละเอียด |
|-----|-----------|
| http://localhost:8000/ | Frontend หลัก |
| http://localhost:8000/docs | Swagger API Documentation |
| http://localhost:8000/api/stats | Dashboard KPIs |

---

## REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/version | Version info |
| GET | /api/stats | Dashboard KPIs (total, active, TCO, health) |
| GET | /api/apps | List apps (filters: status, domain, bcg, ea_group, search, show_decomm) |
| GET | /api/apps/{id} | Get single app |
| POST | /api/apps | Create new app |
| PUT | /api/apps/{id} | Update app |
| POST | /api/apps/{id}/decommission | Mark as decommissioned |
| GET | /api/ea/structure | EA Landscape structure with app counts |

### ตัวอย่าง API calls

```bash
# Get all active apps
curl http://localhost:8000/api/apps?status=Active

# Get apps in EA Group 3
curl "http://localhost:8000/api/apps?ea_group=3.%20Core%20Products"

# Search by name
curl "http://localhost:8000/api/apps?search=SAP"

# Create new app
curl -X POST http://localhost:8000/api/apps \
  -H "Content-Type: application/json" \
  -d '{"name":"New App","domain":"Finance","vendor":"SAP","health":80}'

# Update app
curl -X PUT http://localhost:8000/api/apps/APP-001 \
  -H "Content-Type: application/json" \
  -d '{"health":90,"status":"Active"}'

# Decommission
curl -X POST http://localhost:8000/api/apps/APP-050/decommission \
  -H "Content-Type: application/json" \
  -d '{"decomm_date":"2025-12-31","decomm_reason":"Replaced by SAP S/4HANA"}'
```

---

## การเปลี่ยน Version

แก้ค่า `APP_VERSION` ใน **server.py** บรรทัดแรก:

```python
APP_VERSION = "V001"   # <- แก้ตรงนี้
```

Frontend จะอ่านค่า version จาก `/api/version` และอัปเดตชื่อ tab + logo subtitle อัตโนมัติ

---

## Single HTML (Demo Mode)

ไฟล์ `MPX-AppPort-demo.html` คือ standalone version ที่:
- ข้อมูลอยู่ใน memory (ไม่ต้องรัน server)
- Logo ฝังเป็น base64 ในไฟล์เดียว
- เปิดได้เลยด้วย browser โดยไม่ต้องติดตั้งอะไร
