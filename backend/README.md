# Agentic SOC — FastAPI Backend (Module 2)

Persistent backend service for **Agentic SOC — Auditable AI Security Operations Center**.

## Tech Stack
- **Python 3.10+** (Tested on Python 3.14)
- **FastAPI**
- **SQLite**
- **SQLAlchemy 2.0+**
- **Pydantic v2**

## Directory Layout
```text
backend/
├── app/
│   ├── main.py                    # FastAPI entrypoint, lifespan, and CORS setup
│   ├── database.py                # SQLite engine and session factory
│   ├── models/
│   │   ├── __init__.py
│   │   └── investigation.py       # SQLAlchemy InvestigationModel
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── investigation.py       # Pydantic InvestigationCreate & InvestigationResponse
│   ├── routes/
│   │   ├── __init__.py
│   │   └── investigations.py      # GET /api/investigations, POST /api/investigations
│   └── services/
│       ├── __init__.py
│       └── investigation_service.py # ID generator, seeding, and DB queries
├── agentic_soc.db                 # SQLite database (auto-generated)
├── requirements.txt
└── README.md
```

## Setup & Running

### 1. Create Virtual Environment
```bash
cd backend
python -m venv .venv
```

### 2. Activate & Install Dependencies
On Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On Linux/macOS:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run FastAPI Server
```bash
python -m uvicorn app.main:app --reload --port 8000
```
Interactive Swagger API documentation will be available at:  
`http://localhost:8000/docs`

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations` | Retrieve all investigations sorted newest first |
| `GET` | `/api/investigations/{id}` | Retrieve a single investigation by ID (e.g. `INV-001`) |
| `POST` | `/api/investigations` | Create a new investigation with backend-generated ID (e.g. `INV-007`) |
| `GET` | `/api/health` | Backend health check |

## Database Schema (`investigations`)
- `id` (VARCHAR PK, e.g. `INV-001`)
- `alert_name` (VARCHAR NOT NULL)
- `target_host` (VARCHAR NOT NULL)
- `severity` (VARCHAR NOT NULL)
- `event_timestamp` (VARCHAR NOT NULL)
- `description` (TEXT)
- `status` (VARCHAR NOT NULL DEFAULT 'Investigating')
- `evidence_count` (INTEGER NOT NULL DEFAULT 0)
- `trust_score` (INTEGER NOT NULL DEFAULT 90)
- `created_at` (VARCHAR NOT NULL)
- `assigned_agent` (VARCHAR)
- `mitre_technique` (VARCHAR)
- `evidence_corroboration` (TEXT JSON)
