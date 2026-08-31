# Sentinel Backend

FastAPI backend for Sentinel. It provides authenticated REST endpoints for URL, public GitHub repository, and safe static file analysis plus a security assistant.

## Structure
- `app/main.py` FastAPI app
- `app/api/routes.py` API endpoints
- `app/core/security.py` Supabase JWT verification
- `app/services/` scanner implementations

## Setup (Windows PowerShell)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `SUPABASE_URL`. `SUPABASE_SERVICE_ROLE_KEY` is only needed later if server-side Supabase database writes are added; never expose it to the frontend.

Run:
```powershell
uvicorn app.main:app --reload --port 8000
```

API docs: `http://localhost:8000/docs`

## Frontend connection
Use a frontend environment variable such as:
`VITE_API_BASE_URL=http://localhost:8000`

Send the Supabase access token as:
`Authorization: Bearer <supabase-session-access-token>`

## Safety
The scanners do not execute uploaded files or repository code. They perform static/heuristic analysis. Do not present results as definitive malware or reputation verdicts without an actual threat-intelligence or sandboxing provider.
