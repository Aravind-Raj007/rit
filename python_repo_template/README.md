# CyberGuard Lite (Python)

A fresh Python implementation scaffold for CyberGuard Lite.

## Stack
- FastAPI (backend API)
- SQLite (local-only persistence)
- Passlib + bcrypt (password hashing)
- Pytest (tests)

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
uvicorn app.main:app --reload
```

Open: http://127.0.0.1:8000/docs

## Project layout

```
app/
  main.py
  db.py
  auth.py
tests/
  test_health.py
```

## Notes
This is intentionally a new repository scaffold and does not modify the original Electron/Next.js app.
