# Python Repo Scaffold

This repository now includes a helper script to create a **separate** Python repository scaffold without modifying the existing Electron/Next.js app.

## Create the new repository

```bash
./tools/create_python_repo.sh /workspace/cyberguard-lite-python
```

This will:
- Copy `python_repo_template/` into the target directory
- Initialize a new Git repository in that target directory

## Scaffold contents
- FastAPI app entrypoint (`app/main.py`)
- SQLite initialization (`app/db.py`)
- Password hashing utility (`app/auth.py`)
- Basic health endpoint test (`tests/test_health.py`)
- Python package metadata (`pyproject.toml`)
