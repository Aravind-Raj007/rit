#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-/workspace/cyberguard-lite-python}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$ROOT_DIR/python_repo_template"

if [[ ! -d "$TEMPLATE_DIR" ]]; then
  echo "Template directory not found: $TEMPLATE_DIR" >&2
  exit 1
fi

if [[ -e "$TARGET_DIR" && -n "$(find "$TARGET_DIR" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
  echo "Target directory exists and is not empty: $TARGET_DIR" >&2
  echo "Please choose an empty/new path." >&2
  exit 1
fi

mkdir -p "$TARGET_DIR"
cp -R "$TEMPLATE_DIR"/. "$TARGET_DIR"/

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  git -C "$TARGET_DIR" init >/dev/null
fi

echo "✅ Python repo scaffold created at: $TARGET_DIR"
echo "Next steps:"
echo "  cd $TARGET_DIR"
echo "  python -m venv .venv && source .venv/bin/activate"
echo "  pip install -e .[dev]"
echo "  pytest"
echo "  uvicorn app.main:app --reload"
