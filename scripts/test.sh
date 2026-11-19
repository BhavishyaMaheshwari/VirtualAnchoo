#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
.venv/bin/python -m pytest -ra "$@"
npm --prefix frontend test
npm --prefix frontend run build
