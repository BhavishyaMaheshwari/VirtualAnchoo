#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
command -v python3 >/dev/null || { echo 'Python 3.11+ is required.' >&2; exit 1; }
command -v npm >/dev/null || { echo 'Node.js 20.19+ or 22.12+ and npm are required.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'
if [[ ! -x .venv/bin/python ]]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -r backend/requirements.txt
if [[ -f frontend/package-lock.json ]]; then
  npm --prefix frontend ci
else
  npm --prefix frontend install
fi
npm --prefix frontend run build
echo 'NetScope is ready. Run ./scripts/start.sh for offline PCAP analysis.'
echo 'Live capture and the VLAN lab require separate, explicit operator setup; see README.md.'
