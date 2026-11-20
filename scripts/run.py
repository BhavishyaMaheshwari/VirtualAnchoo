"""Run the local API and dashboard together, with scoped shutdown and PID tracking."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / ".run"
LOCK = RUN / "server.lock"


def process_start(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def stop() -> int:
    if not LOCK.exists():
        print("VirtualAnchoo is not running through scripts/start.sh.")
        return 0
    with LOCK.open("r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("VirtualAnchoo is already stopped.")
            return 0
        except BlockingIOError:
            info = json.loads(lock.read())
        pid = info["pid"]
        if info.get("start"):
            if process_start(pid) != info["start"]:
                raise SystemExit("Stale process identity; refusing to stop an unrelated process.")
        else:
            command = subprocess.check_output(["ps", "-p", str(pid), "-o", "args="], text=True)
            if "scripts/run.py" not in command:
                raise SystemExit("Process identity does not match VirtualAnchoo.")
        os.kill(pid, signal.SIGTERM)
        print("Requested VirtualAnchoo shutdown.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Allow authorized live captures (requires OS capture permission).")
    parser.add_argument("--production", action="store_true", help="Serve frontend/dist from FastAPI; build first.")
    parser.add_argument("--backend-only", action="store_true")
    parser.add_argument("--backend-port", type=int, default=8765)
    parser.add_argument("--frontend-port", type=int, default=5173)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if args.stop:
        return stop()
    if not all(1024 <= p <= 65535 for p in (args.backend_port, args.frontend_port)):
        parser.error("Ports must be between 1024 and 65535.")
    if args.production and not (ROOT / "frontend/dist/index.html").exists():
        parser.error("Production assets missing. Run npm --prefix frontend run build.")
    RUN.mkdir(exist_ok=True)
    lock = LOCK.open("a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("VirtualAnchoo is already running through scripts/start.sh.")
    lock.seek(0)
    lock.truncate()
    json.dump({"pid": os.getpid(), "start": process_start(os.getpid())}, lock)
    lock.flush()
    env = os.environ.copy()
    env["VIRTUALANCHOO_LIVE_CAPTURE"] = "1" if args.live else "0"
    origins = [f"http://{host}:{port}" for host in ("localhost", "127.0.0.1") for port in (args.backend_port, args.frontend_port)]
    env["VIRTUALANCHOO_ALLOWED_ORIGINS"] = ",".join(origins + [env.get("VIRTUALANCHOO_ALLOWED_ORIGINS", "")])
    env["VIRTUALANCHOO_API_TARGET"] = f"http://127.0.0.1:{args.backend_port}"
    children: list[subprocess.Popen] = []
    stopping = False

    def handle_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)
    try:
        api = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(args.backend_port)], cwd=ROOT, env=env, start_new_session=True)
        children.append(api)
        for _ in range(100):
            if stopping or api.poll() is not None:
                break
            try:
                with urlopen(f"http://127.0.0.1:{args.backend_port}/api/capture/status", timeout=0.3) as response:
                    if response.status == 200:
                        break
            except (URLError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Backend did not become ready within 10 seconds.")
        if api.poll() is not None:
            raise RuntimeError("Backend failed to start; inspect the error above.")
        if not args.production and not args.backend_only and not stopping:
            children.append(subprocess.Popen(["npm", "--prefix", "frontend", "run", "dev", "--", "--host", "127.0.0.1", "--port", str(args.frontend_port), "--strictPort"], cwd=ROOT, env=env, start_new_session=True))
        port = args.backend_port if args.production or args.backend_only else args.frontend_port
        print(f"VirtualAnchoo: http://127.0.0.1:{port} | {'live capture enabled' if args.live else 'offline PCAP mode'}", flush=True)
        while not stopping:
            for child in children:
                if child.poll() is not None:
                    return child.returncode or 1
            time.sleep(0.3)
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
