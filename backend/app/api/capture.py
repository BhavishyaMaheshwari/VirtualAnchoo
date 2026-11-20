from pathlib import Path
import tempfile
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool
from ..core.config import MAX_UPLOAD_BYTES
from ..models.schemas import CaptureStart
from ..services.capture_engine import CaptureError, interfaces

router = APIRouter(prefix="/api")


def public_session(session):
    if session is None:
        return None
    return {k:v for k,v in session.items() if k not in {"pcap_path","stats"}}

@router.get("/interfaces")
def list_interfaces():
    return interfaces()

@router.post("/capture/start")
def start_capture(body: CaptureStart, request: Request):
    try:
        return request.app.state.capture.start(**body.model_dump())
    except CaptureError as exc:
        raise HTTPException(409,str(exc)) from exc

@router.post("/capture/stop")
def stop_capture(request: Request):
    try:
        return request.app.state.capture.stop()
    except CaptureError as exc:
        raise HTTPException(409,str(exc)) from exc

@router.get("/capture/status")
def capture_status(request: Request):
    return request.app.state.capture.status()

@router.get("/sessions")
def list_sessions(request: Request):
    return request.app.state.db.sessions()

@router.delete("/sessions/{session_id}")
def delete_session(session_id: str, request: Request):
    engine = request.app.state.capture
    with engine.lock:
        if (engine.running or engine.importing) and session_id == engine.session_id:
            raise HTTPException(409,"Stop capture before deleting its session.")
        if not request.app.state.db.delete_session(session_id):
            raise HTTPException(404,"Capture session not found")
        request.app.state.analytics.invalidate(session_id)
    return {"deleted":session_id}

@router.post("/capture/import")
async def import_capture(request: Request, file: UploadFile = File(...)):
    async with request.app.state.import_lock:
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(prefix="upload-",suffix=".pcap",dir=request.app.state.db.data_dir,delete=False) as handle:
                tmp = Path(handle.name)
                total = 0
                while chunk := await file.read(1024*1024):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise HTTPException(413,"PCAP uploads must be 64 MiB or smaller.")
                    handle.write(chunk)
            if total == 0:
                raise HTTPException(400,"The uploaded file is empty.")
            session = await run_in_threadpool(request.app.state.capture.import_pcap,tmp,file.filename or "imported.pcap")
            return public_session(session)
        except CaptureError as exc:
            raise HTTPException(400,str(exc)) from exc
        finally:
            await file.close()
            if tmp:
                tmp.unlink(missing_ok=True)

@router.get("/capture/{session_id}/export")
def export_capture(session_id: str, request: Request):
    session = request.app.state.db.session(session_id)
    if not session:
        raise HTTPException(404,"Capture session not found")
    if session["status"] in {"running","importing"}:
        raise HTTPException(409,"Stop capture before exporting its PCAP.")
    path = Path(session["pcap_path"])
    if not path.is_file() or path.stat().st_size == 0:
        raise HTTPException(404,"No packet capture file is available for this session.")
    with path.open("rb") as capture_file:
        extension = "pcapng" if capture_file.read(4) == b"\x0a\x0d\x0d\x0a" else "pcap"
    return FileResponse(path,media_type="application/octet-stream" if extension == "pcapng" else "application/vnd.tcpdump.pcap",filename=f"virtualanchoo-{session_id}.{extension}")
