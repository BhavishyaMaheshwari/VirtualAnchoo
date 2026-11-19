"""NetScope local FastAPI service. Run from the repository root."""
from contextlib import asynccontextmanager
import asyncio
import contextlib
import logging
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles
from .core.config import ALLOWED_ORIGINS, DATA_DIR, MAX_UPLOAD_BYTES, ROOT
from .core.websocket import EventHub
from .models.database import Database
from .services.capture_engine import CaptureEngine
from .api import capture, packets, analytics

logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger(__name__)


def create_app(data_dir=None,capture_factory=CaptureEngine):
    @asynccontextmanager
    async def lifespan(app):
        app.state.db = Database(Path(data_dir or DATA_DIR))
        app.state.hub = EventHub()
        app.state.hub.bind()
        app.state.capture = capture_factory(app.state.db,app.state.hub)
        app.state.analytics = analytics.AnalyticsCache(app.state.db)
        app.state.import_lock = asyncio.Lock()
        async def updates():
            last = None
            while True:
                await asyncio.sleep(2)
                session = app.state.db.session()
                key = (session["id"],session["packet_count"],session["status"]) if session else None
                if key != last:
                    result = await asyncio.to_thread(app.state.analytics.get,session)
                    app.state.hub.publish("analytics",result["overview"])
                    app.state.hub.publish("capture_status",app.state.capture.status())
                    last = key
        task = asyncio.create_task(updates())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await asyncio.to_thread(app.state.capture.stop)
            app.state.db.close()

    app = FastAPI(title="NetScope",version="1.0.0",description="Local packet capture, PCAP analysis, and a separately authorized VLAN lab.",lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=["localhost","127.0.0.1","[::1]","testserver"])
    app.add_middleware(CORSMiddleware,allow_origins=sorted(ALLOWED_ORIGINS),allow_methods=["GET","POST","DELETE","PATCH"],allow_headers=["Content-Type"])

    @app.middleware("http")
    async def local_requests(request: Request, call_next):
        from fastapi.responses import JSONResponse
        allowed = ALLOWED_ORIGINS
        if request.method not in {"GET","HEAD","OPTIONS"} and request.headers.get("origin") and request.headers["origin"] not in allowed:
            return JSONResponse({"detail":"Requests from this browser origin are not allowed."},status_code=403)
        if request.url.path == "/api/capture/import":
            try:
                length = int(request.headers.get("content-length","0"))
            except ValueError:
                return JSONResponse({"detail":"Invalid Content-Length"},status_code=400)
            if length > MAX_UPLOAD_BYTES + 1024*1024:
                return JSONResponse({"detail":"PCAP uploads must be 64 MiB or smaller."},status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.include_router(capture.router)
    app.include_router(packets.router)
    app.include_router(analytics.router)
    try:
        from .api.network import router as network_router
        app.include_router(network_router)
    except ImportError as exc:
        log.warning("Network lab API not installed: %s",exc)

    @app.get("/api/health")
    def health():
        return {"status":"ok","name":"NetScope","mode":"live-enabled" if app.state.capture.status()["live_enabled"] else "offline","websocket_dropped_events":app.state.hub.dropped_events}

    @app.websocket("/ws")
    async def websocket(ws: WebSocket):
        allowed = ALLOWED_ORIGINS
        origin = ws.headers.get("origin")
        if origin and origin not in allowed:
            await ws.close(code=1008)
            return
        if len(app.state.hub.clients) >= 16:
            await ws.close(code=1013)
            return
        queue = await app.state.hub.connect(ws)
        await ws.send_json({"type":"capture_status","data":app.state.capture.status()})
        async def receive():
            while True:
                await ws.receive_text()
        async def send():
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(),timeout=15)
                    await ws.send_json(event)
                except asyncio.TimeoutError:
                    await ws.send_json({"type":"heartbeat","data":{}})
        receiver = asyncio.create_task(receive())
        sender = asyncio.create_task(send())
        try:
            done,_ = await asyncio.wait([receiver,sender],return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
            pass
        finally:
            receiver.cancel()
            sender.cancel()
            await asyncio.gather(receiver,sender,return_exceptions=True)
            app.state.hub.disconnect(queue)

    dist = ROOT / "frontend" / "dist"
    if dist.is_dir():
        if (dist/"assets").is_dir():
            app.mount("/assets",StaticFiles(directory=dist/"assets"),name="assets")
        @app.get("/{path:path}")
        def frontend(path: str):
            if path.startswith("api/"):
                raise HTTPException(404,"API endpoint not found")
            requested = (dist/path).resolve()
            if path and requested.is_relative_to(dist.resolve()) and requested.is_file():
                return FileResponse(requested)
            return FileResponse(dist/"index.html")
    return app

app = create_app()
