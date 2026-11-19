"""Analytics cache is bounded to two sessions and refreshes at most once/2s."""
import threading
import time
from fastapi import APIRouter, Request
from .packets import resolve_session
from .capture import public_session
from ..services import traffic_analyzer

router = APIRouter(prefix="/api/analytics")

class AnalyticsCache:
    def __init__(self,database):
        self.db = database
        self.lock = threading.RLock()
        self.cache = {}

    def invalidate(self,sid):
        with self.lock:
            self.cache.pop(sid,None)

    def get(self,session):
        sid = session["id"] if session else None
        count = session["packet_count"] if session else 0
        now = time.monotonic()
        with self.lock:
            cached = self.cache.get(sid)
            if cached and (cached["count"] == count or now-cached["at"] < 2):
                cached["result"]["overview"]["session"] = public_session(session)
                return cached["result"]
            packets = self.db.all_packets(sid)
            result = {name:getattr(traffic_analyzer,name)(packets) for name in ("protocols","bandwidth","devices","flows","sizes","vlans")}
            result["overview"] = traffic_analyzer.overview(packets,public_session(session))
            self.cache[sid] = {"at":now,"count":count,"result":result}
            if len(self.cache)>2:
                oldest = min(self.cache,key=lambda key:self.cache[key]["at"])
                self.cache.pop(oldest)
            if sid:
                self.db.save_stats(sid,result["overview"])
            return result


def endpoint(name):
    def read(request: Request, session_id: str | None=None):
        return request.app.state.analytics.get(resolve_session(request,session_id))[name]
    read.__name__ = "get_"+name
    return read

for name in ("overview","protocols","bandwidth","devices","flows","sizes","vlans"):
    router.add_api_route("/"+name,endpoint(name),methods=["GET"])
