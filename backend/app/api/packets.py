from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import IPvAnyAddress

router = APIRouter(prefix="/api")

def resolve_session(request, sid=None):
    session = request.app.state.db.session(sid)
    if sid and not session:
        raise HTTPException(404,"Capture session not found")
    return session

@router.get("/packets")
def list_packets(request: Request, session_id: str | None=None,
                 page: int=Query(1,ge=1), page_size: int=Query(100,ge=1,le=500),
                 protocol: str | None=Query(None,max_length=32),
                 src_ip: IPvAnyAddress | None=None, dst_ip: IPvAnyAddress | None=None,
                 src_port: int | None=Query(None,ge=0,le=65535), dst_port: int | None=Query(None,ge=0,le=65535),
                 vlan_id: int | None=Query(None,ge=0,le=4094),
                 min_size: int | None=Query(None,ge=0), max_size: int | None=Query(None,ge=0),
                 start_time: float | None=None, end_time: float | None=None,
                 search: str | None=Query(None,max_length=200)):
    if min_size is not None and max_size is not None and min_size > max_size:
        raise HTTPException(422,"min_size must not exceed max_size")
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(422,"start_time must not exceed end_time")
    session = resolve_session(request,session_id)
    return request.app.state.db.packets(session["id"] if session else None,page,page_size,
        protocol=protocol,src_ip=str(src_ip) if src_ip else None,dst_ip=str(dst_ip) if dst_ip else None,
        src_port=src_port,dst_port=dst_port,vlan_id=vlan_id,min_size=min_size,max_size=max_size,
        start_time=start_time,end_time=end_time,search=search)

@router.get("/packets/{packet_id}")
def get_packet(packet_id: int, request: Request):
    packet = request.app.state.db.packet(packet_id)
    if not packet:
        raise HTTPException(404,"Packet not found")
    return packet
