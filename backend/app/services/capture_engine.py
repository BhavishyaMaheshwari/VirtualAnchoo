"""Real Scapy capture with an explicit opt-in, bounded disk, and clean lifecycle."""
from __future__ import annotations
import logging
import os
import shutil
import sys
from pathlib import Path
import threading
import time
from scapy.all import AsyncSniffer, PcapReader, PcapWriter, conf, get_if_list, get_if_addr, get_if_hwaddr
from scapy.arch import in6_getifaddr
from ..core.config import MAX_PACKETS, MAX_SESSION_BYTES, MAX_STORAGE_BYTES
from .packet_parser import parse_packet

log = logging.getLogger(__name__)


def interfaces():
    result = []
    try:
        v6 = in6_getifaddr()
    except Exception:
        v6 = []
    for name in get_if_list():
        addresses = []
        try:
            address = get_if_addr(name)
            if address != "0.0.0.0":
                addresses.append(address)
        except Exception:
            pass
        addresses.extend(item[0] for item in v6 if item[2] == name)
        try:
            mac = get_if_hwaddr(name)
        except Exception:
            mac = None
        result.append({"name": name, "addresses": list(dict.fromkeys(addresses)), "mac": mac, "is_up": None})
    return result


class CaptureError(RuntimeError):
    pass


class CaptureEngine:
    def __init__(self, database, hub):
        self.db, self.hub = database, hub
        self.lock = threading.RLock()
        self.sniffer = None
        self.capture_socket = None
        self.writer = None
        self.monitor = None
        self.session_id = None
        self.running = False
        self.importing = False
        self.error = None
        self.stop_requested = False
        self.bytes_written = 0
        self.packet_count = 0
        self.local_ips = set()
        self.local_macs = set()

    def storage_available(self):
        size = sum(p.stat().st_size for p in self.db.data_dir.rglob("*") if p.is_file())
        if size >= MAX_STORAGE_BYTES:
            raise CaptureError("Storage quota reached (1 GiB). Delete old sessions before capturing or importing.")

    def status(self):
        session = self.db.session(self.session_id) if self.session_id else None
        return {"running":self.running,"importing":self.importing,"session_id":self.session_id,"interface":session["interface"] if session else None,"bpf_filter":session["bpf_filter"] if session else "","packet_count":session["packet_count"] if session else 0,"error":self.error,"live_enabled":os.getenv("VIRTUALANCHOO_LIVE_CAPTURE") == "1"}

    def start(self, interface, bpf_filter="", packet_limit=10000, authorized=False):
        if not authorized:
            raise CaptureError("Confirm authorization to monitor this interface before capture.")
        if os.getenv("VIRTUALANCHOO_LIVE_CAPTURE") != "1":
            raise CaptureError("Live capture is disabled. Restart with scripts/start.sh --live or VIRTUALANCHOO_LIVE_CAPTURE=1; PCAP import is available without capture privileges.")
        with self.lock:
            if self.running or self.importing:
                raise CaptureError("A capture or import is already active.")
            available = {i["name"]:i for i in interfaces()}
            if interface not in available:
                raise CaptureError("Unknown network interface. Refresh the interface list.")
            self.storage_available()
            self.error = None
            self.stop_requested = False
            self.bytes_written = 0
            self.packet_count = 0
            self.local_ips = set(available[interface]["addresses"])
            self.local_macs = {available[interface]["mac"]} if available[interface]["mac"] else set()
            try:
                # Opening first makes permission/BPF failures synchronous and visible.
                self.capture_socket = conf.L2listen(iface=interface, filter=bpf_filter or None, promisc=False)
            except Exception as exc:
                message = self._capture_message(exc)
                self.error = message
                raise CaptureError(message) from exc
            session = self.db.create_session("live",f"Live capture · {interface}",interface,bpf_filter)
            self.session_id = session["id"]
            try:
                self.writer = PcapWriter(session["pcap_path"], sync=True)
                self.running = True
                ready = threading.Event()
                self.sniffer = AsyncSniffer(opened_socket=self.capture_socket, store=False, prn=self._on_packet, count=packet_limit, stop_filter=lambda _:self.stop_requested, started_callback=ready.set)
                self.sniffer.start()
                if not ready.wait(3):
                    raise CaptureError("Capture could not start within 3 seconds.")
                if getattr(self.sniffer,"exception",None):
                    raise self.sniffer.exception
                self.monitor = threading.Thread(target=self._monitor, name="virtualanchoo-capture-monitor", daemon=True)
                self.monitor.start()
            except Exception as exc:
                self.error = self._capture_message(exc)
                self.running = False
                if self.sniffer and self.sniffer.running:
                    self.sniffer.stop(join=False)
                self._close_resources()
                self.db.finish_session(self.session_id,"error",self.error)
                raise CaptureError(self.error) from exc
        self.hub.publish("capture_status",self.status())
        return self.status()

    @staticmethod
    def _capture_message(exc):
        detail = str(exc)
        if isinstance(exc, PermissionError) or "Operation not permitted" in detail or "Permission denied" in detail:
            if sys.platform == "darwin":
                return "Packet capture permission denied. On macOS, check access to /dev/bpf devices and start VirtualAnchoo from a normal Terminal, or import a PCAP file. " + detail
            return "Packet capture permission denied. Use an authorized Linux environment with CAP_NET_RAW/CAP_NET_ADMIN, or import a PCAP file. " + detail
        if "libpcap" in detail.lower() or "filter" in detail.lower():
            return "Capture filter could not be applied. Check BPF syntax and install libpcap on the capture host. " + detail
        return "Capture failed: " + detail

    def _on_packet(self, packet):
        try:
            if self.stop_requested:
                return
            size = len(bytes(packet))
            if self.bytes_written + size > MAX_SESSION_BYTES:
                self.stop_requested = True
                self.error = "128 MiB per-session capture limit reached."
                return
            self.writer.write(packet)
            self.bytes_written += size
            parsed = parse_packet(packet, interface=self.db.session(self.session_id)["interface"], local_ips=self.local_ips, local_macs=self.local_macs)
            saved = self.db.insert_packet(self.session_id,parsed)
            self.packet_count += 1
            if self.packet_count % 1000 == 0:
                self.storage_available()
            self.hub.publish("packet",saved)
        except Exception as exc:
            log.exception("Packet capture callback failed")
            self.error = "Packet processing failed: " + str(exc)
            self.stop_requested = True

    def _monitor(self):
        try:
            self.sniffer.join()
            if getattr(self.sniffer,"exception",None):
                raise self.sniffer.exception
        except Exception as exc:
            self.error = self._capture_message(exc)
            log.warning("Capture ended with error: %s",self.error)
        finally:
            with self.lock:
                self.running = False
                self._close_resources()
                self.db.finish_session(self.session_id,"error" if self.error else "completed",self.error)
            self.hub.publish("capture_status",self.status())

    def _close_resources(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                log.exception("Could not close capture writer")
            self.writer = None
        if self.capture_socket:
            self.capture_socket.close()
            self.capture_socket = None

    def stop(self):
        # Never hold the lifecycle lock while waiting for the monitor to acquire it.
        with self.lock:
            sniffer, monitor = self.sniffer, self.monitor
            self.stop_requested = True
        if sniffer and self.running:
            try:
                sniffer.stop(join=False)
            except Exception as exc:
                if sniffer.running:
                    raise CaptureError("Unable to stop capture: " + str(exc)) from exc
        if monitor and monitor is not threading.current_thread():
            monitor.join(timeout=5)
            if monitor.is_alive():
                raise CaptureError("Capture is still stopping; try again shortly.")
        return self.status()

    def import_pcap(self, path: Path, filename: str):
        with self.lock:
            if self.running or self.importing:
                raise CaptureError("Stop the current capture or wait for the import to finish.")
            self.storage_available()
            self.importing = True
        session = None
        try:
            # Opening validates the magic and link type, even for an empty file.
            with PcapReader(str(path)) as reader:
                session = self.db.create_session("import",Path(filename).name[:200],"pcap")
                self.session_id = session["id"]
                count, byte_count = 0, 0
                limited = False
                # Preserve the original capture container. Rewriting PCAPNG as
                # classic PCAP loses interface/linktype metadata and can corrupt
                # exports for captures with heterogeneous interfaces.
                shutil.copyfile(path,session["pcap_path"])
                for packet in reader:
                    if count >= MAX_PACKETS or byte_count + len(bytes(packet)) > MAX_SESSION_BYTES:
                        limited = True
                        break
                    self.db.insert_packet(session["id"],parse_packet(packet,interface="pcap"))
                    count += 1
                    byte_count += len(bytes(packet))
                    if count % 1000 == 0:
                        self.storage_available()
                if count == 0:
                    raise CaptureError("The PCAP contains no readable packets.")
                notice = "Import stopped at the configured packet/byte limit; statistics cover the imported prefix only." if limited else None
                self.db.finish_session(session["id"],"limited" if limited else "completed",notice)
                self.error = notice
                return self.db.session(session["id"])
        except Exception as exc:
            if session:
                self.db.finish_session(session["id"],"error",str(exc))
            if isinstance(exc,CaptureError):
                raise
            raise CaptureError("Unable to read this capture file. Supply a valid PCAP or PCAPNG file. " + str(exc)) from exc
        finally:
            with self.lock:
                self.importing = False
            self.hub.publish("capture_status",self.status())
