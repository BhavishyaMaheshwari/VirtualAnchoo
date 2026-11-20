"""Exchange actual TCP, UDP and DNS messages only over loopback.

This generates real socket traffic for an authorized capture experiment; it
never creates a PCAP or inserts packet metadata into VirtualAnchoo. Start a live
capture of lo first. DNS uses the mDNS port 5353 so no privileged bind is needed.
"""
import socket
import threading
from scapy.all import DNS, DNSQR, DNSRR


def exchange(kind, payload, handler=lambda data: data):
    with socket.socket(socket.AF_INET, kind) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(3)
        if kind == socket.SOCK_STREAM:
            server.listen(1)
        address = server.getsockname()
        failures = []
        def serve():
            try:
                if kind == socket.SOCK_STREAM:
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(handler(connection.recv(4096)))
                else:
                    data, peer = server.recvfrom(4096)
                    server.sendto(handler(data), peer)
            except Exception as exc:
                failures.append(exc)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with socket.socket(socket.AF_INET, kind) as client:
                client.settimeout(3)
                client.connect(address)
                client.sendall(payload)
                response = client.recv(4096)
                assert response == handler(payload)
            print(f'{"TCP" if kind == socket.SOCK_STREAM else "UDP"}: actual loopback exchange with {address}, {len(response)} response bytes')
        finally:
            worker.join(timeout=4)
        if failures:
            raise failures[0]


if __name__ == '__main__':
    exchange(socket.SOCK_STREAM, b'VirtualAnchoo authorized local TCP experiment')
    exchange(socket.SOCK_DGRAM, b'VirtualAnchoo authorized local UDP experiment')
    # DNS on an ephemeral port is still an actual DNS message, but most
    # dissectors need a port binding to identify it as DNS. Use 5353 here.
    query = DNS(id=42, qd=DNSQR(qname='virtualanchoo.test.'))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
        resolver.settimeout(3)
        try:
            resolver.bind(('127.0.0.1', 5353))
        except OSError as exc:
            raise SystemExit(f'TCP/UDP completed; cannot bind local DNS port 5353: {exc}. Stop the conflicting service or omit the DNS experiment.')
        def reply():
            request, peer = resolver.recvfrom(4096)
            packet = DNS(request)
            response = DNS(id=packet.id, qr=1, aa=1, qd=packet.qd,
                           an=DNSRR(rrname='virtualanchoo.test.', type='A', ttl=60, rdata='127.0.0.1'))
            resolver.sendto(bytes(response), peer)
        worker = threading.Thread(target=reply)
        worker.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(bytes(query), ('127.0.0.1', 5353))
                response, _ = client.recvfrom(4096)
                assert DNS(response).qr == 1
                print('DNS: actual loopback query/response on UDP 5353 for virtualanchoo.test.')
        finally:
            worker.join(timeout=4)
    print('These exchanges are not capture evidence. Confirm captured packets separately in VirtualAnchoo.')
