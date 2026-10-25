#!/usr/bin/env python3
"""Bounded real TCP echo over the TUN; no nc/iperf dependency."""
import json
import socket
import socketserver
import sys
import time

PAYLOAD = b'g4-netns-tcp-' * 8192

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while data := self.request.recv(65536):
            self.request.sendall(data)

if __name__ == '__main__':
    mode, ip = sys.argv[1:]
    if mode == 'serve':
        with socketserver.ThreadingTCPServer((ip, 18080), Echo) as server:
            server.daemon_threads = True
            server.serve_forever()
    elif mode == 'monitor':
        # Existing C2 sessions remain open across R's policy generation change.
        sockets = [socket.create_connection((target, 18080), timeout=5) for target in ip.split(',')]
        for sock in sockets:
            sock.settimeout(5)
        count = 0
        while True:
            start = time.monotonic()
            for sock in sockets:
                sock.sendall(b'g4-continuity')
                received = bytearray()
                while len(received) < 13:
                    part = sock.recv(13-len(received))
                    if not part:
                        raise RuntimeError('continuity EOF')
                    received.extend(part)
                if received != b'g4-continuity':
                    raise RuntimeError('continuity echo mismatch')
            count += 1
            print(json.dumps({'round': count, 'monotonic': start, 'seconds': time.monotonic()-start}), flush=True)
            time.sleep(0.2)
    elif mode == 'probe':
        start = time.monotonic()
        with socket.create_connection((ip, 18080), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(PAYLOAD)
            received = bytearray()
            while len(received) < len(PAYLOAD):
                part = sock.recv(65536)
                if not part:
                    raise RuntimeError('short echo')
                received.extend(part)
            if received != PAYLOAD:
                raise RuntimeError('echo mismatch')
        print(json.dumps({'bytesEachDirection': len(PAYLOAD), 'seconds': time.monotonic()-start}))
    else:
        raise SystemExit('unknown mode')
