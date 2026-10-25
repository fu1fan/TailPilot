#!/usr/bin/env python3
"""Small IPv4 UDP datagrams over TUN, without UDP connect or retries."""
import json
import socket
import sys
import time

PORT = 18081
COUNT = 8
TIMEOUT = 2


def payload(nonce, sequence):
    return f'g4-netns-udp:{nonce}:{sequence}'.encode('ascii')


def serve(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((ip, PORT))
        while True:
            data, source = sock.recvfrom(65535)
            sock.sendto(data, source)


def probe(ip, nonce):
    start = time.monotonic()
    sent = received = size = 0
    result = dict(schema=1, target=ip, nonce=nonce, sent=0, received=0,
                  sequences=[], bytesEachDirection=0, ok=False)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            for sequence in range(COUNT):
                data = payload(nonce, sequence)
                if sock.sendto(data, (ip, PORT)) != len(data):
                    raise ValueError('short UDP send')
                sent += 1
                reply, source = sock.recvfrom(65535)
                if source != (ip, PORT):
                    raise ValueError('UDP source mismatch')
                if reply != data:
                    raise ValueError(f'UDP nonce/sequence/payload mismatch at sequence {sequence}')
                received += 1
                size += len(data)
                result['sequences'].append(sequence)
        result['ok'] = True
    except (OSError, ValueError) as e:
        result['error'] = f'{type(e).__name__}: {e}; sequence={sent-1}'
    result.update(sent=sent, received=received, bytesEachDirection=size,
                  seconds=time.monotonic()-start)
    return result


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'serve':
        serve(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == 'probe':
        result = probe(sys.argv[2], sys.argv[3])
        print(json.dumps(result), flush=True)
        sys.exit(0 if result['ok'] else 1)
    else:
        raise SystemExit('usage: udp.py serve IP | probe IP NONCE')
