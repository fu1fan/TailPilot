#!/usr/bin/env python3
"""Linux read-only safety gate; fail closed on any wildcard/nonloopback 8080/3340."""
import ipaddress
import subprocess

result = subprocess.run(['ss', '-H', '-lntu'], text=True, capture_output=True, check=True)
for line in result.stdout.splitlines():
    fields = line.split()
    endpoint = fields[4]
    address, port = endpoint.rsplit(':', 1)
    if port not in ('8080', '3340'):
        continue
    try:
        safe = ipaddress.ip_address(address.strip('[]')).is_loopback
    except ValueError:
        safe = False
    if not safe:
        raise SystemExit('BLOCKED: external listener must be removed by its owner: ' + line)
print('PASS: no external TCP/UDP listener on 8080/3340 (IPv4 and IPv6)')
