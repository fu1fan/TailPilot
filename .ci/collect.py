#!/usr/bin/env python3
"""Export only reviewed summaries. Never upload state, keys, commands or pcaps."""
import json
import pathlib
import sys
import tarfile

root, out = map(pathlib.Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
allowed = ('result.json', 'scale-acceptance.json', 'dualstack-evidence.json', 'scope.json')
with tarfile.open(out / ('lab-' + root.name + '.tar.gz'), 'w:gz') as tar:
    for case in sorted(root.iterdir()):
        if not case.is_dir():
            continue
        for name in allowed:
            path = case / name
            if path.is_file():
                tar.add(path, arcname=case.name + '/' + name, recursive=False)
        result = case / 'result.json'
        if result.exists():
            data = json.loads(result.read_text())
            print(json.dumps({'case': case.name, 'result': data.get('result'),
                              'gates': data.get('gates'), 'acceptance': data.get('acceptance')}, ensure_ascii=False))
