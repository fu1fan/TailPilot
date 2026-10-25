#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 "$here/selftest.py"
python3 "$here/native_test.py"
python3 "$here/static_test.py"
python3 "$here/rehearsal_test.py"
python3 "$here/make_plan_test.py"
python3 "$here/r35_test.py"
